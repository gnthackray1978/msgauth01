using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;
using IdentityModel;
using IdentityServer4.Events;
using IdentityServer;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using IdentityServer4.Test;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using IdentityServer.Data;
using IdentityServer.Models;

namespace Host.Quickstart.Account
{
    [SecurityHeaders]
    [AllowAnonymous]
    public class ExternalController : Controller
    { 
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IClientStore _clientStore;
        private readonly IEventService _events;
        private readonly ApplicationDbContext _context;

        public ExternalController(
            IIdentityServerInteractionService interaction,
            IClientStore clientStore,
            IEventService events,
            ApplicationDbContext context )
        {
             
            _interaction = interaction;
            _clientStore = clientStore;
            _events = events;
            _context = context;

            _context.SaveChanges();
        }

        /// <summary>
        /// initiate roundtrip to external authentication provider
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Challenge(string provider, string returnUrl)
        {
            if (string.IsNullOrEmpty(returnUrl)) returnUrl = "~/";

            // validate returnUrl - either it is a valid OIDC URL or back to a local page
            if (Url.IsLocalUrl(returnUrl) == false && _interaction.IsValidReturnUrl(returnUrl) == false)
            {
                // user might have clicked on a malicious link - should be logged
                throw new Exception("invalid return URL");
            }

            if (AccountOptions.WindowsAuthenticationSchemeName == provider)
            {
                // windows authentication needs special handling
                return await ProcessWindowsLoginAsync(returnUrl);
            }
            else
            {
                // start challenge and roundtrip the return URL and scheme 
                var props = new AuthenticationProperties
                {
                    RedirectUri = Url.Action(nameof(Callback)),
                    Items =
                    {
                        { "returnUrl", returnUrl },
                        { "scheme", provider },
                    }
                };

                return Challenge(props, provider);
            }
        }

        /// <summary>
        /// Post processing of external authentication
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Callback()
        {
            // read external identity from the temporary cookie
            var result = await HttpContext.AuthenticateAsync(IdentityServer4.IdentityServerConstants.ExternalCookieAuthenticationScheme);
            if (result?.Succeeded != true)
            {
                throw new Exception("External authentication error");
            }

            var externalUser = result.Principal;

            // try to determine the unique id of the external user (issued by the provider)
            // the most common claim type for that are the sub claim and the NameIdentifier
            // depending on the external provider, some other claim type might be used
            var userIdClaim = externalUser.FindFirst(JwtClaimTypes.Subject) ??
                              externalUser.FindFirst(ClaimTypes.NameIdentifier) ??
                              throw new Exception("Unknown userid");

            // this allows us to collect any additonal claims or properties
            // for the specific prtotocols used and store them in the local auth cookie.
            // this is typically used to store data needed for signout from those protocols.
            var additionalLocalClaims = new List<Claim>();
            var localSignInProps = new AuthenticationProperties();
            var googleData = ProcessLoginCallbackForOidc(result, additionalLocalClaims, localSignInProps);

            // remove the user id claim so we don't include it as an extra claim if/when we provision the user
            var claims = externalUser.Claims.ToList();
            claims.Remove(userIdClaim);

            var provider = result.Properties.Items["scheme"];
            var providerUserId = userIdClaim.Value;

            // find external user
            //var user = _users.FindByExternalProvider(provider, providerUserId);

            var user = _context.Users.FirstOrDefault(f => f.NameIdentifier == providerUserId);

            //user doesnt exist so we want to add him/her
            if(user == null)
            {
                user = new AppUser() { 
                    Email = googleData.Email,
                    FirstName = googleData.FirstName,
                    LastName = googleData.Surname,
                    Id = DateTime.Now.Ticks.ToString(),
                    NameIdentifier = googleData.NameIdentifier,
                    UserName = googleData.Name,
                    PictureUrl = googleData.Image
                    
                };

                _context.Users.Add(user);

                _context.SaveChanges();
            }

            var token = new Token() {
                Expires = googleData.Expires,
                Issued = googleData.Issued,
                Name = googleData.TokenName,
                UserId = user.Id,
                Provider = provider,
                Type = googleData.TokenType,
                Value = googleData.AccessToken,
                Refresh = googleData.Refresh,
                ImageUrl = googleData.Image,
                Locale = googleData.Locale
            };

            _context.Tokens.Add(token);
            _context.SaveChanges();

             

            // issue authentication cookie for user
            await _events.RaiseAsync(new UserLoginSuccessEvent(provider, providerUserId, user.Id, user.UserName));

            await HttpContext.SignInAsync(user.NameIdentifier, user.UserName, provider, localSignInProps, additionalLocalClaims.ToArray());

            // delete temporary cookie used during external authentication
            await HttpContext.SignOutAsync(IdentityServer4.IdentityServerConstants.ExternalCookieAuthenticationScheme);

            // retrieve return URL
            var returnUrl = result.Properties.Items["returnUrl"] ?? "~/";

            // check if external login is in the context of an OIDC request
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);

            
            if (context != null)
            {
                if (await _clientStore.IsPkceClientAsync(context.ClientId))
                {
                    // if the client is PKCE then we assume it's native, so this change in how to
                    // return the response is for better UX for the end user.
                    Debug.WriteLine("ret url : " + returnUrl);
                    return View("Redirect", new RedirectViewModel { RedirectUrl = returnUrl });
                }
            }

            Debug.WriteLine("ret url : " + returnUrl);
            return Redirect(returnUrl);
        }

        private async Task<IActionResult> ProcessWindowsLoginAsync(string returnUrl)
        {
            // see if windows auth has already been requested and succeeded
            var result = await HttpContext.AuthenticateAsync(AccountOptions.WindowsAuthenticationSchemeName);
            if (result?.Principal is WindowsPrincipal wp)
            {
                // we will issue the external cookie and then redirect the
                // user back to the external callback, in essence, treating windows
                // auth the same as any other external authentication mechanism
                var props = new AuthenticationProperties()
                {
                    RedirectUri = Url.Action("Callback"),
                    Items =
                    {
                        { "returnUrl", returnUrl },
                        { "scheme", AccountOptions.WindowsAuthenticationSchemeName },
                    }
                };

                var id = new ClaimsIdentity(AccountOptions.WindowsAuthenticationSchemeName);
                id.AddClaim(new Claim(JwtClaimTypes.Subject, wp.Identity.Name));
                id.AddClaim(new Claim(JwtClaimTypes.Name, wp.Identity.Name));

                // add the groups as claims -- be careful if the number of groups is too large
                if (AccountOptions.IncludeWindowsGroups)
                {
                    var wi = wp.Identity as WindowsIdentity;
                    var groups = wi.Groups.Translate(typeof(NTAccount));
                    var roles = groups.Select(x => new Claim(JwtClaimTypes.Role, x.Value));
                    id.AddClaims(roles);
                }

                await HttpContext.SignInAsync(
                    IdentityServer4.IdentityServerConstants.ExternalCookieAuthenticationScheme,
                    new ClaimsPrincipal(id),
                    props);
                return Redirect(props.RedirectUri);
            }
            else
            {
                // trigger windows auth
                // since windows auth don't support the redirect uri,
                // this URL is re-triggered when we call challenge
                return Challenge(AccountOptions.WindowsAuthenticationSchemeName);
            }
        }
      
        private GoogleSignInData ProcessLoginCallbackForOidc(AuthenticateResult externalResult, List<Claim> localClaims, AuthenticationProperties localSignInProps)
        {
            // if the external system sent a session id claim, copy it over
            // so we can use it for single sign-out

            GoogleSignInData googleSignInData = new GoogleSignInData();

            foreach (var c in externalResult.Principal.Claims)
            {
                //  Debug.WriteLine(c.Type + " , " + c.Value);

                if (c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier")
                {
                    localClaims.Add(new Claim(JwtClaimTypes.Id, c.Value));
                    googleSignInData.NameIdentifier = c.Value;
                }
                if (c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name")
                {
                    localClaims.Add(new Claim(JwtClaimTypes.Name, c.Value));
                    googleSignInData.Name = c.Value;
                }

                if (c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname")
                {
                    localClaims.Add(new Claim(JwtClaimTypes.GivenName, c.Value));
                    googleSignInData.FirstName = c.Value;
                }

                if (c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname")
                {
                    localClaims.Add(new Claim(JwtClaimTypes.FamilyName, c.Value));
                    googleSignInData.Surname = c.Value;
                }

                if (c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
                    || c.Type == "urn:google:email")
                {
                    localClaims.Add(new Claim(JwtClaimTypes.Email, c.Value));
                    googleSignInData.Email = c.Value;
                }

                if (c.Type == "urn:google:picture")
                {
                    localClaims.Add(new Claim(JwtClaimTypes.Picture, c.Value));
                    googleSignInData.Image = c.Value;
                }

                if (c.Type == "urn:google:locale")
                {
                    localClaims.Add(new Claim(JwtClaimTypes.Locale, c.Value));
                    googleSignInData.Locale = c.Value;
                }
            }

            var sid = externalResult.Principal.Claims.FirstOrDefault(x => x.Type == JwtClaimTypes.SessionId);
            if (sid != null)
            {
                localClaims.Add(new Claim(JwtClaimTypes.SessionId, sid.Value));

            }
            foreach(var i in externalResult.Properties.Items)
            {
                if (i.Key == "picture")
                    googleSignInData.Image = i.Value;

                if (i.Key == "locale")
                    googleSignInData.Locale = i.Value;


                //  Debug.WriteLine(i.Key + " , " + i.Value);
                if (i.Key == ".Token.refresh_token")
                    googleSignInData.Refresh = i.Value;

                if (i.Key == ".Token.access_token")
                    googleSignInData.AccessToken = i.Value;

                if (i.Key == ".AuthScheme")
                    googleSignInData.AuthScheme = i.Value;

                if (i.Key == ".Token.TicketCreated")
                    googleSignInData.TicketCreated = DateTime.Parse(i.Value) ;

                if (i.Key == ".Token.expires_at")
                    googleSignInData.Expires = DateTime.Parse(i.Value);

                if (i.Key == ".Token.token_type")
                    googleSignInData.TokenType = i.Value;

                if (i.Key == ".issued")
                    googleSignInData.Issued = DateTime.Parse(i.Value);

                if (i.Key == ".Token.expires")
                    googleSignInData.Expires = DateTime.Parse(i.Value);

                if (i.Key == ".TokenNames")
                    googleSignInData.TokenName = i.Value;

                if (i.Key == "scheme")
                    googleSignInData.Scheme  = i.Value;
            }
            // if the external provider issued an id_token, we'll keep it for signout
            var id_token = externalResult.Properties.GetTokenValue("id_token");
            if (id_token != null)
            {
                localSignInProps.StoreTokens(new[] { new AuthenticationToken { Name = "id_token", Value = id_token } });
            }

            return googleSignInData;
        }

      }

}