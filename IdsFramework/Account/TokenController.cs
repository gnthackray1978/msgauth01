using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using System.Threading.Tasks;
using System.Diagnostics;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;
using System.Collections.Generic;
using System.Linq;
using System;
using IdentityServer4.Test;
using IdentityModel;
using IdentityServer4.Events;
using IdentityServer;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using IdentityServer.Data;
using IdentityServer.Models;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Http;
using System.Globalization;
using System.Text.Encodings.Web;
using Newtonsoft.Json.Linq;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System.Net.Http;
using Newtonsoft.Json;
using System.Net;
using System.Text;
using System.IO;
using Microsoft.Extensions.Configuration;
using Api;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Authentication.JwtBearer;
//using System.Web.Http;

namespace IdentityServer.Quickstart.Account
{
    

    [Route("token")]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    [SecurityHeaders]
    public class TokenController : ControllerBase
    {
        private readonly ApplicationDbContext _users;
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IClientStore _clientStore;
        private readonly IEventService _events;
        private readonly IConfiguration _configuration;
        private readonly ILogger<TokenController> _logger;
        private readonly IMSGConfigHelper _iMSGConfigHelper;
        public IDictionary<string, string> AuthProperties { get; set; }

        public TokenController(
            IIdentityServerInteractionService interaction,
            IClientStore clientStore,
            IEventService events,
            ApplicationDbContext users,
            IConfiguration configuration,
            IMSGConfigHelper iMSGConfigHelper,
            ILogger<TokenController> logger)
        {
            // if the TestUserStore is not in DI, then we'll just use the global users collection
            // this is where you would plug in your own custom identity management library (e.g. ASP.NET Identity)
            _users = users;// ?? 
            _iMSGConfigHelper = iMSGConfigHelper;
            _interaction = interaction;
            _clientStore = clientStore;
            _events = events;
            _configuration = configuration;
            _logger = logger;
        }

        private RefreshToken GetAccessTokenDataFromRefreshToken(string refreshToken)
        {
            var clientId = _iMSGConfigHelper.GoogleClientId;
            var clientSecret = _iMSGConfigHelper.GoogleClientSecret;

            string Url = _iMSGConfigHelper.GoogleTokenEndpoint;
            string data = "client_id={0}&client_secret={1}&refresh_token={2}&grant_type=refresh_token";

            HttpWebRequest request = HttpWebRequest.Create(Url) as HttpWebRequest;
            string result = null;
            request.Method = "POST";
            request.KeepAlive = true;
            request.ContentType = "application/x-www-form-urlencoded";
            string param = string.Format(data, clientId, clientSecret, refreshToken);
            var bs = Encoding.UTF8.GetBytes(param);
            using (Stream reqStream = request.GetRequestStream()) // <=== exception thrown with error "(400) Bad Request"
            {
                reqStream.Write(bs, 0, bs.Length);
            }

            using (WebResponse response = request.GetResponse())
            {
                var sr = new StreamReader(response.GetResponseStream());
                result = sr.ReadToEnd();
                sr.Close();
            }
           
            var tokenData = JsonConvert.DeserializeObject<RefreshToken>(result);

            return tokenData;
        }

        public async Task<IActionResult> Get()
        {
            ClaimsPrincipal currentUser = this.User;

            _logger.LogDebug("token endpoint reached");

            var result = await HttpContext.AuthenticateAsync("Bearer");
            if (result?.Succeeded != true)
            {
                _logger.LogDebug("token authentication failed");
                throw new Exception("External authentication error");
            }

            // lookup our user and external provider info
            var (user, provider, providerUserId, claims) = FindUserFromExternalProvider(result);

            Token token = null;
            if (user != null)
            {
                token = _users.Tokens.OrderByDescending(o=>o.Id).FirstOrDefault(f => f.UserId == user.Id);
                try
                {
                    if (token.Expires < DateTime.Now)
                    {
                        var tp = GetAccessTokenDataFromRefreshToken(token.Refresh);

                        token.Expires = DateTime.Now.AddSeconds(tp.expires_in);
                        token.Value = tp.access_token;
                        
                    }
                }
                catch(Exception e)
                {
                    Debug.WriteLine(e.Message);
                    throw e;
                }
              
            }
             
            if(token!=null)
            {
                 
                var json = JsonConvert.SerializeObject(token);

                return new JsonResult(token);
            }

            return new JsonResult("");


        }
        
        [Route("refresh")]
        public async Task<IActionResult> Refresh()
        {

            var response = HttpContext.Response;
 
            // This is what [Authorize] calls
            var userResult = await HttpContext.AuthenticateAsync("Bearer");
          
            var authProperties = userResult.Properties;
 
            if (userResult?.Succeeded != true)
            {
                return new JsonResult("Authentication failed");
            }

            var (user, provider, providerUserId, claims) = FindUserFromExternalProvider(userResult);

            Token token = null;
            if (user != null)
            {
                token = _users.Tokens.OrderByDescending(o => o.Id).FirstOrDefault(f => f.UserId == user.Id);
            }

         
            var options = await Task.FromResult<OAuthOptions>(HttpContext.RequestServices.GetRequiredService<IOptionsMonitor<GoogleOptions>>().Get(GoogleDefaults.AuthenticationScheme));

            var pairs = new Dictionary<string, string>()
                        {
                            { "client_id", _iMSGConfigHelper.GoogleClientId},
                            { "client_secret", _iMSGConfigHelper.GoogleClientSecret  },
                            { "grant_type", "refresh_token" },
                            { "refresh_token", token.Refresh }
                        };

            var content = new FormUrlEncodedContent(pairs);
               
            var refreshResponse = await options.Backchannel.PostAsync(options.TokenEndpoint, content, HttpContext.RequestAborted);
           
            
            refreshResponse.EnsureSuccessStatusCode();

            var payload = JObject.Parse(await refreshResponse.Content.ReadAsStringAsync());

            // Persist the new acess token
            var newAccessToken = payload.Value<string>("access_token");
            var newRefreshToken = payload.Value<string>("refresh_token");
        
            if (int.TryParse(payload.Value<string>("expires_in"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var seconds))
            {
                var expiresAt = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(seconds);

                var newtoken = new Token()
                {
                    Expires = expiresAt.DateTime,
                    Issued = token.Issued,
                    Name = token.Name,
                    UserId = user.Id,
                    Provider = provider,
                    Type = token.Type,
                    Value = newAccessToken,
                    Refresh = token.Refresh
                };

                _users.Tokens.Add(newtoken);
                _users.SaveChanges();

                var json = JsonConvert.SerializeObject(newtoken);

                return new JsonResult(newtoken);
            }

            return new JsonResult("Refresh has not been implemented for this provider");
        }

         

        private (AppUser user, string provider, string providerUserId, IEnumerable<Claim> claims) 
            FindUserFromExternalProvider(AuthenticateResult result)
        {
            var externalUser = result.Principal;

            // try to determine the unique id of the external user (issued by the provider)
            // the most common claim type for that are the sub claim and the NameIdentifier
            // depending on the external provider, some other claim type might be used
            var userIdClaim = externalUser.FindFirst(JwtClaimTypes.Subject) ??
                              externalUser.FindFirst(ClaimTypes.NameIdentifier) ??
                              throw new Exception("Unknown userid");

            // remove the user id claim so we don't include it as an extra claim if/when we provision the user
            var claims = externalUser.Claims.ToList();
            claims.Remove(userIdClaim);

            string provider = "";

            if(result.Properties.Items.ContainsKey("scheme"))
                provider = result.Properties.Items["scheme"];

            var providerUserId = userIdClaim.Value;

            // find external user
            var user = _users.Users.FirstOrDefault(f=>f.NameIdentifier == providerUserId); //_users.FindByExternalProvider(provider, providerUserId);

            return (user, provider, providerUserId, claims);
        }


        private Task<OAuthOptions> GetOAuthOptionsAsync(HttpContext context, string currentAuthType)
        {
            if (string.Equals(GoogleDefaults.AuthenticationScheme, currentAuthType))
            {
                return Task.FromResult<OAuthOptions>(context.RequestServices.GetRequiredService<IOptionsMonitor<GoogleOptions>>().Get(GoogleDefaults.AuthenticationScheme));
            }
         
            throw new NotImplementedException(currentAuthType);
        }

        private async Task PrintRefreshedTokensAsync(HttpResponse response, JObject payload, AuthenticationProperties authProperties)
        {
            response.ContentType = "text/html";
            await response.WriteAsync("<html><body>");
            await response.WriteAsync("Refreshed.<br>");
            await response.WriteAsync(HtmlEncoder.Default.Encode(payload.ToString()).Replace(",", ",<br>") + "<br>");

            await response.WriteAsync("<br>Tokens:<br>");

            await response.WriteAsync("Access Token: " + authProperties.GetTokenValue("access_token") + "<br>");
            await response.WriteAsync("Refresh Token: " + authProperties.GetTokenValue("refresh_token") + "<br>");
            await response.WriteAsync("Token Type: " + authProperties.GetTokenValue("token_type") + "<br>");
            await response.WriteAsync("expires_at: " + authProperties.GetTokenValue("expires_at") + "<br>");

            await response.WriteAsync("<a href=\"/\">Home</a><br>");
            await response.WriteAsync("<a href=\"/refresh_token\">Refresh Token</a><br>");
            await response.WriteAsync("</body></html>");
        }
    }
}