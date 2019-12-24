using IdentityServer4.Models;
using IdentityServer4.Stores;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;



namespace IdentityServer
{
    public static class Extensions
    {
        /// <summary>
        /// Determines whether the client is configured to use PKCE.
        /// </summary>
        /// <param name="store">The store.</param>
        /// <param name="client_id">The client identifier.</param>
        /// <returns></returns>
        public static async Task<bool> IsPkceClientAsync(this IClientStore store, string client_id)
        {
            if (!string.IsNullOrWhiteSpace(client_id))
            {
                var client = await store.FindEnabledClientByIdAsync(client_id);
                return client?.RequirePkce == true;
            }

            return false;
        }
    }


    /// <summary>
    /// Extension methods for using Azure Key Vault with <see cref="IIdentityServerBuilder"/>.
    /// </summary>
    public static class IdentityServerAzureKeyVaultConfigurationExtensions
    {
        /// <summary>
        /// Adds a SigningCredentialStore and a ValidationKeysStore that reads the signing certificate from the Azure KeyVault.
        /// </summary>
        /// <param name="identityServerbuilder">The <see cref="IIdentityServerBuilder"/> to add to.</param>
        /// <param name="vault">The Azure KeyVault uri.</param>
        /// <param name="clientId">The application client id.</param>
        /// <param name="clientSecret">The client secret to use for authentication.</param>
        /// <param name="certificateName">The name of the certificate to use as the signing certificate.</param>
        /// <returns>The <see cref="IIdentityServerBuilder"/>.</returns>
        public static IIdentityServerBuilder AddSigningCredentialFromAzureKeyVault(this IIdentityServerBuilder identityServerbuilder, string vault, string clientId, string clientSecret, string certificateName, int signingKeyRolloverTimeInHours)
        {
            KeyVaultClient.AuthenticationCallback authenticationCallback = (authority, resource, scope) => GetTokenFromClientSecret(authority, resource, clientId, clientSecret);
            var keyVaultClient = new KeyVaultClient(authenticationCallback);

            identityServerbuilder.Services.AddMemoryCache();

            var sp = identityServerbuilder.Services.BuildServiceProvider();
            identityServerbuilder.Services.AddSingleton<ISigningCredentialStore>(new AzureKeyVaultSigningCredentialStore(sp.GetService<IMemoryCache>(), keyVaultClient, vault, certificateName, signingKeyRolloverTimeInHours));
            identityServerbuilder.Services.AddSingleton<IValidationKeysStore>(new AzureKeyVaultValidationKeysStore(sp.GetService<IMemoryCache>(), keyVaultClient, vault, certificateName));

            return identityServerbuilder;
        }

        /// <summary>
        /// Adds a SigningCredentialStore and a ValidationKeysStore that reads the signing certificate from the Azure KeyVault.
        /// </summary>
        /// <param name="identityServerbuilder">The <see cref="IIdentityServerBuilder"/> to add to.</param>
        /// <param name="vault">The Azure KeyVault uri.</param>
        /// <param name="certificateName">The name of the certificate to use as the signing certificate.</param>
        /// <remarks>Use this if you are using MSI (Managed Service Identity)</remarks>
        /// <returns>The <see cref="IIdentityServerBuilder"/>.</returns>
        public static IIdentityServerBuilder AddSigningCredentialFromAzureKeyVault(this IIdentityServerBuilder builder, string vault, string certificateName, int signingKeyRolloverTimeInHours)
        {
            var azureServiceTokenProvider = new AzureServiceTokenProvider();
            var authenticationCallback = new KeyVaultClient.AuthenticationCallback(azureServiceTokenProvider.KeyVaultTokenCallback);
            var keyVaultClient = new KeyVaultClient(authenticationCallback);

            builder.Services.AddMemoryCache();

            var sp = builder.Services.BuildServiceProvider();
            builder.Services.AddSingleton<ISigningCredentialStore>(new AzureKeyVaultSigningCredentialStore(sp.GetService<IMemoryCache>(), keyVaultClient, vault, certificateName, signingKeyRolloverTimeInHours));
            builder.Services.AddSingleton<IValidationKeysStore>(new AzureKeyVaultValidationKeysStore(sp.GetService<IMemoryCache>(), keyVaultClient, vault, certificateName));

            return builder;
        }

        private static async Task<string> GetTokenFromClientSecret(string authority, string resource, string clientId, string clientSecret)
        {
            var authContext = new AuthenticationContext(authority);
            var clientCred = new ClientCredential(clientId, clientSecret);
            var result = await authContext.AcquireTokenAsync(resource, clientCred);
            return result.AccessToken;
        }
    }

    public class AzureKeyVaultSigningCredentialStore : KeyStore, ISigningCredentialStore
    {
        private readonly IMemoryCache _cache;
        private readonly KeyVaultClient _keyVaultClient;
        private readonly string _vault;
        private readonly string _certificateName;
        private readonly int _signingKeyRolloverTimeInHours;

        public AzureKeyVaultSigningCredentialStore(IMemoryCache memoryCache, KeyVaultClient keyVaultClient, string vault, string certificateName, int signingKeyRolloverTimeInHours) : base(keyVaultClient, vault)
        {
            _cache = memoryCache;
            _keyVaultClient = keyVaultClient;
            _vault = vault;
            _certificateName = certificateName;
            _signingKeyRolloverTimeInHours = signingKeyRolloverTimeInHours;
        }

        public async Task<SigningCredentials> GetSigningCredentialsAsync()
        {
            // Try get the signing credentials from the cache
            if (_cache.TryGetValue("SigningCredentials", out SigningCredentials signingCredentials))
                return signingCredentials;

            signingCredentials = await GetFirstValidSigningCredentials();

            if (signingCredentials == null)
                return null;

            // Cache it
            var options = new MemoryCacheEntryOptions();
            options.AbsoluteExpiration = DateTime.Now.AddDays(1);
            _cache.Set("SigningCredentials", signingCredentials, options);

            return signingCredentials;
        }

        private async Task<SigningCredentials> GetFirstValidSigningCredentials()
        {
            // Find all enabled versions of the certificate
            var enabledCertificateVersions = await GetAllEnabledCertificateVersionsAsync(_certificateName);

            if (!enabledCertificateVersions.Any())
            {
                return null;
            }

            // Find the first certificate version that has a passed rollover time
            var certificateVersionWithPassedRolloverTime = enabledCertificateVersions
              .FirstOrDefault(certVersion => certVersion.Attributes.Created.HasValue && certVersion.Attributes.Created.Value < DateTime.UtcNow.AddHours(-_signingKeyRolloverTimeInHours));

            // If no certificate with passed rollovertime was found, pick the first enabled version of the certificate (This can happen if it's a newly created certificate)
            if (certificateVersionWithPassedRolloverTime == null)
            {
                return await GetSigningCredentialsFromCertificateAsync(enabledCertificateVersions.First());
            }
            else
            {
                return await GetSigningCredentialsFromCertificateAsync(certificateVersionWithPassedRolloverTime);
            }
        }
    }

    public class AzureKeyVaultValidationKeysStore : KeyStore, IValidationKeysStore
    {
        private readonly IMemoryCache _cache;
        private readonly KeyVaultClient _keyVaultClient;
        private readonly string _vault;
        private readonly string _certificateName;

        public AzureKeyVaultValidationKeysStore(IMemoryCache memoryCache, KeyVaultClient keyVaultClient, string vault, string certificateName) : base(keyVaultClient, vault)
        {
            _cache = memoryCache;
            _keyVaultClient = keyVaultClient;
            _vault = vault;
            _certificateName = certificateName;
        }
        //Task<IEnumerable<SecurityKeyInfo>> GetValidationKeysAsync();
        public async Task<IEnumerable<SecurityKeyInfo>> GetValidationKeysAsync()
        {
            // Try get the signing credentials from the cache
            if (_cache.TryGetValue("ValidationKeys", out List<SecurityKeyInfo> validationKeys))
                return validationKeys;

            validationKeys = new List<SecurityKeyInfo>();

            // Get all the certificate versions (this will also get the currect active version)
            var enabledCertificateVersions = await GetAllEnabledCertificateVersionsAsync(_certificateName);
            foreach (var certificateItem in enabledCertificateVersions)
            {
                // Add the security key to validation keys so any JWT tokens signed with a older version of the signing certificate
                validationKeys.Add(await GetSecurityKeyFromCertificateAsync(certificateItem));
            }

            // Add the validation keys to the cache
            var options = new MemoryCacheEntryOptions();
            options.AbsoluteExpiration = DateTime.Now.AddDays(1);
            _cache.Set("ValidationKeys", validationKeys, options);

            return validationKeys;
        }
    }

    public abstract class KeyStore
    {
        private readonly KeyVaultClient _keyVaultClient;
        private readonly string _vault;

        public KeyStore(KeyVaultClient keyVaultClient, string vault)
        {
            _keyVaultClient = keyVaultClient;
            _vault = vault;
        }

        internal async Task<List<Microsoft.Azure.KeyVault.Models.CertificateItem>> GetAllEnabledCertificateVersionsAsync(string certificateName)
        {
            // Get all the certificate versions (this will also get the currect active version)
            var certificateVersions = await _keyVaultClient.GetCertificateVersionsAsync(_vault, certificateName);

            // Find all enabled versions of the certificate and sort them by creation date in decending order 
            return certificateVersions
              .Where(certVersion => certVersion.Attributes.Enabled.HasValue && certVersion.Attributes.Enabled.Value)
              .OrderByDescending(certVersion => certVersion.Attributes.Created)
              .ToList();
        }
        internal async Task<SigningCredentials> GetSigningCredentialsFromCertificateAsync(Microsoft.Azure.KeyVault.Models.CertificateItem certificateItem)
        {
            var certificateVersionSecurityKey = await GetSecurityKeyFromCertificateAsync(certificateItem);
            return new SigningCredentials(certificateVersionSecurityKey.Key, certificateVersionSecurityKey.SigningAlgorithm);
        }
        internal async Task<SecurityKeyInfo> GetSecurityKeyFromCertificateAsync(Microsoft.Azure.KeyVault.Models.CertificateItem certificateItem)
        {
            var certificateVersionBundle = await _keyVaultClient.GetCertificateAsync(certificateItem.Identifier.Identifier);
            var certificatePrivateKeySecretBundle = await _keyVaultClient.GetSecretAsync(certificateVersionBundle.SecretIdentifier.Identifier);
            var privateKeyBytes = Convert.FromBase64String(certificatePrivateKeySecretBundle.Value);
            var certificateWithPrivateKey = new X509Certificate2(privateKeyBytes, (string)null, X509KeyStorageFlags.MachineKeySet);
            var tp = new SecurityKeyInfo();
            //certificateWithPrivateKey.SignatureAlgorithm
            tp.Key = new X509SecurityKey(certificateWithPrivateKey);
            tp.SigningAlgorithm = SecurityAlgorithms.RsaSha256;
            return tp;
        }
    }

}
