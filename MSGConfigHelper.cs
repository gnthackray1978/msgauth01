using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace Api
{
    public interface IMSGConfigHelper
    {
        string TestClientUrl { get; set; }
        string AuthServerUrl { get; set; }

        string MSGApiGenUrl { get; set; }

        string MSGGenDB01 { get; set; }

        X509Certificate2 MSGCert01 { get; set; }


        //GoogleClientId
        string GoogleClientId { get; set; }

        //GoogleClientSecret
        string GoogleClientSecret { get; set; }

        string GoogleTokenEndpoint { get; set; }

       
    }

    public class MSGConfigHelper : IMSGConfigHelper
    {
        public string GoogleTokenEndpoint { get; set; }

        public string GoogleClientId { get; set; }


        public string GoogleClientSecret { get; set; }

        public string TestClientUrl { get; set; }

        public string AuthServerUrl { get; set; }

        public string MSGApiGenUrl { get; set; }

        public string MSGGenDB01 { get; set; }

        public X509Certificate2 MSGCert01 { get; set; }

        //private readonly IConfiguration _configuration;

        public MSGConfigHelper(IConfiguration configuration)
        {
            //_configuration = configuration;

            TestClientUrl = configuration["TestClientUrl"];

             AuthServerUrl = configuration["AuthServerUrl"];

          //  AuthServerUrl = "http://localhost:5000";

            MSGApiGenUrl = configuration["MSGApiGenUrl"];

            MSGGenDB01 = configuration["MSGGenDB01"];
            GoogleTokenEndpoint = configuration["GoogleTokenEndpoint"];
            GoogleClientId = configuration["GoogleClientId"];
            GoogleClientSecret = configuration["GoogleClientSecret"];

            var key = configuration["MSGCert01"];

            var pfxBytes = Convert.FromBase64String(key);
            var cert = new X509Certificate2(pfxBytes, (string)null, X509KeyStorageFlags.MachineKeySet);
            MSGCert01 = cert;

            //builder.AddSigningCredential(cert);

        }


    }

     
}
