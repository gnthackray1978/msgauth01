using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityServer.Models
{

    public class GoogleSignInData
    {
        public string NameIdentifier { get; set; }

        public string FirstName { get; set; }

        public string Surname { get; set; }

        public string Email { get; set; }

        public string Name { get; set; }

        public DateTime TicketCreated { get; set; }

        public string Scheme { get; set; }

        public string AuthScheme { get; set; }

        public DateTime ExpiresAt { get; set; }
        public DateTime Expires { get; set; }
        public DateTime Issued { get; set; }

        public string TokenType { get; set; }

        public string AccessToken { get; set; }

        public string Refresh { get; set; }

        public string TokenName { get; set; }

        public string Locale { get; set; }

        public string Image { get; set; }
    }
}
