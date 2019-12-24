using System;

namespace IdentityServer.Models
{
    public class Token
    {
        public int Id { get; set; }
        public string UserId { get; set; }
        public string Provider { get; set; }  // navigation property
        public string Type { get; set; }
        
        public string ImageUrl { get; set; }

        public string Locale { get; set; }

        public DateTime Expires { get; set; }
        public DateTime Issued { get; set; }

        public string Name { get; set; }

        public string Value { get; set; }

        public string Refresh { get; set; }
    }
}
