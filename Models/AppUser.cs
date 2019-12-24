using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.AspNetCore.Identity;

namespace IdentityServer.Models
{
    public class AppUser : IdentityUser
    {
        // Extended Properties
        public string FirstName { get; set; }
         
        public string LastName { get; set; }
        public long? FacebookId { get; set; }
        public string PictureUrl { get; set; }
        public string NameIdentifier { get; set; }
    }
}
