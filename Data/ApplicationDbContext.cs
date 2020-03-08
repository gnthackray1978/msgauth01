using IdentityServer.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace IdentityServer.Data
{
    public class ApplicationDbContext : IdentityDbContext<AppUser> 
    {

        public ApplicationDbContext(
            DbContextOptions<ApplicationDbContext> options )
            : base(options)
        {
         
        }

        public DbSet<Token> Tokens { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {

            base.OnModelCreating(builder);
         
        }
    }
}
