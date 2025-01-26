using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using recurro.api.Models;

namespace recurro.api.Data
{
    public class ApplicationDbContext : IdentityDbContext<UserModel>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        // Add your entities here 
        // public DbSet<Entity> Entities { get; set; }

        public new DbSet<UserModel> Users { get; set; }
    }
}