using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using IdentityServerTest.Models;
using Microsoft.AspNetCore.Identity;

namespace IdentityServerTest.Data;

public class ApplicationDbContext : IdentityDbContext<ApplicationUser, IdentityRole, string>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    // Add any additional DbSets as needed
    public DbSet<UserLoginHistory> UserLoginHistory { get; set; }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        // Customize ASP.NET Identity schema
        builder.Entity<ApplicationUser>(entity =>
        {
            entity.ToTable("Users");

            // Configure additional properties
            entity.Property(u => u.FirstName).IsRequired().HasMaxLength(50);
            entity.Property(u => u.LastName).IsRequired().HasMaxLength(50);
            entity.Property(u => u.CreatedAt).IsRequired();
            entity.Property(u => u.IsActive).IsRequired().HasDefaultValue(true);

            // Index for performance
            entity.HasIndex(u => u.CreatedAt);
            entity.HasIndex(u => u.IsActive);
        });

        // Configure identity tables with better names
        builder.Entity<IdentityRole>(entity =>
            entity.ToTable("Roles"));

        builder.Entity<IdentityUserRole<string>>(entity =>
            entity.ToTable("UserRoles"));

        builder.Entity<IdentityUserClaim<string>>(entity =>
            entity.ToTable("UserClaims"));

        builder.Entity<IdentityUserLogin<string>>(entity =>
            entity.ToTable("UserLogins"));

        builder.Entity<IdentityRoleClaim<string>>(entity =>
            entity.ToTable("RoleClaims"));

        builder.Entity<IdentityUserToken<string>>(entity =>
            entity.ToTable("UserTokens"));

        // Configure UserLoginHistory
        builder.Entity<UserLoginHistory>(entity =>
        {
            entity.ToTable("UserLoginHistory");
            entity.HasKey(h => h.Id);

            entity.Property(h => h.UserId).IsRequired();
            entity.Property(h => h.LoginTime).IsRequired();
            entity.Property(h => h.IpAddress).HasMaxLength(50);
            entity.Property(h => h.UserAgent).HasMaxLength(500);

            entity.HasIndex(h => h.UserId);
            entity.HasIndex(h => h.LoginTime);

            // Establish relationship with ApplicationUser
            entity.HasOne<ApplicationUser>()
                  .WithMany()
                  .HasForeignKey(h => h.UserId)
                  .OnDelete(DeleteBehavior.Cascade);
        });
    }

    public override async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        // Automatically update timestamps for auditing purposes
        var entries = ChangeTracker.Entries<ApplicationUser>();

        foreach (var entry in entries)
        {
            if (entry.State == EntityState.Modified)
            {
                entry.Entity.LastActivityAt = DateTime.UtcNow;
            }
        }

        return await base.SaveChangesAsync(cancellationToken);
    }
}

// Entity for tracking user login history
public class UserLoginHistory
{
    public int Id { get; set; }
    public string UserId { get; set; } = default!;
    public DateTime LoginTime { get; set; }
    public string IpAddress { get; set; } = default!;
    public string UserAgent { get; set; } = default!;
    public string LoginResult { get; set; } = default!;
    public string Location { get; set; } = default!;
}