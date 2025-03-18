using System.Security.Claims;
using Duende.IdentityModel;
using IdentityServerTest.Data;
using IdentityServerTest.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Serilog;

namespace IdentityServerTest;

public static class SeedData
{
    public static void EnsureSeedData(WebApplication app)
    {
        using (var scope = app.Services.GetRequiredService<IServiceScopeFactory>().CreateScope())
        {
            var context = scope.ServiceProvider.GetService<ApplicationDbContext>();
            try
            {
                Log.Information("Starting database migration...");
                context.Database.Migrate();
                Log.Information("Database migration completed successfully.");
            }
            catch (Exception ex)
            {
                Log.Error(ex, "An error occurred while migrating the database.");
                throw;
            }

            var userMgr = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var roleMgr = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();

            // Create roles first
            EnsureRolesAsync(roleMgr).GetAwaiter().GetResult();

            // Then create users and assign roles
            EnsureUsersAsync(userMgr).GetAwaiter().GetResult();
        }
    }

    private static async Task EnsureRolesAsync(RoleManager<IdentityRole> roleMgr)
    {
        Log.Information("Creating roles...");

        // Define all roles with their claims
        var roles = new Dictionary<string, string[]>
        {
            { "Admin", new[] { "admin", "full_access" } },
            { "Support", new[] { "support", "customer_support" } },
            { "Registered", new[] { "user", "customer" } }
        };

        foreach (var role in roles)
        {
            var roleName = role.Key;
            var roleClaims = role.Value;

            var roleExists = await roleMgr.RoleExistsAsync(roleName);
            if (!roleExists)
            {
                var newRole = new IdentityRole(roleName)
                {
                    NormalizedName = roleName.ToUpper()
                };

                var result = await roleMgr.CreateAsync(newRole);
                if (!result.Succeeded)
                {
                    Log.Error("Failed to create role {RoleName}: {Errors}",
                        roleName, string.Join(", ", result.Errors.Select(e => e.Description)));
                    throw new Exception($"Failed to create role {roleName}");
                }

                // Add claims to the role
                foreach (var claimValue in roleClaims)
                {
                    var claim = new Claim("role", claimValue);
                    await roleMgr.AddClaimAsync(newRole, claim);
                }

                Log.Information("Created role {RoleName} with claims: {Claims}",
                    roleName, string.Join(", ", roleClaims));
            }
        }
    }

    private static async Task EnsureUsersAsync(UserManager<ApplicationUser> userMgr)
    {
        Log.Information("Creating users...");

        // Define all seed users
        var users = new[]
        {
            new
            {
                Username = "admin@eshop.com",
                Password = "Admin123!",
                FirstName = "System",
                LastName = "Administrator",
                Roles = new[] { "Admin" },
                Claims = new Dictionary<string, string>
                {
                    { "permission", "all" },
                    { "api_access", "full" }
                }
            },
            new
            {
                Username = "support@eshop.com",
                Password = "Support123!",
                FirstName = "Support",
                LastName = "Team",
                Roles = new[] { "Support" },
                Claims = new Dictionary<string, string>
                {
                    { "permission", "support" },
                    { "api_access", "limited" }
                }
            },
            new
            {
                Username = "user@eshop.com",
                Password = "User123!",
                FirstName = "Demo",
                LastName = "User",
                Roles = new[] { "Registered" },
                Claims = new Dictionary<string, string>
                {
                    { "permission", "basic" },
                    { "api_access", "user" }
                }
            }
        };

        foreach (var userData in users)
        {
            var user = await userMgr.FindByNameAsync(userData.Username);
            if (user == null)
            {
                user = new ApplicationUser
                {
                    UserName = userData.Username,
                    Email = userData.Username,
                    EmailConfirmed = true,
                    FirstName = userData.FirstName,
                    LastName = userData.LastName,
                    IsActive = true,
                    CreatedAt = DateTime.UtcNow,
                    HasCompletedRegistration = true
                };

                var result = await userMgr.CreateAsync(user, userData.Password);
                if (!result.Succeeded)
                {
                    Log.Error("Failed to create user {Username}: {Errors}",
                        userData.Username, string.Join(", ", result.Errors.Select(e => e.Description)));
                    throw new Exception($"Failed to create user {userData.Username}");
                }

                // Add user to roles
                foreach (var role in userData.Roles)
                {
                    await userMgr.AddToRoleAsync(user, role);
                }

                // Add claims to user
                var claims = new List<Claim>
                {
                    new Claim(JwtClaimTypes.Name, $"{userData.FirstName} {userData.LastName}"),
                    new Claim(JwtClaimTypes.GivenName, userData.FirstName),
                    new Claim(JwtClaimTypes.FamilyName, userData.LastName),
                    new Claim(JwtClaimTypes.Email, userData.Username)
                };

                // Add custom claims
                foreach (var claim in userData.Claims)
                {
                    claims.Add(new Claim(claim.Key, claim.Value));
                }

                // Add role claims
                foreach (var role in userData.Roles)
                {
                    claims.Add(new Claim(JwtClaimTypes.Role, role));
                }

                await userMgr.AddClaimsAsync(user, claims);

                Log.Information("Created user {Username} with roles: {Roles}",
                    userData.Username, string.Join(", ", userData.Roles));
            }
        }
    }
}

