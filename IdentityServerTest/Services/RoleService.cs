using IdentityServerTest.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace IdentityServerTest.Services;

public interface IRoleService
{
    Task<IEnumerable<IdentityRole>> GetAllRolesAsync();
    Task<IdentityRole> GetRoleByIdAsync(string roleId);
    Task<IdentityRole> GetRoleByNameAsync(string roleName);
    Task<bool> CreateRoleAsync(string roleName, IEnumerable<Claim> claims = null);
    Task<bool> UpdateRoleAsync(string roleId, string roleName);
    Task<bool> DeleteRoleAsync(string roleId);
    Task<IEnumerable<Claim>> GetRoleClaimsAsync(string roleId);
    Task<bool> AddClaimToRoleAsync(string roleId, Claim claim);
    Task<bool> RemoveClaimFromRoleAsync(string roleId, Claim claim);
    Task<IEnumerable<string>> GetUsersInRoleAsync(string roleName);
}

public class RoleService : IRoleService
{
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ILogger<RoleService> _logger;

    public RoleService(
        RoleManager<IdentityRole> roleManager,
        UserManager<ApplicationUser> userManager,
        ILogger<RoleService> logger)
    {
        _roleManager = roleManager;
        _userManager = userManager;
        _logger = logger;
    }

    public async Task<IEnumerable<IdentityRole>> GetAllRolesAsync()
    {
        return await _roleManager.Roles.OrderBy(r => r.Name).ToListAsync();
    }

    public async Task<IdentityRole> GetRoleByIdAsync(string roleId)
    {
        if (string.IsNullOrEmpty(roleId))
        {
            throw new ArgumentException("Role ID cannot be null or empty", nameof(roleId));
        }

        var role = await _roleManager.FindByIdAsync(roleId);
        if (role == null)
        {
            _logger.LogWarning("Role with ID {RoleId} not found", roleId);
        }

        return role;
    }

    public async Task<IdentityRole> GetRoleByNameAsync(string roleName)
    {
        if (string.IsNullOrEmpty(roleName))
        {
            throw new ArgumentException("Role name cannot be null or empty", nameof(roleName));
        }

        var role = await _roleManager.FindByNameAsync(roleName);
        if (role == null)
        {
            _logger.LogWarning("Role with name {RoleName} not found", roleName);
        }

        return role;
    }

    public async Task<bool> CreateRoleAsync(string roleName, IEnumerable<Claim> claims = null)
    {
        if (string.IsNullOrEmpty(roleName))
        {
            throw new ArgumentException("Role name cannot be null or empty", nameof(roleName));
        }

        if (await _roleManager.RoleExistsAsync(roleName))
        {
            _logger.LogWarning("Role with name {RoleName} already exists", roleName);
            return false;
        }

        var role = new IdentityRole(roleName);
        var result = await _roleManager.CreateAsync(role);

        if (!result.Succeeded)
        {
            _logger.LogError("Failed to create role {RoleName}: {Errors}",
                roleName, string.Join(", ", result.Errors.Select(e => e.Description)));
            return false;
        }

        // Add claims if provided
        if (claims != null)
        {
            foreach (var claim in claims)
            {
                var claimResult = await _roleManager.AddClaimAsync(role, claim);
                if (!claimResult.Succeeded)
                {
                    _logger.LogError("Failed to add claim {ClaimType}:{ClaimValue} to role {RoleName}: {Errors}",
                        claim.Type, claim.Value, roleName, string.Join(", ", claimResult.Errors.Select(e => e.Description)));
                }
            }
        }

        _logger.LogInformation("Role {RoleName} created", roleName);
        return true;
    }

    public async Task<bool> UpdateRoleAsync(string roleId, string roleName)
    {
        var role = await GetRoleByIdAsync(roleId);
        if (role == null)
        {
            return false;
        }

        if (string.IsNullOrEmpty(roleName))
        {
            throw new ArgumentException("Role name cannot be null or empty", nameof(roleName));
        }

        // Don't update if name hasn't changed
        if (role.Name == roleName)
        {
            return true;
        }

        // Check if another role already has this name
        var existingRole = await _roleManager.FindByNameAsync(roleName);
        if (existingRole != null && existingRole.Id != roleId)
        {
            _logger.LogWarning("Another role with name {RoleName} already exists", roleName);
            return false;
        }

        role.Name = roleName;
        var result = await _roleManager.UpdateAsync(role);

        if (!result.Succeeded)
        {
            _logger.LogError("Failed to update role {RoleId}: {Errors}",
                roleId, string.Join(", ", result.Errors.Select(e => e.Description)));
            return false;
        }

        _logger.LogInformation("Role {RoleId} updated", roleId);
        return true;
    }

    public async Task<bool> DeleteRoleAsync(string roleId)
    {
        var role = await GetRoleByIdAsync(roleId);
        if (role == null)
        {
            return false;
        }

        // Check if role is in use
        var usersInRole = await _userManager.GetUsersInRoleAsync(role.Name);
        if (usersInRole.Any())
        {
            _logger.LogWarning("Cannot delete role {RoleName} because it has {UserCount} assigned users",
                role.Name, usersInRole.Count);
            return false;
        }

        var result = await _roleManager.DeleteAsync(role);
        if (!result.Succeeded)
        {
            _logger.LogError("Failed to delete role {RoleId}: {Errors}",
                roleId, string.Join(", ", result.Errors.Select(e => e.Description)));
            return false;
        }

        _logger.LogInformation("Role {RoleName} deleted", role.Name);
        return true;
    }

    public async Task<IEnumerable<Claim>> GetRoleClaimsAsync(string roleId)
    {
        var role = await GetRoleByIdAsync(roleId);
        if (role == null)
        {
            return Enumerable.Empty<Claim>();
        }

        return await _roleManager.GetClaimsAsync(role);
    }

    public async Task<bool> AddClaimToRoleAsync(string roleId, Claim claim)
    {
        var role = await GetRoleByIdAsync(roleId);
        if (role == null)
        {
            return false;
        }

        var existingClaims = await _roleManager.GetClaimsAsync(role);
        if (existingClaims.Any(c => c.Type == claim.Type && c.Value == claim.Value))
        {
            _logger.LogInformation("Claim {ClaimType}:{ClaimValue} already exists for role {RoleId}",
                claim.Type, claim.Value, roleId);
            return true;
        }

        var result = await _roleManager.AddClaimAsync(role, claim);
        if (!result.Succeeded)
        {
            _logger.LogError("Failed to add claim {ClaimType}:{ClaimValue} to role {RoleId}: {Errors}",
                claim.Type, claim.Value, roleId, string.Join(", ", result.Errors.Select(e => e.Description)));
            return false;
        }

        _logger.LogInformation("Claim {ClaimType}:{ClaimValue} added to role {RoleName}",
            claim.Type, claim.Value, role.Name);
        return true;
    }

    public async Task<bool> RemoveClaimFromRoleAsync(string roleId, Claim claim)
    {
        var role = await GetRoleByIdAsync(roleId);
        if (role == null)
        {
            return false;
        }

        var existingClaims = await _roleManager.GetClaimsAsync(role);
        var matchingClaim = existingClaims.FirstOrDefault(c => c.Type == claim.Type && c.Value == claim.Value);

        if (matchingClaim == null)
        {
            _logger.LogWarning("Claim {ClaimType}:{ClaimValue} not found for role {RoleId}",
                claim.Type, claim.Value, roleId);
            return true;
        }

        var result = await _roleManager.RemoveClaimAsync(role, matchingClaim);
        if (!result.Succeeded)
        {
            _logger.LogError("Failed to remove claim {ClaimType}:{ClaimValue} from role {RoleId}: {Errors}",
                claim.Type, claim.Value, roleId, string.Join(", ", result.Errors.Select(e => e.Description)));
            return false;
        }

        _logger.LogInformation("Claim {ClaimType}:{ClaimValue} removed from role {RoleName}",
            claim.Type, claim.Value, role.Name);
        return true;
    }

    public async Task<IEnumerable<string>> GetUsersInRoleAsync(string roleName)
    {
        if (string.IsNullOrEmpty(roleName))
        {
            throw new ArgumentException("Role name cannot be null or empty", nameof(roleName));
        }

        if (!await _roleManager.RoleExistsAsync(roleName))
        {
            _logger.LogWarning("Role {RoleName} not found", roleName);
            return Enumerable.Empty<string>();
        }

        var users = await _userManager.GetUsersInRoleAsync(roleName);
        return users.Select(u => u.UserName);
    }
}