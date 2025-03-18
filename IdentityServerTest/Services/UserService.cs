using Duende.IdentityModel;
using IdentityServerTest.Data;
using IdentityServerTest.Models;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;

namespace IdentityServerTest.Services;


public interface IUserService
{
    Task<ApplicationUser> GetUserByIdAsync(string userId);
    Task<ApplicationUser> GetUserByEmailAsync(string email);
    Task<IEnumerable<ApplicationUser>> GetAllUsersAsync();
    Task<IEnumerable<ApplicationUser>> GetUsersByRoleAsync(string roleName);
    Task<bool> AddUserToRoleAsync(string userId, string roleName);
    Task<bool> RemoveUserFromRoleAsync(string userId, string roleName);
    Task<bool> LockUserAsync(string userId, TimeSpan duration);
    Task<bool> UnlockUserAsync(string userId);
    Task<bool> DeactivateUserAsync(string userId);
    Task<bool> ActivateUserAsync(string userId);
    Task<bool> SetTwoFactorEnabledAsync(string userId, bool enabled);
    Task<IEnumerable<string>> GetUserRolesAsync(string userId);
    Task<IEnumerable<Claim>> GetUserClaimsAsync(string userId);
    Task<bool> AddClaimToUserAsync(string userId, Claim claim);
    Task<bool> RemoveClaimFromUserAsync(string userId, string claimType);
    Task<bool> UpdateUserAsync(ApplicationUser user);
    Task<UserLoginHistory> RecordUserLoginAsync(string userId, string ipAddress, string userAgent, string result);
    Task<IEnumerable<UserLoginHistory>> GetUserLoginHistoryAsync(string userId, int limit = 10);
}

public class UserService : IUserService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly ApplicationDbContext _dbContext;
    private readonly ILogger<UserService> _logger;

    public UserService(
        UserManager<ApplicationUser> userManager,
        RoleManager<IdentityRole> roleManager,
        ApplicationDbContext dbContext,
        ILogger<UserService> logger)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _dbContext = dbContext;
        _logger = logger;
    }

    public async Task<ApplicationUser> GetUserByIdAsync(string userId)
    {
        if (string.IsNullOrEmpty(userId))
        {
            throw new ArgumentException("User ID cannot be null or empty", nameof(userId));
        }

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            _logger.LogWarning("User with ID {UserId} not found", userId);
        }

        return user;
    }

    public async Task<ApplicationUser> GetUserByEmailAsync(string email)
    {
        if (string.IsNullOrEmpty(email))
        {
            throw new ArgumentException("Email cannot be null or empty", nameof(email));
        }

        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            _logger.LogWarning("User with email {Email} not found", email);
        }

        return user;
    }

    public async Task<IEnumerable<ApplicationUser>> GetAllUsersAsync()
    {
        return await _userManager.Users
            .Where(u => u.IsActive)
            .OrderBy(u => u.Email)
            .ToListAsync();
    }

    public async Task<IEnumerable<ApplicationUser>> GetUsersByRoleAsync(string roleName)
    {
        if (string.IsNullOrEmpty(roleName))
        {
            throw new ArgumentException("Role name cannot be null or empty", nameof(roleName));
        }

        if (!await _roleManager.RoleExistsAsync(roleName))
        {
            _logger.LogWarning("Role {RoleName} not found", roleName);
            return Enumerable.Empty<ApplicationUser>();
        }

        var usersInRole = await _userManager.GetUsersInRoleAsync(roleName);
        return usersInRole.Where(u => u.IsActive);
    }

    public async Task<bool> AddUserToRoleAsync(string userId, string roleName)
    {
        var user = await GetUserByIdAsync(userId);
        if (user == null)
        {
            return false;
        }

        if (!await _roleManager.RoleExistsAsync(roleName))
        {
            _logger.LogWarning("Role {RoleName} not found", roleName);
            return false;
        }

        // Check if user already in role
        if (await _userManager.IsInRoleAsync(user, roleName))
        {
            _logger.LogInformation("User {UserId} is already in role {RoleName}", userId, roleName);
            return true;
        }

        var result = await _userManager.AddToRoleAsync(user, roleName);
        if (!result.Succeeded)
        {
            _logger.LogError("Failed to add user {UserId} to role {RoleName}: {Errors}",
                userId, roleName, string.Join(", ", result.Errors.Select(e => e.Description)));
            return false;
        }

        // Add role claim
        await _userManager.AddClaimAsync(user, new Claim(ClaimTypes.Role, roleName));

        _logger.LogInformation("User {UserId} added to role {RoleName}", userId, roleName);
        return true;
    }

    public async Task<bool> RemoveUserFromRoleAsync(string userId, string roleName)
    {
        var user = await GetUserByIdAsync(userId);
        if (user == null)
        {
            return false;
        }

        // Prevent removing the last admin user
        if (roleName == "Admin")
        {
            var adminUsers = await _userManager.GetUsersInRoleAsync("Admin");
            if (adminUsers.Count <= 1 && adminUsers.Any(u => u.Id == userId))
            {
                _logger.LogWarning("Cannot remove the last Admin user");
                return false;
            }
        }

        var result = await _userManager.RemoveFromRoleAsync(user, roleName);
        if (!result.Succeeded)
        {
            _logger.LogError("Failed to remove user {UserId} from role {RoleName}: {Errors}",
                userId, roleName, string.Join(", ", result.Errors.Select(e => e.Description)));
            return false;
        }

        // Remove role claim
        var roleClaim = (await _userManager.GetClaimsAsync(user))
            .FirstOrDefault(c => c.Type == ClaimTypes.Role && c.Value == roleName);

        if (roleClaim != null)
        {
            await _userManager.RemoveClaimAsync(user, roleClaim);
        }

        _logger.LogInformation("User {UserId} removed from role {RoleName}", userId, roleName);
        return true;
    }

    public async Task<bool> LockUserAsync(string userId, TimeSpan duration)
    {
        var user = await GetUserByIdAsync(userId);
        if (user == null)
        {
            return false;
        }

        // Prevent locking admin users
        if (await _userManager.IsInRoleAsync(user, "Admin"))
        {
            _logger.LogWarning("Cannot lock admin user {UserId}", userId);
            return false;
        }

        var result = await _userManager.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow.Add(duration));
        if (!result.Succeeded)
        {
            _logger.LogError("Failed to lock user {UserId}: {Errors}",
                userId, string.Join(", ", result.Errors.Select(e => e.Description)));
            return false;
        }

        _logger.LogInformation("User {UserId} locked for {Duration}", userId, duration);
        return true;
    }

    public async Task<bool> UnlockUserAsync(string userId)
    {
        var user = await GetUserByIdAsync(userId);
        if (user == null)
        {
            return false;
        }

        var result = await _userManager.SetLockoutEndDateAsync(user, null);
        if (!result.Succeeded)
        {
            _logger.LogError("Failed to unlock user {UserId}: {Errors}",
                userId, string.Join(", ", result.Errors.Select(e => e.Description)));
            return false;
        }

        // Reset failed access count
        await _userManager.ResetAccessFailedCountAsync(user);

        _logger.LogInformation("User {UserId} unlocked", userId);
        return true;
    }

    public async Task<bool> DeactivateUserAsync(string userId)
    {
        var user = await GetUserByIdAsync(userId);
        if (user == null)
        {
            return false;
        }

        // Prevent deactivating the last admin user
        if (await _userManager.IsInRoleAsync(user, "Admin"))
        {
            var adminUsers = await _userManager.GetUsersInRoleAsync("Admin");
            if (adminUsers.Count <= 1)
            {
                _logger.LogWarning("Cannot deactivate the last admin user {UserId}", userId);
                return false;
            }
        }

        user.IsActive = false;
        var result = await _userManager.UpdateAsync(user);
        if (!result.Succeeded)
        {
            _logger.LogError("Failed to deactivate user {UserId}: {Errors}",
                userId, string.Join(", ", result.Errors.Select(e => e.Description)));
            return false;
        }

        _logger.LogInformation("User {UserId} deactivated", userId);
        return true;
    }

    public async Task<bool> ActivateUserAsync(string userId)
    {
        var user = await GetUserByIdAsync(userId);
        if (user == null)
        {
            return false;
        }

        user.IsActive = true;
        var result = await _userManager.UpdateAsync(user);
        if (!result.Succeeded)
        {
            _logger.LogError("Failed to activate user {UserId}: {Errors}",
                userId, string.Join(", ", result.Errors.Select(e => e.Description)));
            return false;
        }

        _logger.LogInformation("User {UserId} activated", userId);
        return true;
    }

    public async Task<bool> SetTwoFactorEnabledAsync(string userId, bool enabled)
    {
        var user = await GetUserByIdAsync(userId);
        if (user == null)
        {
            return false;
        }

        var result = await _userManager.SetTwoFactorEnabledAsync(user, enabled);
        if (!result.Succeeded)
        {
            _logger.LogError("Failed to set two-factor authentication for user {UserId}: {Errors}",
                userId, string.Join(", ", result.Errors.Select(e => e.Description)));
            return false;
        }

        _logger.LogInformation("Two-factor authentication for user {UserId} set to {Enabled}", userId, enabled);
        return true;
    }

    public async Task<IEnumerable<string>> GetUserRolesAsync(string userId)
    {
        var user = await GetUserByIdAsync(userId);
        if (user == null)
        {
            return Enumerable.Empty<string>();
        }

        return await _userManager.GetRolesAsync(user);
    }

    public async Task<IEnumerable<Claim>> GetUserClaimsAsync(string userId)
    {
        var user = await GetUserByIdAsync(userId);
        if (user == null)
        {
            return Enumerable.Empty<Claim>();
        }

        return await _userManager.GetClaimsAsync(user);
    }

    public async Task<bool> AddClaimToUserAsync(string userId, Claim claim)
    {
        var user = await GetUserByIdAsync(userId);
        if (user == null)
        {
            return false;
        }

        var result = await _userManager.AddClaimAsync(user, claim);
        if (!result.Succeeded)
        {
            _logger.LogError("Failed to add claim {ClaimType}:{ClaimValue} to user {UserId}: {Errors}",
                claim.Type, claim.Value, userId, string.Join(", ", result.Errors.Select(e => e.Description)));
            return false;
        }

        _logger.LogInformation("Claim {ClaimType}:{ClaimValue} added to user {UserId}",
            claim.Type, claim.Value, userId);
        return true;
    }

    public async Task<bool> RemoveClaimFromUserAsync(string userId, string claimType)
    {
        var user = await GetUserByIdAsync(userId);
        if (user == null)
        {
            return false;
        }

        var claims = await _userManager.GetClaimsAsync(user);
        var claimsToRemove = claims.Where(c => c.Type == claimType).ToList();

        if (!claimsToRemove.Any())
        {
            _logger.LogWarning("No claims of type {ClaimType} found for user {UserId}", claimType, userId);
            return true;
        }

        foreach (var claim in claimsToRemove)
        {
            var result = await _userManager.RemoveClaimAsync(user, claim);
            if (!result.Succeeded)
            {
                _logger.LogError("Failed to remove claim {ClaimType}:{ClaimValue} from user {UserId}: {Errors}",
                    claim.Type, claim.Value, userId, string.Join(", ", result.Errors.Select(e => e.Description)));
                return false;
            }
        }

        _logger.LogInformation("Claims of type {ClaimType} removed from user {UserId}", claimType, userId);
        return true;
    }

    public async Task<bool> UpdateUserAsync(ApplicationUser user)
    {
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        var result = await _userManager.UpdateAsync(user);
        if (!result.Succeeded)
        {
            _logger.LogError("Failed to update user {UserId}: {Errors}",
                user.Id, string.Join(", ", result.Errors.Select(e => e.Description)));
            return false;
        }

        _logger.LogInformation("User {UserId} updated", user.Id);
        return true;
    }

    public async Task<UserLoginHistory> RecordUserLoginAsync(string userId, string ipAddress, string userAgent, string result)
    {
        var loginRecord = new UserLoginHistory
        {
            UserId = userId,
            LoginTime = DateTime.UtcNow,
            IpAddress = ipAddress,
            UserAgent = userAgent,
            LoginResult = result
        };

        _dbContext.UserLoginHistory.Add(loginRecord);
        await _dbContext.SaveChangesAsync();

        _logger.LogInformation("Login record created for user {UserId}, result: {Result}", userId, result);
        return loginRecord;
    }

    public async Task<IEnumerable<UserLoginHistory>> GetUserLoginHistoryAsync(string userId, int limit = 10)
    {
        return await _dbContext.UserLoginHistory
            .Where(h => h.UserId == userId)
            .OrderByDescending(h => h.LoginTime)
            .Take(limit)
            .ToListAsync();
    }
}
