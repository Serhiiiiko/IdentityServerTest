using IdentityServerTest.Models;
using IdentityServerTest.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;

namespace IdentityServerTest.Controllers;


[Route("api/[controller]")]
[ApiController]
[Authorize(Policy = "RequireAdminRole")]
public class UserManagementController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IUserService _userService;
    private readonly IRoleService _roleService;
    private readonly ILogger<UserManagementController> _logger;

    public UserManagementController(
        UserManager<ApplicationUser> userManager,
        IUserService userService,
        IRoleService roleService,
        ILogger<UserManagementController> logger)
    {
        _userManager = userManager;
        _userService = userService;
        _roleService = roleService;
        _logger = logger;
    }

    [HttpGet("users")]
    public async Task<IActionResult> GetUsers([FromQuery] UserFilterRequest filter)
    {
        var query = _userManager.Users.AsQueryable();

        // Apply filters if provided
        if (!string.IsNullOrEmpty(filter.SearchTerm))
        {
            query = query.Where(u =>
                u.Email.Contains(filter.SearchTerm) ||
                u.UserName.Contains(filter.SearchTerm) ||
                u.FirstName.Contains(filter.SearchTerm) ||
                u.LastName.Contains(filter.SearchTerm));
        }

        if (filter.IsActive.HasValue)
        {
            query = query.Where(u => u.IsActive == filter.IsActive.Value);
        }

        if (filter.FromDate.HasValue)
        {
            query = query.Where(u => u.CreatedAt >= filter.FromDate.Value);
        }

        if (filter.ToDate.HasValue)
        {
            query = query.Where(u => u.CreatedAt <= filter.ToDate.Value);
        }

        if (!string.IsNullOrEmpty(filter.Role))
        {
            var usersInRole = await _userManager.GetUsersInRoleAsync(filter.Role);
            var userIds = usersInRole.Select(u => u.Id).ToList();
            query = query.Where(u => userIds.Contains(u.Id));
        }

        // Apply sorting
        query = filter.SortBy?.ToLower() switch
        {
            "email" => filter.SortDescending == true ? query.OrderByDescending(u => u.Email) : query.OrderBy(u => u.Email),
            "firstname" => filter.SortDescending == true ? query.OrderByDescending(u => u.FirstName) : query.OrderBy(u => u.FirstName),
            "lastname" => filter.SortDescending == true ? query.OrderByDescending(u => u.LastName) : query.OrderBy(u => u.LastName),
            "createdat" => filter.SortDescending == true ? query.OrderByDescending(u => u.CreatedAt) : query.OrderBy(u => u.CreatedAt),
            "lastloginat" => filter.SortDescending == true ? query.OrderByDescending(u => u.LastLoginAt) : query.OrderBy(u => u.LastLoginAt),
            _ => query.OrderBy(u => u.Email)
        };

        // Apply pagination
        var pageSize = filter.PageSize ?? 10;
        var pageNumber = filter.PageNumber ?? 1;

        var totalCount = await query.CountAsync();
        var users = await query
            .Skip((pageNumber - 1) * pageSize)
            .Take(pageSize)
            .Select(u => new
            {
                u.Id,
                u.UserName,
                u.Email,
                u.FirstName,
                u.LastName,
                FullName = u.FirstName + " " + u.LastName,
                u.IsActive,
                u.CreatedAt,
                u.LastLoginAt,
                u.LastActivityAt,
                u.IsTwoFactorEnabled
            })
            .ToListAsync();

        // Get roles for each user
        var userDtos = new List<object>();
        foreach (var user in users)
        {
            var roles = await _userManager.GetRolesAsync(await _userManager.FindByIdAsync(user.Id));
            userDtos.Add(new
            {
                user.Id,
                user.UserName,
                user.Email,
                user.FirstName,
                user.LastName,
                user.FullName,
                user.IsActive,
                user.CreatedAt,
                user.LastLoginAt,
                user.LastActivityAt,
                user.IsTwoFactorEnabled,
                Roles = roles
            });
        }

        return Ok(new
        {
            TotalCount = totalCount,
            PageSize = pageSize,
            PageNumber = pageNumber,
            TotalPages = (int)Math.Ceiling((double)totalCount / pageSize),
            Users = userDtos
        });
    }

    [HttpGet("users/{id}")]
    public async Task<IActionResult> GetUser(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null)
        {
            return NotFound(new { message = "User not found" });
        }

        var roles = await _userManager.GetRolesAsync(user);
        var claims = await _userManager.GetClaimsAsync(user);

        // Get login history
        var loginHistory = await _userService.GetUserLoginHistoryAsync(id, 10);

        return Ok(new
        {
            Id = user.Id,
            UserName = user.UserName,
            Email = user.Email,
            FirstName = user.FirstName,
            LastName = user.LastName,
            FullName = user.FullName,
            IsActive = user.IsActive,
            IsTwoFactorEnabled = user.IsTwoFactorEnabled,
            CreatedAt = user.CreatedAt,
            LastLoginAt = user.LastLoginAt,
            LastActivityAt = user.LastActivityAt,
            Roles = roles,
            Claims = claims.Select(c => new { c.Type, c.Value }),
            LoginHistory = loginHistory.Select(h => new
            {
                h.LoginTime,
                h.IpAddress,
                h.UserAgent,
                h.LoginResult,
                h.Location
            })
        });
    }

    [HttpPost("users")]
    public async Task<IActionResult> CreateUser([FromBody] CreateUserRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var userExists = await _userManager.FindByEmailAsync(request.Email);
        if (userExists != null)
        {
            return Conflict(new { message = "User with this email already exists" });
        }

        var user = new ApplicationUser
        {
            UserName = request.Email,
            Email = request.Email,
            FirstName = request.FirstName,
            LastName = request.LastName,
            IsActive = request.IsActive,
            CreatedAt = DateTime.UtcNow,
            HasCompletedRegistration = true
        };

        var result = await _userManager.CreateAsync(user, request.Password);
        if (!result.Succeeded)
        {
            return BadRequest(new
            {
                message = "Failed to create user",
                errors = result.Errors.Select(e => e.Description)
            });
        }

        // Add user to roles
        if (request.Roles != null && request.Roles.Any())
        {
            foreach (var role in request.Roles)
            {
                if (await _roleService.GetRoleByNameAsync(role) != null)
                {
                    await _userManager.AddToRoleAsync(user, role);
                }
            }
        }
        else
        {
            // Add to Registered role by default
            await _userManager.AddToRoleAsync(user, "Registered");
        }

        _logger.LogInformation("Admin created new user {Email}", user.Email);

        return CreatedAtAction(nameof(GetUser), new { id = user.Id }, new
        {
            Id = user.Id,
            Email = user.Email,
            FirstName = user.FirstName,
            LastName = user.LastName,
            IsActive = user.IsActive,
            Roles = await _userManager.GetRolesAsync(user)
        });
    }

    [HttpPut("users/{id}")]
    public async Task<IActionResult> UpdateUser(string id, [FromBody] UpdateUserRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var user = await _userManager.FindByIdAsync(id);
        if (user == null)
        {
            return NotFound(new { message = "User not found" });
        }

        // Check if email is being changed and if it's already in use
        if (request.Email != user.Email)
        {
            var existingUser = await _userManager.FindByEmailAsync(request.Email);
            if (existingUser != null && existingUser.Id != id)
            {
                return Conflict(new { message = "Email is already in use" });
            }

            user.Email = request.Email;
            user.UserName = request.Email; // UserName is the same as Email in this implementation
            user.NormalizedEmail = request.Email.ToUpper();
            user.NormalizedUserName = request.Email.ToUpper();
        }

        user.FirstName = request.FirstName;
        user.LastName = request.LastName;
        user.IsActive = request.IsActive;

        var result = await _userManager.UpdateAsync(user);
        if (!result.Succeeded)
        {
            return BadRequest(new
            {
                message = "Failed to update user",
                errors = result.Errors.Select(e => e.Description)
            });
        }

        // Update password if provided
        if (!string.IsNullOrEmpty(request.Password))
        {
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var resetResult = await _userManager.ResetPasswordAsync(user, token, request.Password);

            if (!resetResult.Succeeded)
            {
                return BadRequest(new
                {
                    message = "Failed to update password",
                    errors = resetResult.Errors.Select(e => e.Description)
                });
            }
        }

        // Update roles if provided
        if (request.Roles != null)
        {
            var currentRoles = await _userManager.GetRolesAsync(user);

            // Roles to remove
            var rolesToRemove = currentRoles.Except(request.Roles).ToList();
            if (rolesToRemove.Any())
            {
                // Prevent removing Admin role if it's the last admin
                if (rolesToRemove.Contains("Admin"))
                {
                    var adminUsers = await _userManager.GetUsersInRoleAsync("Admin");
                    if (adminUsers.Count <= 1 && adminUsers.Any(u => u.Id == id))
                    {
                        return BadRequest(new { message = "Cannot remove the last admin user from Admin role" });
                    }
                }

                var removeResult = await _userManager.RemoveFromRolesAsync(user, rolesToRemove);
                if (!removeResult.Succeeded)
                {
                    return BadRequest(new
                    {
                        message = "Failed to remove roles",
                        errors = removeResult.Errors.Select(e => e.Description)
                    });
                }
            }

            // Roles to add
            var rolesToAdd = request.Roles.Except(currentRoles).ToList();
            if (rolesToAdd.Any())
            {
                var addResult = await _userManager.AddToRolesAsync(user, rolesToAdd);
                if (!addResult.Succeeded)
                {
                    return BadRequest(new
                    {
                        message = "Failed to add roles",
                        errors = addResult.Errors.Select(e => e.Description)
                    });
                }
            }
        }

        _logger.LogInformation("Admin updated user {Email}", user.Email);

        return Ok(new
        {
            Id = user.Id,
            Email = user.Email,
            FirstName = user.FirstName,
            LastName = user.LastName,
            IsActive = user.IsActive,
            Roles = await _userManager.GetRolesAsync(user)
        });
    }

    [HttpDelete("users/{id}")]
    public async Task<IActionResult> DeleteUser(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null)
        {
            return NotFound(new { message = "User not found" });
        }

        // Prevent deleting yourself
        var currentUserId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (id == currentUserId)
        {
            return BadRequest(new { message = "You cannot delete your own account" });
        }

        // Prevent deleting the last admin
        if (await _userManager.IsInRoleAsync(user, "Admin"))
        {
            var adminUsers = await _userManager.GetUsersInRoleAsync("Admin");
            if (adminUsers.Count <= 1)
            {
                return BadRequest(new { message = "Cannot delete the last admin user" });
            }
        }

        var result = await _userManager.DeleteAsync(user);
        if (!result.Succeeded)
        {
            return BadRequest(new
            {
                message = "Failed to delete user",
                errors = result.Errors.Select(e => e.Description)
            });
        }

        _logger.LogInformation("Admin deleted user {Email}", user.Email);

        return Ok(new { message = "User deleted successfully" });
    }

    [HttpPost("users/{id}/lock")]
    public async Task<IActionResult> LockUser(string id, [FromBody] LockUserRequest request)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null)
        {
            return NotFound(new { message = "User not found" });
        }

        // Prevent locking yourself
        var currentUserId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (id == currentUserId)
        {
            return BadRequest(new { message = "You cannot lock your own account" });
        }

        // Prevent locking the last admin
        if (await _userManager.IsInRoleAsync(user, "Admin"))
        {
            var adminUsers = await _userManager.GetUsersInRoleAsync("Admin");
            if (adminUsers.Count <= 1)
            {
                return BadRequest(new { message = "Cannot lock the last admin user" });
            }
        }

        var lockoutEnd = request.LockDays > 0
            ? DateTimeOffset.UtcNow.AddDays(request.LockDays)
            : (DateTimeOffset?)null;

        await _userManager.SetLockoutEndDateAsync(user, lockoutEnd);

        var action = lockoutEnd.HasValue ? "locked" : "unlocked";
        _logger.LogInformation("Admin {action} user {Email}", action, user.Email);

        return Ok(new { message = $"User {action} successfully" });
    }

    [HttpPost("users/{id}/toggle-activation")]
    public async Task<IActionResult> ToggleUserActivation(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null)
        {
            return NotFound(new { message = "User not found" });
        }

        // Prevent deactivating yourself
        var currentUserId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (id == currentUserId)
        {
            return BadRequest(new { message = "You cannot deactivate your own account" });
        }

        // Prevent deactivating the last admin
        if (!user.IsActive && await _userManager.IsInRoleAsync(user, "Admin"))
        {
            var adminUsers = await _userManager.GetUsersInRoleAsync("Admin");
            if (adminUsers.Count(u => u.IsActive) <= 1 && adminUsers.Any(u => u.Id == id))
            {
                return BadRequest(new { message = "Cannot deactivate the last admin user" });
            }
        }

        user.IsActive = !user.IsActive;
        await _userManager.UpdateAsync(user);

        var action = user.IsActive ? "activated" : "deactivated";
        _logger.LogInformation("Admin {action} user {Email}", action, user.Email);

        return Ok(new { message = $"User {action} successfully" });
    }

    [HttpGet("roles")]
    public async Task<IActionResult> GetRoles()
    {
        var roles = await _roleService.GetAllRolesAsync();
        return Ok(roles.Select(r => new
        {
            r.Id,
            r.Name,
            r.NormalizedName
        }));
    }

    [HttpGet("roles/{id}")]
    public async Task<IActionResult> GetRole(string id)
    {
        var role = await _roleService.GetRoleByIdAsync(id);
        if (role == null)
        {
            return NotFound(new { message = "Role not found" });
        }

        var claims = await _roleService.GetRoleClaimsAsync(id);
        var userCount = (await _roleService.GetUsersInRoleAsync(role.Name)).Count();

        return Ok(new
        {
            role.Id,
            role.Name,
            role.NormalizedName,
            Claims = claims.Select(c => new { c.Type, c.Value }),
            UserCount = userCount
        });
    }

    [HttpPost("roles")]
    public async Task<IActionResult> CreateRole([FromBody] CreateRoleRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var result = await _roleService.CreateRoleAsync(request.Name);
        if (!result)
        {
            return BadRequest(new { message = "Failed to create role" });
        }

        _logger.LogInformation("Admin created new role {RoleName}", request.Name);

        var role = await _roleService.GetRoleByNameAsync(request.Name);
        return CreatedAtAction(nameof(GetRole), new { id = role.Id }, new
        {
            role.Id,
            role.Name
        });
    }

    // DTOs for requests
    public class UserFilterRequest
    {
        public string SearchTerm { get; set; }
        public bool? IsActive { get; set; }
        public DateTime? FromDate { get; set; }
        public DateTime? ToDate { get; set; }
        public string Role { get; set; }
        public int? PageNumber { get; set; } = 1;
        public int? PageSize { get; set; } = 10;
        public string SortBy { get; set; } = "Email";
        public bool? SortDescending { get; set; } = false;
    }

    public class CreateUserRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [MinLength(8)]
        public string Password { get; set; }

        [Required]
        public string FirstName { get; set; }

        [Required]
        public string LastName { get; set; }

        public bool IsActive { get; set; } = true;

        public List<string> Roles { get; set; } = new List<string>();
    }

    public class UpdateUserRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        public string Password { get; set; }

        [Required]
        public string FirstName { get; set; }

        [Required]
        public string LastName { get; set; }

        public bool IsActive { get; set; } = true;

        public List<string> Roles { get; set; }
    }

    public class LockUserRequest
    {
        [Required]
        public int LockDays { get; set; } = 0;
    }

    public class CreateRoleRequest
    {
        [Required]
        public string Name { get; set; }

        public List<ClaimRequest> Claims { get; set; } = new List<ClaimRequest>();
    }

    public class UpdateRoleRequest
    {
        [Required]
        public string Name { get; set; }

        public List<ClaimRequest> Claims { get; set; } = new List<ClaimRequest>();
    }

    public class ClaimRequest
    {
        [Required]
        public string Type { get; set; }

        [Required]
        public string Value { get; set; }
    }

    public class AddUserToRoleRequest
    {
        [Required]
        public string RoleName { get; set; }
    }
}