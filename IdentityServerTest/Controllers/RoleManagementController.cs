using IdentityServerTest.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;

namespace IdentityServerTest.Controllers;


[Route("api/[controller]")]
[ApiController]
[Authorize(Policy = "RequireAdminRole")]
public class RoleManagementController : ControllerBase
{
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly IRoleService _roleService;
    private readonly ILogger<RoleManagementController> _logger;

    public RoleManagementController(
        RoleManager<IdentityRole> roleManager,
        IRoleService roleService,
        ILogger<RoleManagementController> logger)
    {
        _roleManager = roleManager;
        _roleService = roleService;
        _logger = logger;
    }

    [HttpGet]
    public async Task<IActionResult> GetRoles()
    {
        var roles = await _roleService.GetAllRolesAsync();

        var result = new List<object>();
        foreach (var role in roles)
        {
            var claims = await _roleService.GetRoleClaimsAsync(role.Id);
            var userCount = (await _roleService.GetUsersInRoleAsync(role.Name)).Count();

            result.Add(new
            {
                role.Id,
                role.Name,
                role.NormalizedName,
                Claims = claims.Select(c => new { c.Type, c.Value }).ToList(),
                UserCount = userCount
            });
        }

        return Ok(result);
    }

    [HttpGet("{id}")]
    public async Task<IActionResult> GetRole(string id)
    {
        var role = await _roleService.GetRoleByIdAsync(id);
        if (role == null)
        {
            return NotFound(new { message = "Role not found" });
        }

        var claims = await _roleService.GetRoleClaimsAsync(id);
        var users = await _roleService.GetUsersInRoleAsync(role.Name);

        return Ok(new
        {
            role.Id,
            role.Name,
            role.NormalizedName,
            Claims = claims.Select(c => new { c.Type, c.Value }).ToList(),
            Users = users.ToList(),
            UserCount = users.Count()
        });
    }

    [HttpPost]
    public async Task<IActionResult> CreateRole([FromBody] CreateRoleRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        // Check if role already exists
        if (await _roleManager.RoleExistsAsync(request.Name))
        {
            return Conflict(new { message = $"Role '{request.Name}' already exists" });
        }

        // Create claims list
        var claims = request.Claims?.Select(c => new Claim(c.Type, c.Value)).ToList()
            ?? new List<Claim>();

        // Always add a role claim with the role name
        claims.Add(new Claim("role", request.Name));

        // Create role
        var result = await _roleService.CreateRoleAsync(request.Name, claims);
        if (!result)
        {
            return BadRequest(new { message = "Failed to create role" });
        }

        _logger.LogInformation("Role {RoleName} created by {User}",
            request.Name, User.Identity.Name);

        // Get the created role
        var createdRole = await _roleManager.FindByNameAsync(request.Name);

        return CreatedAtAction(nameof(GetRole), new { id = createdRole.Id }, new
        {
            createdRole.Id,
            createdRole.Name,
            Claims = claims.Select(c => new { c.Type, c.Value }).ToList()
        });
    }

    [HttpPut("{id}")]
    public async Task<IActionResult> UpdateRole(string id, [FromBody] UpdateRoleRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var role = await _roleService.GetRoleByIdAsync(id);
        if (role == null)
        {
            return NotFound(new { message = "Role not found" });
        }

        // Prevent modification of built-in roles
        if (IsBuiltInRole(role.Name))
        {
            if (role.Name != request.Name)
            {
                return BadRequest(new { message = $"Cannot rename built-in role '{role.Name}'" });
            }
        }

        // Check if new name already exists for another role
        if (role.Name != request.Name)
        {
            var existingRole = await _roleManager.FindByNameAsync(request.Name);
            if (existingRole != null && existingRole.Id != id)
            {
                return Conflict(new { message = $"Role '{request.Name}' already exists" });
            }

            // Update role name
            var nameUpdateResult = await _roleService.UpdateRoleAsync(id, request.Name);
            if (!nameUpdateResult)
            {
                return BadRequest(new { message = "Failed to update role name" });
            }
        }

        // Update claims if this is not a built-in role
        if (!IsBuiltInRole(role.Name))
        {
            // Get current claims
            var currentClaims = await _roleService.GetRoleClaimsAsync(id);

            // Remove all claims except the 'role' claim with the role name
            foreach (var claim in currentClaims)
            {
                if (!(claim.Type == "role" && claim.Value == role.Name))
                {
                    await _roleService.RemoveClaimFromRoleAsync(id, claim);
                }
            }

            // Add new claims
            if (request.Claims != null)
            {
                foreach (var claimRequest in request.Claims)
                {
                    await _roleService.AddClaimToRoleAsync(id, new Claim(claimRequest.Type, claimRequest.Value));
                }
            }
        }

        _logger.LogInformation("Role {RoleId} updated by {User}", id, User.Identity.Name);

        // Get updated role
        var updatedRole = await _roleService.GetRoleByIdAsync(id);
        var updatedClaims = await _roleService.GetRoleClaimsAsync(id);

        return Ok(new
        {
            updatedRole.Id,
            updatedRole.Name,
            Claims = updatedClaims.Select(c => new { c.Type, c.Value }).ToList()
        });
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> DeleteRole(string id)
    {
        var role = await _roleService.GetRoleByIdAsync(id);
        if (role == null)
        {
            return NotFound(new { message = "Role not found" });
        }

        // Prevent deletion of built-in roles
        if (IsBuiltInRole(role.Name))
        {
            return BadRequest(new { message = $"Cannot delete built-in role '{role.Name}'" });
        }

        // Check if role is assigned to any user
        var users = await _roleService.GetUsersInRoleAsync(role.Name);
        if (users.Any())
        {
            return BadRequest(new
            {
                message = $"Cannot delete role '{role.Name}' because it is assigned to {users.Count()} users"
            });
        }

        // Delete role
        var result = await _roleService.DeleteRoleAsync(id);
        if (!result)
        {
            return BadRequest(new { message = "Failed to delete role" });
        }

        _logger.LogInformation("Role {RoleName} deleted by {User}", role.Name, User.Identity.Name);

        return Ok(new { message = $"Role '{role.Name}' deleted successfully" });
    }

    [HttpPost("{id}/claims")]
    public async Task<IActionResult> AddClaimToRole(string id, [FromBody] ClaimRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var role = await _roleService.GetRoleByIdAsync(id);
        if (role == null)
        {
            return NotFound(new { message = "Role not found" });
        }

        // Prevent modification of built-in roles
        if (IsBuiltInRole(role.Name))
        {
            return BadRequest(new { message = $"Cannot modify claims for built-in role '{role.Name}'" });
        }

        // Add claim
        var claim = new Claim(request.Type, request.Value);
        var result = await _roleService.AddClaimToRoleAsync(id, claim);
        if (!result)
        {
            return BadRequest(new { message = "Failed to add claim to role" });
        }

        _logger.LogInformation("Claim {ClaimType}:{ClaimValue} added to role {RoleName} by {User}",
            request.Type, request.Value, role.Name, User.Identity.Name);

        return Ok(new
        {
            message = $"Claim '{request.Type}:{request.Value}' added to role '{role.Name}' successfully"
        });
    }

    [HttpDelete("{id}/claims")]
    public async Task<IActionResult> RemoveClaimFromRole(string id, [FromBody] ClaimRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var role = await _roleService.GetRoleByIdAsync(id);
        if (role == null)
        {
            return NotFound(new { message = "Role not found" });
        }

        // Prevent modification of built-in roles
        if (IsBuiltInRole(role.Name))
        {
            return BadRequest(new { message = $"Cannot modify claims for built-in role '{role.Name}'" });
        }

        // Prevent removal of the 'role' claim with the role name
        if (request.Type == "role" && request.Value == role.Name)
        {
            return BadRequest(new { message = "Cannot remove the core role claim" });
        }

        // Remove claim
        var claim = new Claim(request.Type, request.Value);
        var result = await _roleService.RemoveClaimFromRoleAsync(id, claim);
        if (!result)
        {
            return BadRequest(new { message = "Failed to remove claim from role" });
        }

        _logger.LogInformation("Claim {ClaimType}:{ClaimValue} removed from role {RoleName} by {User}",
            request.Type, request.Value, role.Name, User.Identity.Name);

        return Ok(new
        {
            message = $"Claim '{request.Type}:{request.Value}' removed from role '{role.Name}' successfully"
        });
    }

    [HttpGet("{id}/users")]
    public async Task<IActionResult> GetUsersInRole(string id)
    {
        var role = await _roleService.GetRoleByIdAsync(id);
        if (role == null)
        {
            return NotFound(new { message = "Role not found" });
        }

        var users = await _roleService.GetUsersInRoleAsync(role.Name);

        return Ok(users);
    }

    // Helper method to check if a role is a built-in role
    private bool IsBuiltInRole(string roleName)
    {
        return new[] { "Admin", "Support", "Registered" }.Contains(roleName);
    }

    // DTOs
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
}