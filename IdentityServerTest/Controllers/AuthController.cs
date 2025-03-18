using IdentityServerTest.Models;
using IdentityServerTest.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace IdentityServerTest.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly IUserService _userService;
    private readonly IConfiguration _configuration;
    private readonly ILogger<AuthController> _logger;

    public AuthController(
        UserManager<ApplicationUser> userManager,
        RoleManager<IdentityRole> roleManager,
        IUserService userService,
        IConfiguration configuration,
        ILogger<AuthController> logger)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _userService = userService;
        _configuration = configuration;
        _logger = logger;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        // Validate the request
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        // Check if user already exists
        var userExists = await _userManager.FindByEmailAsync(request.Email);
        if (userExists != null)
        {
            return StatusCode(StatusCodes.Status409Conflict,
                new ResponseDto { Success = false, Message = "User already exists", Status = "Error" });
        }

        // Create the user
        var user = new ApplicationUser
        {
            Email = request.Email,
            UserName = request.Email,
            FirstName = request.FirstName,
            LastName = request.LastName,
            SecurityStamp = Guid.NewGuid().ToString(),
            CreatedAt = DateTime.UtcNow,
            IsActive = true,
            HasCompletedRegistration = true
        };

        var result = await _userManager.CreateAsync(user, request.Password);
        if (!result.Succeeded)
        {
            return StatusCode(StatusCodes.Status400BadRequest,
                new ResponseDto
                {
                    Success = false,
                    Message = "User creation failed",
                    Status = "Error",
                    Errors = result.Errors.Select(e => e.Description).ToList()
                });
        }

        // Add user to Registered role
        await _userManager.AddToRoleAsync(user, "Registered");

        // Add default claims
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, $"{user.FirstName} {user.LastName}"),
            new Claim(ClaimTypes.GivenName, user.FirstName),
            new Claim(ClaimTypes.Surname, user.LastName),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(ClaimTypes.Role, "Registered")
        };

        await _userManager.AddClaimsAsync(user, claims);

        _logger.LogInformation("User {Email} registered successfully", user.Email);

        return Ok(new ResponseDto
        {
            Success = true,
            Message = "User created successfully",
            Status = "Success"
        });
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        // Validate request
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        // Find the user
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user == null)
        {
            _logger.LogWarning("Login failed: User {Email} not found", request.Email);
            return Unauthorized(new ResponseDto { Success = false, Message = "Invalid credentials", Status = "Error" });
        }

        // Check if user is active
        if (!user.IsActive)
        {
            _logger.LogWarning("Login failed: User {Email} is inactive", request.Email);
            return Unauthorized(new ResponseDto { Success = false, Message = "Account is inactive", Status = "Error" });
        }

        // Check credentials
        var isPasswordValid = await _userManager.CheckPasswordAsync(user, request.Password);
        if (!isPasswordValid)
        {
            _logger.LogWarning("Login failed: Invalid password for user {Email}", request.Email);

            // Increment failed login count
            await _userManager.AccessFailedAsync(user);

            return Unauthorized(new ResponseDto { Success = false, Message = "Invalid credentials", Status = "Error" });
        }

        // Check if user is locked out
        if (await _userManager.IsLockedOutAsync(user))
        {
            _logger.LogWarning("Login failed: User {Email} is locked out", request.Email);
            return Unauthorized(new ResponseDto { Success = false, Message = "Account is locked", Status = "Error" });
        }

        // Get user roles
        var userRoles = await _userManager.GetRolesAsync(user);

        // Get user claims
        var userClaims = await _userManager.GetClaimsAsync(user);

        // Create token claims
        var authClaims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id),
            new Claim(ClaimTypes.Name, user.FullName),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Sub, user.Id)
        };

        // Add role claims
        foreach (var role in userRoles)
        {
            authClaims.Add(new Claim(ClaimTypes.Role, role));
        }

        // Add additional user claims
        foreach (var claim in userClaims)
        {
            // Skip role claims as we've already added them
            if (claim.Type != ClaimTypes.Role)
            {
                authClaims.Add(claim);
            }
        }

        // Create tokens
        var token = CreateToken(authClaims);
        var refreshToken = GenerateRefreshToken();

        // Save refresh token to user
        user.RefreshToken = refreshToken;
        user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7); // 7 days
        user.LastLoginAt = DateTime.UtcNow;
        await _userManager.UpdateAsync(user);

        // Record login for audit
        await _userService.RecordUserLoginAsync(user.Id,
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            HttpContext.Request.Headers["User-Agent"].ToString(),
            "Success");

        // Reset failed login count
        await _userManager.ResetAccessFailedCountAsync(user);

        _logger.LogInformation("User {Email} logged in successfully", user.Email);

        return Ok(new
        {
            Success = true,
            Token = new JwtSecurityTokenHandler().WriteToken(token),
            RefreshToken = refreshToken,
            Expiration = token.ValidTo,
            User = new
            {
                Id = user.Id,
                Email = user.Email,
                FirstName = user.FirstName,
                LastName = user.LastName,
                FullName = user.FullName,
                Roles = userRoles
            }
        });
    }

    [HttpPost("refresh-token")]
    public async Task<IActionResult> RefreshToken([FromBody] TokenRefreshRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var principal = GetPrincipalFromExpiredToken(request.Token);
        if (principal == null)
        {
            return BadRequest(new ResponseDto { Success = false, Message = "Invalid token", Status = "Error" });
        }

        var userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userId))
        {
            return BadRequest(new ResponseDto { Success = false, Message = "Invalid token", Status = "Error" });
        }

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null || !user.IsRefreshTokenValid(request.RefreshToken))
        {
            return BadRequest(new ResponseDto { Success = false, Message = "Invalid token or refresh token", Status = "Error" });
        }

        // Get user roles and claims
        var userRoles = await _userManager.GetRolesAsync(user);
        var userClaims = await _userManager.GetClaimsAsync(user);

        // Create new claims
        var authClaims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id),
            new Claim(ClaimTypes.Name, user.FullName),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Sub, user.Id)
        };

        // Add role claims
        foreach (var role in userRoles)
        {
            authClaims.Add(new Claim(ClaimTypes.Role, role));
        }

        // Add additional user claims
        foreach (var claim in userClaims)
        {
            if (claim.Type != ClaimTypes.Role)
            {
                authClaims.Add(claim);
            }
        }

        // Create new tokens
        var newToken = CreateToken(authClaims);
        var newRefreshToken = GenerateRefreshToken();

        // Update user
        user.RefreshToken = newRefreshToken;
        user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
        await _userManager.UpdateAsync(user);

        _logger.LogInformation("Token refreshed for user {Email}", user.Email);

        return Ok(new
        {
            Success = true,
            Token = new JwtSecurityTokenHandler().WriteToken(newToken),
            RefreshToken = newRefreshToken,
            Expiration = newToken.ValidTo
        });
    }

    [Authorize]
    [HttpPost("revoke-token")]
    public async Task<IActionResult> RevokeToken()
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userId))
        {
            return Unauthorized();
        }

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return NotFound();
        }

        user.RefreshToken = null;
        user.RefreshTokenExpiryTime = null;
        await _userManager.UpdateAsync(user);

        _logger.LogInformation("Token revoked for user {Email}", user.Email);

        return Ok(new ResponseDto { Success = true, Message = "Token revoked", Status = "Success" });
    }

    [Authorize]
    [HttpGet("me")]
    public async Task<IActionResult> GetCurrentUser()
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userId))
        {
            return Unauthorized();
        }

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return NotFound();
        }

        var roles = await _userManager.GetRolesAsync(user);
        var claims = await _userManager.GetClaimsAsync(user);

        return Ok(new
        {
            Id = user.Id,
            Email = user.Email,
            FirstName = user.FirstName,
            LastName = user.LastName,
            FullName = user.FullName,
            Roles = roles,
            Claims = claims.Select(c => new { c.Type, c.Value }),
            IsActive = user.IsActive,
            IsTwoFactorEnabled = user.IsTwoFactorEnabled,
            CreatedAt = user.CreatedAt,
            LastLoginAt = user.LastLoginAt
        });
    }

    #region Helper Methods
    private JwtSecurityToken CreateToken(IEnumerable<Claim> authClaims)
    {
        var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
        var tokenExpirationHours = Convert.ToInt32(_configuration["JWT:TokenValidityInHours"] ?? "3");

        var token = new JwtSecurityToken(
            issuer: _configuration["JWT:ValidIssuer"],
            audience: _configuration["JWT:ValidAudience"],
            expires: DateTime.UtcNow.AddHours(tokenExpirationHours),
            claims: authClaims,
            signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
        );

        return token;
    }

    private string GenerateRefreshToken()
    {
        var randomNumber = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }

    private ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
    {
        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = true,
            ValidateIssuer = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"])),
            ValidateLifetime = false, // Don't validate lifetime for expired tokens
            ValidIssuer = _configuration["JWT:ValidIssuer"],
            ValidAudience = _configuration["JWT:ValidAudience"]
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        try
        {
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var securityToken);
            if (!(securityToken is JwtSecurityToken jwtSecurityToken) ||
                !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                return null;
            }

            return principal;
        }
        catch
        {
            return null;
        }
    }
    #endregion

    // DTOs for requests and responses
    public class RegisterRequest
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
    }

    public class LoginRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        public string Password { get; set; }
    }

    public class TokenRefreshRequest
    {
        [Required]
        public string Token { get; set; }

        [Required]
        public string RefreshToken { get; set; }
    }

    public class ResponseDto
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public string Status { get; set; }
        public List<string> Errors { get; set; } = new List<string>();
    }
}