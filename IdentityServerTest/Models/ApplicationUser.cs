// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.


using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace IdentityServerTest.Models;

public class ApplicationUser : IdentityUser
{
    [Required]
    [MaxLength(50)]
    public string FirstName { get; set; } = default!;

    [MaxLength(50)]
    public string? LastName { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? LastLoginAt { get; set; }
    public DateTime? LastActivityAt { get; set; }

    public string? PreferredLanguage { get; set; }
    public string TimeZone { get; set; } = "UTC";

    public bool IsActive { get; set; } = true;

    public bool IsTwoFactorEnabled => TwoFactorEnabled;

    public bool HasCompletedRegistration { get; set; }

    public string RefreshToken { get; set; } = default!;
    public DateTime? RefreshTokenExpiryTime { get; set; }

    public string FullName => $"{FirstName} {LastName}";

    public bool IsRefreshTokenValid(string token)
    {
        return RefreshToken == token &&
               RefreshTokenExpiryTime != null &&
               RefreshTokenExpiryTime > DateTime.UtcNow;
    }

    public void UpdateLastActivity()
    {
        LastActivityAt = DateTime.UtcNow;
    }

    public void UpdateLoginTime()
    {
        LastLoginAt = DateTime.UtcNow;
        UpdateLastActivity();
    }
}
