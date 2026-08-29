namespace WebApplicationAPI.Models;

/// <summary>
/// Represents a user principal identity containing authorization rules, security tracking metrics, 
/// and 2FA credentials.
/// </summary>
public class UserModel
{
    /// <summary>
    /// Gets or sets the unique primary key identifier for the user.
    /// </summary>
    public int Id { get; set; }

    /// <summary>
    /// Gets or sets the unique username used for login identification.
    /// </summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the salted and hashed secret representation of the user password.
    /// </summary>
    public string PasswordHash { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the primary access control role assigned to the user (e.g., "Admin", "User").
    /// </summary>
    public string Role { get; set; } = "User";

    /// <summary>
    /// Gets or sets the list of granular permission keys granted to this user.
    /// </summary>
    public List<string> Permissions { get; set; } = new();

    /// <summary>
    /// Gets or sets the UTC timestamp when the user account was created.
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Gets or sets the counter tracking consecutive failed access attempts for lockout evaluation.
    /// </summary>
    public int AccessFailedCount { get; set; } = 0;

    /// <summary>
    /// Gets or sets the UTC timestamp indicating when an account lockout period expires.
    /// </summary>
    public DateTimeOffset? LockoutEnd { get; set; } = null;

    /// <summary>
    /// Gets or sets the active one-time passcode (OTP) generated for two-factor authentication verification.
    /// </summary>
    public string? TwoFactorCode { get; set; }

    /// <summary>
    /// Gets or sets the UTC expiration timestamp for the current active 2FA code.
    /// </summary>
    public DateTime? TwoFactorExpiry { get; set; }
}