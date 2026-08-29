namespace WebApplicationAPI.Models;

/// <summary>
/// Represents an active or historical user authentication session linked to a refresh token.
/// </summary>
public class UserSessionModel
{
    /// <summary>
    /// Gets or sets the unique session identifier. Defaults to a 32-character hexadecimal string.
    /// </summary>
    public string SessionId { get; set; } = Guid.NewGuid().ToString("N");

    /// <summary>
    /// Gets or sets the username associated with this session.
    /// </summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the cryptographically secure refresh token tied to the active session.
    /// </summary>
    public string RefreshToken { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the User-Agent client browser header string recorded at session initiation.
    /// </summary>
    public string UserAgent { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the UTC timestamp when the session was initialized.
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Gets or sets the UTC timestamp of the most recent activity recorded on this session.
    /// </summary>
    public DateTime LastActivity { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Gets or sets the UTC expiration timestamp after which the session becomes invalid.
    /// </summary>
    public DateTime ExpiresAt { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the session has been explicitly revoked or invalidated.
    /// </summary>
    public bool IsRevoked { get; set; } = false;
}