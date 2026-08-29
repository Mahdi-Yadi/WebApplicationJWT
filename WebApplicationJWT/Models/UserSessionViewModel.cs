namespace WebApplicationJWT.Models;

/// <summary>
/// Represents metadata regarding an active user session for monitoring and management interfaces.
/// </summary>
public class UserSessionViewModel
{
    /// <summary>
    /// Gets or sets the unique session identifier string.
    /// </summary>
    public string SessionId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the client user-agent header information.
    /// </summary>
    public string UserAgent { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the session creation timestamp.
    /// </summary>
    public DateTime CreatedAt { get; set; }

    /// <summary>
    /// Gets or sets the timestamp of the last recorded session activity.
    /// </summary>
    public DateTime LastActivity { get; set; }

    /// <summary>
    /// Gets or sets the session expiration timestamp.
    /// </summary>
    public DateTime ExpiresAt { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the session has been revoked.
    /// </summary>
    public bool IsRevoked { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the session is currently active and valid.
    /// </summary>
    public bool IsActive { get; set; }
}