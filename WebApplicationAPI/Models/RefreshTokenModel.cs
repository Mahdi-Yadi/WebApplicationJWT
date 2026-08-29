namespace WebApplicationAPI.Models;

/// <summary>
/// Represents a refresh token entity used for renewing short-lived access tokens.
/// </summary>
public class RefreshTokenModel
{
    /// <summary>
    /// Gets or sets the unique token value string.
    /// </summary>
    public string RefreshToken { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the username owning the token.
    /// </summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the UTC expiration date of the refresh token.
    /// </summary>
    public DateTime Expiry { get; set; }
}