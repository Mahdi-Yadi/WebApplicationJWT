namespace WebApplicationJWT.Models;

/// <summary>
/// Represents user account details and assigned authorization metadata for view presentation.
/// </summary>
public class UserViewModel
{
    /// <summary>
    /// Gets or sets the unique user identifier.
    /// </summary>
    public int Id { get; set; }

    /// <summary>
    /// Gets or sets the username.
    /// </summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the primary security role assigned to the user.
    /// </summary>
    public string Role { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the collection of specific permissions granted to the user.
    /// </summary>
    public List<string> Permissions { get; set; } = new();

    /// <summary>
    /// Gets or sets the account creation timestamp in UTC.
    /// </summary>
    public DateTime CreatedAt { get; set; }
}