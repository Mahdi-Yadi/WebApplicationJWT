namespace WebApplicationJWT.Models;

/// <summary>
/// Represents editable parameters for updating user account properties and permissions.
/// </summary>
public class UpdateUserViewModel
{
    /// <summary>
    /// Gets or sets the username identifying the user to update.
    /// </summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the updated security role assignment, if modified.
    /// </summary>
    public string? Role { get; set; }

    /// <summary>
    /// Gets or sets the new password string, if a reset is requested.
    /// </summary>
    public string? NewPassword { get; set; }

    /// <summary>
    /// Gets or sets the updated collection of permission identifiers assigned to the user.
    /// </summary>
    public List<string> SelectedPermissions { get; set; } = new();
}