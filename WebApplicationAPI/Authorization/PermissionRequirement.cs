using Microsoft.AspNetCore.Authorization;

namespace WebApplicationAPI.Authorization;

/// <summary>
/// Represents a custom authorization requirement that encapsulates a specific permission key.
/// </summary>
public class PermissionRequirement : IAuthorizationRequirement
{
    /// <summary>
    /// Gets the permission name required to satisfy the authorization policy.
    /// </summary>
    public string Permission { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="PermissionRequirement"/> class.
    /// </summary>
    /// <param name="permission">The permission key to be evaluated.</param>
    public PermissionRequirement(string permission)
    {
        Permission = permission ?? throw new ArgumentNullException(nameof(permission));
    }
}