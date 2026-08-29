using Microsoft.AspNetCore.Authorization;

namespace WebApplicationAPI.Authorization;

/// <summary>
/// Declarative attribute applied to controllers or actions to enforce permission-based authorization.
/// Automatically sets the policy name to the specified permission key.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
public class HasPermissionAttribute : AuthorizeAttribute
{
    /// <summary>
    /// Initializes a new instance of the <see cref="HasPermissionAttribute"/> class with the target permission.
    /// </summary>
    /// <param name="permission">The permission required to access the decorated resource.</param>
    public HasPermissionAttribute(string permission) : base(policy: permission)
    {
    }
}