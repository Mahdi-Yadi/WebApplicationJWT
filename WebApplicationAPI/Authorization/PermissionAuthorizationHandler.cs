using Microsoft.AspNetCore.Authorization;

namespace WebApplicationAPI.Authorization;

/// <summary>
/// Handles authorization checks by verifying whether the current authenticated user 
/// possesses the required permission claim.
/// </summary>
public class PermissionAuthorizationHandler : AuthorizationHandler<PermissionRequirement>
{
    /// <summary>
    /// Evaluates the authorization requirement against the claims present in the authenticated user's principal.
    /// </summary>
    /// <param name="context">The authorization context containing information about the user and resource.</param>
    /// <param name="requirement">The permission requirement being evaluated.</param>
    /// <returns>A completed task representing the asynchronous operation.</returns>
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        PermissionRequirement requirement)
    {
        if (context.User?.Identity == null || !context.User.Identity.IsAuthenticated)
        {
            return Task.CompletedTask;
        }

        // Verify if the user contains a matching 'permission' claim
        var hasPermission = context.User.HasClaim(c =>
            string.Equals(c.Type, "permission", StringComparison.OrdinalIgnoreCase) &&
            string.Equals(c.Value, requirement.Permission, StringComparison.OrdinalIgnoreCase));

        if (hasPermission)
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}