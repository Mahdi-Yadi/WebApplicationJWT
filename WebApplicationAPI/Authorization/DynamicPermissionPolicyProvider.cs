using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace WebApplicationAPI.Authorization;

/// <summary>
/// Custom authorization policy provider that dynamically generates policy definitions 
/// on-demand based on permission names requested by attributes.
/// </summary>
public class DynamicPermissionPolicyProvider : DefaultAuthorizationPolicyProvider
{
    /// <summary>
    /// Initializes a new instance of the <see cref="DynamicPermissionPolicyProvider"/> class.
    /// </summary>
    /// <param name="options">Configuration options for authorization.</param>
    public DynamicPermissionPolicyProvider(IOptions<AuthorizationOptions> options) : base(options)
    {
    }

    /// <summary>
    /// Retrieves an existing static authorization policy or dynamically generates a new policy 
    /// containing a <see cref="PermissionRequirement"/> for the specified policy name.
    /// </summary>
    /// <param name="policyName">The name of the requested policy (permission key).</param>
    /// <returns>An <see cref="AuthorizationPolicy"/> instance if constructed or found; otherwise, null.</returns>
    public override async Task<AuthorizationPolicy?> GetPolicyAsync(string policyName)
    {
        // Check if a pre-registered policy matches the provided policy name
        var policy = await base.GetPolicyAsync(policyName);
        if (policy != null)
        {
            return policy;
        }

        // Dynamically build a policy requiring the specified permission
        return new AuthorizationPolicyBuilder()
            .AddRequirements(new PermissionRequirement(policyName))
            .Build();
    }
}