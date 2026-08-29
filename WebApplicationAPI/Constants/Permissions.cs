namespace WebApplicationAPI.Constants;

/// <summary>
/// Provides application-wide permission constants used for policy-based authorization.
/// </summary>
public static class Permissions
{
    /// <summary>
    /// Permission required to view user profiles and listings.
    /// </summary>
    public const string ViewUsers = "permissions.users.view";

    /// <summary>
    /// Permission required to manage user accounts, including unlocking locked accounts.
    /// </summary>
    public const string ManageUsers = "permissions.users.manage";

    /// <summary>
    /// Permission required to delete user accounts.
    /// </summary>
    public const string DeleteUsers = "permissions.users.delete";

    /// <summary>
    /// Permission required to access administrative and analytical reports.
    /// </summary>
    public const string ViewReports = "permissions.reports.view";
}