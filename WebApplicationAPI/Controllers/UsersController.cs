using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using WebApplicationAPI.Authorization;
using WebApplicationAPI.Constants;
using WebApplicationAPI.Models;
using WebApplicationAPI.Services;

namespace WebApplicationAPI.Controllers;

/// <summary>
/// Provides administrative endpoints for user management, role/permission assignment,
/// account deletion, and session inspection.
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class UsersController : ControllerBase
{
    private readonly ILogger<UsersController> _logger;
    private readonly IPasswordHasher<UserModel> _passwordHasher;

    /// <summary>
    /// Initializes a new instance of the <see cref="UsersController"/> class.
    /// </summary>
    /// <param name="logger">The logger instance for tracking operational and audit logs.</param>
    /// <param name="passwordHasher">The password hashing service for secure credential updates.</param>
    public UsersController(ILogger<UsersController> logger, IPasswordHasher<UserModel> passwordHasher)
    {
        _logger = logger;
        _passwordHasher = passwordHasher;
    }

    /// <summary>
    /// Retrieves a list of all registered users without exposing sensitive credentials.
    /// </summary>
    /// <returns>An <see cref="IActionResult"/> containing sanitized user profiles.</returns>
    [HttpGet]
    [HasPermission(Permissions.ViewUsers)]
    public IActionResult GetUsers()
    {
        var users = UserJsonRepository.GetAll().Select(u => new
        {
            u.Id,
            u.Username,
            u.Role,
            u.Permissions,
            u.CreatedAt
        });

        return Ok(users);
    }

    /// <summary>
    /// Retrieves detailed user information by username.
    /// </summary>
    /// <param name="username">The unique username of the requested profile.</param>
    /// <returns>An <see cref="IActionResult"/> containing the user details or a not-found status.</returns>
    [HttpGet("{username}")]
    [HasPermission(Permissions.ViewUsers)]
    public IActionResult GetUserByUsername(string username)
    {
        var user = UserJsonRepository.GetByUsername(username);
        if (user == null)
            return NotFound(new { Message = "Target user not found." });

        return Ok(new
        {
            user.Id,
            user.Username,
            user.Role,
            user.Permissions,
            user.CreatedAt
        });
    }

    /// <summary>
    /// Updates role, permissions, or password for a target user account.
    /// </summary>
    /// <param name="username">The username of the account to be updated.</param>
    /// <param name="dto">The data transfer object containing update values.</param>
    /// <returns>An <see cref="IActionResult"/> confirming the operation result.</returns>
    [HttpPut("{username}")]
    [HasPermission(Permissions.ManageUsers)]
    public IActionResult UpdateUser(string username, [FromBody] UpdateUserDto dto)
    {
        var user = UserJsonRepository.GetByUsername(username);
        if (user == null)
            return NotFound(new { Message = "Target user not found." });

        // Update role if explicitly provided
        if (!string.IsNullOrWhiteSpace(dto.Role))
        {
            user.Role = dto.Role;
        }

        // Update permissions list if provided
        if (dto.Permissions != null)
        {
            user.Permissions = dto.Permissions.Where(p => !string.IsNullOrWhiteSpace(p)).ToList();
        }

        // Update password hash if a new password is set
        if (!string.IsNullOrWhiteSpace(dto.NewPassword))
        {
            user.PasswordHash = _passwordHasher.HashPassword(user, dto.NewPassword);
        }

        UserJsonRepository.Update(user);

        _logger.LogInformation("SECURITY AUDIT: User profile for {Username} updated by administrator {Admin}.",
            username, User.Identity?.Name ?? "System");

        return Ok(new { Message = "User information updated successfully." });
    }

    /// <summary>
    /// Deletes a user account and revokes all active sessions belonging to that user.
    /// Prevents administrators from deleting their own active accounts.
    /// </summary>
    /// <param name="username">The username of the account to be deleted.</param>
    /// <returns>An <see cref="IActionResult"/> confirming deletion or error status.</returns>
    [HttpDelete("{username}")]
    [HasPermission(Permissions.DeleteUsers)]
    public IActionResult DeleteUser(string username)
    {
        var user = UserJsonRepository.GetByUsername(username);
        if (user == null)
            return NotFound(new { Message = "Target user not found." });

        var currentAdminUsername = User.Identity?.Name;

        // Prevent self-deletion of currently authenticated account
        if (!string.IsNullOrEmpty(currentAdminUsername) &&
            string.Equals(user.Username, currentAdminUsername, StringComparison.OrdinalIgnoreCase))
        {
            return BadRequest(new { Message = "You cannot delete your own active account." });
        }

        UserJsonRepository.Remove(username);
        SessionJsonRepository.RevokeAllUserSessions(username);

        _logger.LogWarning("SECURITY AUDIT: User {Username} was deleted by administrator {Admin}.",
            username, currentAdminUsername ?? "System");

        return Ok(new { Message = $"User '{username}' and all associated active sessions were removed successfully." });
    }

    /// <summary>
    /// Retrieves all active and inactive sessions assigned to a specific user.
    /// </summary>
    /// <param name="username">The username whose sessions are being inspected.</param>
    /// <returns>An <see cref="IActionResult"/> containing session state records.</returns>
    [HttpGet("{username}/sessions")]
    [HasPermission(Permissions.ManageUsers)]
    public IActionResult GetUserSessions(string username)
    {
        var user = UserJsonRepository.GetByUsername(username);
        if (user == null)
            return NotFound(new { Message = "Target user not found." });

        var sessions = SessionJsonRepository.GetAll()
            .Where(s => string.Equals(s.Username, username, StringComparison.OrdinalIgnoreCase))
            .Select(s => new
            {
                s.SessionId,
                s.UserAgent,
                s.CreatedAt,
                s.LastActivity,
                s.ExpiresAt,
                s.IsRevoked,
                IsActive = !s.IsRevoked && s.ExpiresAt > DateTime.UtcNow
            });

        return Ok(sessions);
    }
}

/// <summary>
/// Data Transfer Object representing editable fields for user profile management.
/// </summary>
/// <param name="Role">Optional new role designation for the user.</param>
/// <param name="Permissions">Optional updated list of granted permission strings.</param>
/// <param name="NewPassword">Optional new plain-text password to hash and set.</param>
public record UpdateUserDto(
    string? Role,
    List<string>? Permissions,
    string? NewPassword
);