namespace WebApplicationAPI.DTOs;

/// <summary>
/// Data Transfer Object representing user registration parameters.
/// </summary>
/// <param name="Username">The desired username for the new account.</param>
/// <param name="Password">The plain-text password to be hashed upon registration.</param>
public record RegisterDto(
    string Username,
    string Password
);