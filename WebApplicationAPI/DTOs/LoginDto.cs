namespace WebApplicationAPI.DTOs;

/// <summary>
/// Data Transfer Object representing user authentication credentials.
/// </summary>
/// <param name="Username">The account username.</param>
/// <param name="Password">The account password.</param>
public record LoginDto(
    string Username,
    string Password
);