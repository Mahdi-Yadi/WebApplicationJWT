namespace WebApplicationAPI.DTOs;

/// <summary>
/// Data Transfer Object representing two-factor authentication verification parameters.
/// </summary>
/// <param name="Username">The target username attempting authentication.</param>
/// <param name="Code">The one-time passcode (OTP) submitted by the user.</param>
/// <param name="TwoFactorToken">The temporary intermediate JWT token validating the 2FA state.</param>
public record Verify2FaDto(
    string Username,
    string Code,
    string TwoFactorToken
);