namespace WebApplicationJWT.Models;

/// <summary>
/// Data transfer object representing the outcome of an authentication attempt, 
/// including support for adaptive multi-factor authentication (2FA) challenges.
/// </summary>
/// <param name="RequiresTwoFactor">Indicates whether secondary 2FA verification is required.</param>
/// <param name="TwoFactorToken">Temporary security token required for the 2FA validation step.</param>
/// <param name="AccessToken">The issued JWT access token upon successful authentication.</param>
/// <param name="RefreshToken">The issued refresh token for session continuation.</param>
/// <param name="Message">Descriptive informational or status message.</param>
/// <param name="TestOtpCode">Optional development/testing OTP code for validation convenience.</param>
public record LoginResponseDto(
    bool RequiresTwoFactor,
    string? TwoFactorToken,
    string? AccessToken,
    string? RefreshToken,
    string? Message,
    string? TestOtpCode
);