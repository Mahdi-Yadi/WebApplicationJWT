using System.ComponentModel.DataAnnotations;

namespace WebApplicationJWT.Models;

/// <summary>
/// Data transfer model for capturing and validating two-factor authentication (2FA) inputs.
/// </summary>
public class Verify2FaViewModel
{
    /// <summary>
    /// Gets or sets the target username undergoing verification.
    /// </summary>
    [Required]
    public string Username { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the 6-digit OTP verification code.
    /// </summary>
    [Required(ErrorMessage = "Please enter the 6-digit verification code.")]
    [StringLength(6, MinimumLength = 6, ErrorMessage = "The verification code must be exactly 6 digits.")]
    [Display(Name = "6-Digit Verification Code")]
    public string Code { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the temporary session security token associated with the 2FA challenge.
    /// </summary>
    [Required]
    public string TwoFactorToken { get; set; } = string.Empty;
}