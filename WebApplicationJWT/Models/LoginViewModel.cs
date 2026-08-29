using System.ComponentModel.DataAnnotations;

namespace WebApplicationJWT.Models;

/// <summary>
/// Represents authentication credentials submitted during user login.
/// </summary>
public class LoginViewModel
{
    /// <summary>
    /// Gets or sets the username.
    /// </summary>
    [Required(ErrorMessage = "Username is required.")]
    [Display(Name = "Username")]
    public string Username { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the account password.
    /// </summary>
    [Required(ErrorMessage = "Password is required.")]
    [DataType(DataType.Password)]
    [Display(Name = "Password")]
    public string Password { get; set; } = string.Empty;
}