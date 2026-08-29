namespace WebApplicationAPI.ML;

/// <summary>
/// Represents contextual input attributes collected during a user login attempt for anomaly detection.
/// </summary>
public class LoginInput
{
    /// <summary>
    /// Gets or sets the hour of the day (0 to 23) when the login request occurred.
    /// </summary>
    public float RequestHour { get; set; }

    /// <summary>
    /// Gets or sets the day of the week (1 to 7) corresponding to the login request.
    /// </summary>
    public float DayOfWeek { get; set; }

    /// <summary>
    /// Gets or sets the character count of the submitted username.
    /// </summary>
    public float UsernameLength { get; set; }

    /// <summary>
    /// Gets or sets the character count of the submitted password.
    /// </summary>
    public float PasswordLength { get; set; }

    /// <summary>
    /// Gets or sets the client IPv4 or IPv6 address associated with the connection.
    /// </summary>
    public string IpAddress { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the HTTP User-Agent string sent by the client browser or application.
    /// </summary>
    public string UserAgent { get; set; } = string.Empty;
}