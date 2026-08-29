namespace WebApplicationAPI.ML;

/// <summary>
/// Represents the feature input schema for evaluating automated bot and brute-force attack patterns.
/// </summary>
public class BotInput
{
    /// <summary>
    /// Gets or sets the count of recent failed authentication attempts.
    /// </summary>
    public float FailedAttemptsCount { get; set; }

    /// <summary>
    /// Gets or sets the elapsed time delta in seconds between the current and prior request.
    /// </summary>
    public float TimeDeltaSeconds { get; set; }

    /// <summary>
    /// Gets or sets the aggregate request frequency originating from the client IP within a 5-minute window.
    /// </summary>
    public float RequestRatePer5Min { get; set; }

    /// <summary>
    /// Gets or sets the ground-truth target label used exclusively during model training.
    /// True indicates a verified bot or malicious attack; False indicates legitimate human traffic.
    /// </summary>
    public bool IsAttack { get; set; }
}