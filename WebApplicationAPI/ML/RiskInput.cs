using Microsoft.ML.Data;

namespace WebApplicationAPI.ML;

/// <summary>
/// Represents user behavioral parameters evaluated to compute a continuous risk assessment score.
/// </summary>
public class RiskInput
{
    /// <summary>
    /// Gets or sets the number of currently active sessions tied to the user account.
    /// </summary>
    public float ActiveSessionsCount { get; set; }

    /// <summary>
    /// Gets or sets the total count of revoked or invalidated sessions.
    /// </summary>
    public float RevokedSessionsCount { get; set; }

    /// <summary>
    /// Gets or sets the total accumulated failed access attempts.
    /// </summary>
    public float FailedAttemptsCount { get; set; }

    /// <summary>
    /// Gets or sets the historical frequency of IP address changes associated with the user account.
    /// </summary>
    public float IpChangeFrequency { get; set; }

    /// <summary>
    /// Gets or sets a binary flag indicating off-hours activity (1.0 for off-hours/overnight, 0.0 for normal hours).
    /// </summary>
    public float IsOffHours { get; set; }

    /// <summary>
    /// Gets or sets the ground-truth target risk score (0 to 100) used during model training.
    /// </summary>
    [ColumnName("Label")]
    public float RiskScore { get; set; }
}