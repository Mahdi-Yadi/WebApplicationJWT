using Microsoft.ML.Data;

namespace WebApplicationAPI.ML;

/// <summary>
/// Represents the estimated risk score output produced by the regression model.
/// </summary>
public class RiskPrediction
{
    /// <summary>
    /// Gets or sets the predicted numerical risk score value (typically scaled from 0 to 100).
    /// </summary>
    [ColumnName("Score")]
    public float PredictedRiskScore { get; set; }
}