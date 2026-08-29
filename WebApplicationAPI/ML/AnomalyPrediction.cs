using Microsoft.ML.Data;

namespace WebApplicationAPI.ML;

/// <summary>
/// Represents the output prediction produced by the Randomized PCA anomaly detection model.
/// </summary>
public class AnomalyPrediction
{
    /// <summary>
    /// Gets or sets a 2-element vector containing the anomaly evaluation metrics.
    /// Index 0: Binary anomaly indicator (1 for anomalous/suspicious, 0 for normal).
    /// Index 1: The calculated raw anomaly score measuring distance from the centroid.
    /// </summary>
    [VectorType(2)]
    public double[] Prediction { get; set; } = new double[2];
}