using Microsoft.ML;
using WebApplicationAPI.ML;

namespace WebApplicationAPI.Services.ML;

/// <summary>
/// Defines contracts for computing continuous user risk scores using regression models.
/// </summary>
public interface IUserRiskScoringService
{
    /// <summary>
    /// Calculates a normalized user risk score between 0.0 and 100.0 based on behavioral security indicators.
    /// </summary>
    /// <param name="activeSessions">The count of currently active sessions for the user.</param>
    /// <param name="revokedSessions">The count of historically revoked or invalidated sessions.</param>
    /// <param name="failedAttempts">The aggregate count of failed authentication attempts.</param>
    /// <param name="ipChanges">The frequency of IP address transitions associated with the user account.</param>
    /// <param name="isOffHours">Indicates whether the current activity occurs outside normal business hours.</param>
    /// <returns>A float representing the rounded risk score scaled from 0.0 to 100.0.</returns>
    float CalculateUserRiskScore(float activeSessions, float revokedSessions, float failedAttempts, float ipChanges, bool isOffHours);

    /// <summary>
    /// Retrains the FastTree regression model and saves the updated serialized model file to disk.
    /// </summary>
    void TrainAndSaveModel();
}
/// <summary>
/// Provides machine learning services for evaluating continuous user risk scores 
/// using ML.NET FastTree Regression.
/// </summary>
public class UserRiskScoringService : IUserRiskScoringService
{
    private readonly MLContext _mlContext;
    private readonly object _engineLock = new();
    private ITransformer? _model;
    private PredictionEngine<RiskInput, RiskPrediction>? _predictionEngine;

    private readonly string _modelPath = Path.Combine(AppContext.BaseDirectory, "MLModels", "user_risk_model.zip");

    /// <summary>
    /// Initializes a new instance of the <see cref="UserRiskScoringService"/> class.
    /// </summary>
    public UserRiskScoringService()
    {
        _mlContext = new MLContext(seed: 42);
        LoadOrCreateModel();
    }

    /// <summary>
    /// Loads an existing regression model from disk or initiates training if the model file does not exist.
    /// </summary>
    private void LoadOrCreateModel()
    {
        lock (_engineLock)
        {
            if (File.Exists(_modelPath))
            {
                _model = _mlContext.Model.Load(_modelPath, out _);
                _predictionEngine = _mlContext.Model.CreatePredictionEngine<RiskInput, RiskPrediction>(_model);
            }
            else
            {
                TrainAndSaveModel();
            }
        }
    }

    /// <inheritdoc />
    public void TrainAndSaveModel()
    {
        // Baseline dataset mapping user risk attributes to target numerical risk scores (0 to 100)
        var trainingData = new List<RiskInput>
        {
            // Low-risk user profiles (Risk Score: 0 - 25)
            new() { ActiveSessionsCount = 1, RevokedSessionsCount = 0, FailedAttemptsCount = 0, IpChangeFrequency = 0, IsOffHours = 0, RiskScore = 5f },
            new() { ActiveSessionsCount = 1, RevokedSessionsCount = 0, FailedAttemptsCount = 1, IpChangeFrequency = 0, IsOffHours = 0, RiskScore = 15f },
            new() { ActiveSessionsCount = 2, RevokedSessionsCount = 0, FailedAttemptsCount = 0, IpChangeFrequency = 1, IsOffHours = 0, RiskScore = 20f },

            // Medium-risk user profiles (Risk Score: 26 - 60)
            new() { ActiveSessionsCount = 3, RevokedSessionsCount = 1, FailedAttemptsCount = 2, IpChangeFrequency = 2, IsOffHours = 0, RiskScore = 45f },
            new() { ActiveSessionsCount = 2, RevokedSessionsCount = 1, FailedAttemptsCount = 3, IpChangeFrequency = 1, IsOffHours = 1, RiskScore = 55f },

            // High-risk user profiles (Risk Score: 61 - 100)
            new() { ActiveSessionsCount = 5, RevokedSessionsCount = 3, FailedAttemptsCount = 4, IpChangeFrequency = 4, IsOffHours = 1, RiskScore = 85f },
            new() { ActiveSessionsCount = 4, RevokedSessionsCount = 2, FailedAttemptsCount = 4, IpChangeFrequency = 5, IsOffHours = 1, RiskScore = 95f }
        };

        var dataView = _mlContext.Data.LoadFromEnumerable(trainingData);

        // Build feature aggregation pipeline and configure FastTree Regression trainer
        var pipeline = _mlContext.Transforms.Concatenate("Features",
                nameof(RiskInput.ActiveSessionsCount),
                nameof(RiskInput.RevokedSessionsCount),
                nameof(RiskInput.FailedAttemptsCount),
                nameof(RiskInput.IpChangeFrequency),
                nameof(RiskInput.IsOffHours))
            .Append(_mlContext.Regression.Trainers.FastTree(
                labelColumnName: "Label",
                featureColumnName: "Features"));

        // 1. Train the regression model
        _model = pipeline.Fit(dataView);

        // 2. Ensure target storage directory exists
        var directory = Path.GetDirectoryName(_modelPath);
        if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
        {
            Directory.CreateDirectory(directory);
        }

        // 3. Persist the trained model file to disk
        _mlContext.Model.Save(_model, dataView.Schema, _modelPath);

        // 4. Re-initialize prediction engine under thread synchronization lock
        lock (_engineLock)
        {
            _predictionEngine = _mlContext.Model.CreatePredictionEngine<RiskInput, RiskPrediction>(_model);
        }
    }

    /// <inheritdoc />
    public float CalculateUserRiskScore(float activeSessions, float revokedSessions, float failedAttempts, float ipChanges, bool isOffHours)
    {
        if (_predictionEngine == null)
        {
            return 0f;
        }

        var input = new RiskInput
        {
            ActiveSessionsCount = activeSessions,
            RevokedSessionsCount = revokedSessions,
            FailedAttemptsCount = failedAttempts,
            IpChangeFrequency = ipChanges,
            IsOffHours = isOffHours ? 1f : 0f
        };

        RiskPrediction prediction;

        // Synchronize access to non-thread-safe PredictionEngine instance
        lock (_engineLock)
        {
            prediction = _predictionEngine.Predict(input);
        }

        // Normalize and clamp predicted score strictly within the [0.0, 100.0] range
        float score = Math.Clamp(prediction.PredictedRiskScore, 0f, 100f);
        return (float)Math.Round(score, 1);
    }
}