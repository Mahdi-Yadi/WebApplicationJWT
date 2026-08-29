using Microsoft.ML;
using WebApplicationAPI.ML;

namespace WebApplicationAPI.Services.ML;

/// <summary>
/// Defines contracts for machine-learning-driven bot detection and automated attack evaluation.
/// </summary>
public interface IBotDetectionService
{
    /// <summary>
    /// Predicts whether incoming request traffic parameters originate from an automated bot or brute-force attack.
    /// </summary>
    /// <param name="failedAttempts">The number of prior consecutive failed authentication attempts.</param>
    /// <param name="timeDeltaSeconds">The time interval in seconds elapsed since the previous request.</param>
    /// <param name="requestRate">The total volume of requests received from the client IP within a 5-minute window.</param>
    /// <returns>A tuple containing a boolean flag indicating an attack (<c>IsAttack</c>) and the probability confidence score (<c>Confidence</c>).</returns>
    (bool IsAttack, float Confidence) PredictAttack(float failedAttempts, float timeDeltaSeconds, float requestRate);

    /// <summary>
    /// Retrains the FastTree binary classification model and persists the updated model zip file to disk.
    /// </summary>
    void TrainAndSaveModel();
}
/// <summary>
/// Provides machine learning services for identifying automated bot activity and brute-force patterns 
/// using ML.NET FastTree Binary Classification.
/// </summary>
public class BotDetectionService : IBotDetectionService
{
    private readonly MLContext _mlContext;
    private readonly object _engineLock = new();
    private ITransformer? _model;
    private PredictionEngine<BotInput, BotPrediction>? _predictionEngine;

    private readonly string _modelPath = Path.Combine(AppContext.BaseDirectory, "MLModels", "bot_detection_model.zip");

    /// <summary>
    /// Initializes a new instance of the <see cref="BotDetectionService"/> class.
    /// </summary>
    public BotDetectionService()
    {
        _mlContext = new MLContext(seed: 42);
        LoadOrCreateModel();
    }

    /// <summary>
    /// Loads an existing trained model from disk or triggers training if the model binary is absent.
    /// </summary>
    private void LoadOrCreateModel()
    {
        lock (_engineLock)
        {
            if (File.Exists(_modelPath))
            {
                _model = _mlContext.Model.Load(_modelPath, out _);
                _predictionEngine = _mlContext.Model.CreatePredictionEngine<BotInput, BotPrediction>(_model);
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
        // Baseline training dataset containing legitimate human request intervals and bot attack metrics
        var trainingData = new List<BotInput>
        {
            // Legitimate human patterns (regular intervals, low request rates)
            new() { FailedAttemptsCount = 0, TimeDeltaSeconds = 120, RequestRatePer5Min = 2, IsAttack = false },
            new() { FailedAttemptsCount = 1, TimeDeltaSeconds = 45,  RequestRatePer5Min = 3, IsAttack = false },
            new() { FailedAttemptsCount = 2, TimeDeltaSeconds = 30,  RequestRatePer5Min = 4, IsAttack = false },
            new() { FailedAttemptsCount = 0, TimeDeltaSeconds = 300, RequestRatePer5Min = 1, IsAttack = false },

            // Malicious bot / brute-force patterns (sub-second bursts or elevated request frequencies)
            new() { FailedAttemptsCount = 3, TimeDeltaSeconds = 0.5f, RequestRatePer5Min = 40, IsAttack = true },
            new() { FailedAttemptsCount = 4, TimeDeltaSeconds = 1.0f, RequestRatePer5Min = 30, IsAttack = true },
            new() { FailedAttemptsCount = 2, TimeDeltaSeconds = 0.2f, RequestRatePer5Min = 60, IsAttack = true },
            new() { FailedAttemptsCount = 1, TimeDeltaSeconds = 0.1f, RequestRatePer5Min = 50, IsAttack = true },
            new() { FailedAttemptsCount = 3, TimeDeltaSeconds = 2.0f, RequestRatePer5Min = 25, IsAttack = true }
        };

        var dataView = _mlContext.Data.LoadFromEnumerable(trainingData);

        // Build transformation and training pipeline using the FastTree Binary Classification trainer
        var pipeline = _mlContext.Transforms.Concatenate("Features",
                nameof(BotInput.FailedAttemptsCount),
                nameof(BotInput.TimeDeltaSeconds),
                nameof(BotInput.RequestRatePer5Min))
            .Append(_mlContext.BinaryClassification.Trainers.FastTree(
                labelColumnName: nameof(BotInput.IsAttack),
                featureColumnName: "Features",
                numberOfLeaves: 10,
                numberOfTrees: 20));

        // 1. Train the model
        _model = pipeline.Fit(dataView);

        // 2. Ensure target storage directory exists
        var directory = Path.GetDirectoryName(_modelPath);
        if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
        {
            Directory.CreateDirectory(directory);
        }

        // 3. Save the serialized model to disk
        _mlContext.Model.Save(_model, dataView.Schema, _modelPath);

        // 4. Re-initialize prediction engine under thread synchronization lock
        lock (_engineLock)
        {
            _predictionEngine = _mlContext.Model.CreatePredictionEngine<BotInput, BotPrediction>(_model);
        }
    }

    /// <inheritdoc />
    public (bool IsAttack, float Confidence) PredictAttack(float failedAttempts, float timeDeltaSeconds, float requestRate)
    {
        if (_predictionEngine == null)
        {
            return (false, 0f);
        }

        var input = new BotInput
        {
            FailedAttemptsCount = failedAttempts,
            TimeDeltaSeconds = timeDeltaSeconds,
            RequestRatePer5Min = requestRate
        };

        BotPrediction prediction;

        // Synchronize access to non-thread-safe PredictionEngine instance
        lock (_engineLock)
        {
            prediction = _predictionEngine.Predict(input);
        }

        return (prediction.IsBotOrAttack, prediction.Probability);
    }
}