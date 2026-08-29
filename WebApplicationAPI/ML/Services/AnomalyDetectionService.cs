using Microsoft.ML;
using WebApplicationAPI.ML;

namespace WebApplicationAPI.Services.ML;

/// <summary>
/// Defines contracts for automated machine-learning-based login anomaly detection.
/// </summary>
public interface IAnomalyDetectionService
{
    /// <summary>
    /// Evaluates whether incoming authentication attempt attributes indicate suspicious behavior.
    /// </summary>
    /// <param name="username">The username submitted during login.</param>
    /// <param name="password">The password submitted during login.</param>
    /// <param name="ipAddress">The client IP address associated with the request.</param>
    /// <param name="userAgent">The HTTP User-Agent header string of the client browser/device.</param>
    /// <returns><c>true</c> if the request is flagged as an anomaly; otherwise, <c>false</c>.</returns>
    bool IsSuspiciousLogin(string username, string password, string ipAddress, string userAgent);

    /// <summary>
    /// Retrains the Randomized PCA anomaly detection model and persists the updated binary model to disk.
    /// </summary>
    void TrainAndSaveModel();
}
/// <summary>
/// Provides machine learning services for detecting anomalous user login patterns using ML.NET Randomized PCA.
/// </summary>
public class AnomalyDetectionService : IAnomalyDetectionService
{
    private readonly MLContext _mlContext;
    private readonly object _engineLock = new();
    private ITransformer? _model;
    private PredictionEngine<LoginInput, AnomalyPrediction>? _predictionEngine;

    private readonly string _modelPath = Path.Combine(AppContext.BaseDirectory, "MLModels", "anomaly_model.zip");

    /// <summary>
    /// Initializes a new instance of the <see cref="AnomalyDetectionService"/> class.
    /// </summary>
    public AnomalyDetectionService()
    {
        _mlContext = new MLContext(seed: 42);
        LoadOrCreateModel();
    }

    /// <summary>
    /// Loads an existing trained model from disk or triggers training if the model file is absent.
    /// </summary>
    private void LoadOrCreateModel()
    {
        lock (_engineLock)
        {
            if (File.Exists(_modelPath))
            {
                _model = _mlContext.Model.Load(_modelPath, out _);
                _predictionEngine = _mlContext.Model.CreatePredictionEngine<LoginInput, AnomalyPrediction>(_model);
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
        // Sample baseline dataset representing regular, benign authentication patterns
        var sampleData = new List<LoginInput>
        {
            new() { RequestHour = 8, DayOfWeek = 1, UsernameLength = 6, PasswordLength = 10, IpAddress = "192.168.1.50", UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" },
            new() { RequestHour = 9, DayOfWeek = 1, UsernameLength = 5, PasswordLength = 8, IpAddress = "192.168.1.50", UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" },
            new() { RequestHour = 10, DayOfWeek = 2, UsernameLength = 7, PasswordLength = 12, IpAddress = "192.168.1.51", UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)" },
            new() { RequestHour = 14, DayOfWeek = 3, UsernameLength = 6, PasswordLength = 9, IpAddress = "192.168.1.50", UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" },
            new() { RequestHour = 16, DayOfWeek = 4, UsernameLength = 8, PasswordLength = 11, IpAddress = "10.0.0.12", UserAgent = "Mozilla/5.0 (X11; Linux x86_64)" },
            new() { RequestHour = 11, DayOfWeek = 5, UsernameLength = 5, PasswordLength = 10, IpAddress = "192.168.1.50", UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" }
        };

        var dataView = _mlContext.Data.LoadFromEnumerable(sampleData);

        // Define transformation pipeline for categorical IP encoding, text featurization, and PCA anomaly detection
        var pipeline = _mlContext.Transforms.Categorical.OneHotHashEncoding("IpEncoded", nameof(LoginInput.IpAddress))
            .Append(_mlContext.Transforms.Text.FeaturizeText("UserAgentFeaturized", nameof(LoginInput.UserAgent)))
            .Append(_mlContext.Transforms.Concatenate("Features",
                nameof(LoginInput.RequestHour),
                nameof(LoginInput.DayOfWeek),
                nameof(LoginInput.UsernameLength),
                nameof(LoginInput.PasswordLength),
                "IpEncoded",
                "UserAgentFeaturized"))
            .Append(_mlContext.AnomalyDetection.Trainers.RandomizedPca(
                featureColumnName: "Features",
                rank: 2));

        // 1. Train the machine learning pipeline model
        _model = pipeline.Fit(dataView);

        // 2. Ensure destination directory path exists
        var directory = Path.GetDirectoryName(_modelPath);
        if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
        {
            Directory.CreateDirectory(directory);
        }

        // 3. Persist the trained model schema to disk
        _mlContext.Model.Save(_model, dataView.Schema, _modelPath);

        // 4. Re-initialize the thread-safe prediction engine reference
        lock (_engineLock)
        {
            _predictionEngine = _mlContext.Model.CreatePredictionEngine<LoginInput, AnomalyPrediction>(_model);
        }
    }

    /// <inheritdoc />
    public bool IsSuspiciousLogin(string username, string password, string ipAddress, string userAgent)
    {
        if (_predictionEngine == null)
        {
            return false;
        }

        var utcNow = DateTime.UtcNow;

        var input = new LoginInput
        {
            RequestHour = utcNow.Hour,
            DayOfWeek = (int)utcNow.DayOfWeek + 1,
            UsernameLength = username?.Length ?? 0,
            PasswordLength = password?.Length ?? 0,
            IpAddress = string.IsNullOrWhiteSpace(ipAddress) ? "127.0.0.1" : ipAddress,
            UserAgent = string.IsNullOrWhiteSpace(userAgent) ? "Unknown" : userAgent
        };

        AnomalyPrediction prediction;

        // Synchronize access to non-thread-safe PredictionEngine instance
        lock (_engineLock)
        {
            prediction = _predictionEngine.Predict(input);
        }

        if (prediction?.Prediction != null && prediction.Prediction.Length > 0)
        {
            // Index 0 == 1.0 indicates that the input pattern has been flagged as an anomaly
            return prediction.Prediction[0] == 1.0;
        }

        return false;
    }
}