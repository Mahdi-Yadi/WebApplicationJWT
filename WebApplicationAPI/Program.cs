using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using Serilog.Events;
using System.Net;
using System.Threading.RateLimiting;
using WebApplicationAPI.Authorization;
using WebApplicationAPI.Models;
using WebApplicationAPI.Services;
using WebApplicationAPI.Services.ML;

var builder = WebApplication.CreateBuilder(args);

// -----------------------------------------------------------------------------
// 1. Serilog Logging Architecture Setup
// -----------------------------------------------------------------------------
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Information()
    .MinimumLevel.Override("Microsoft", LogEventLevel.Warning) // Suppress redundant framework diagnostics
    .Enrich.FromLogContext()
    .WriteTo.Console()
    .WriteTo.File(
        path: "Logs/audit-log-.txt",
        rollingInterval: RollingInterval.Day,
        retainedFileCountLimit: 30,
        outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] [{SourceContext}] {Message:lj}{NewLine}{Exception}"
    )
    .CreateLogger();

// Replace default .NET logging host provider with Serilog
builder.Host.UseSerilog();

builder.Services.AddControllers();

// -----------------------------------------------------------------------------
// 2. Security Rate Limiting Policies
// -----------------------------------------------------------------------------
builder.Services.AddRateLimiter(options =>
{
    // Custom JSON response format for HTTP 429 (Too Many Requests) rejections
    options.RejectionStatusCode = (int)HttpStatusCode.TooManyRequests;
    options.OnRejected = async (context, token) =>
    {
        context.HttpContext.Response.ContentType = "application/json; charset=utf-8";
        await context.HttpContext.Response.WriteAsync(
            "{\"message\": \"Rate limit exceeded. Please wait 1 minute before retrying.\"}",
            cancellationToken: token);
    };

    // Strict IP-partitioned rate policy for authentication endpoints (Login, Refresh)
    options.AddPolicy("StrictPolicy", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "global",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 10,                 // Maximum 10 requests allowed
                Window = TimeSpan.FromMinutes(1), // Per 1-minute window
                QueueLimit = 0                    // Instant rejection (no queuing)
            }));

    // General IP-partitioned rate policy for regular API controllers
    options.AddPolicy("GeneralPolicy", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "global",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 100,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 2
            }));
});

// -----------------------------------------------------------------------------
// 3. JWT Authentication & Public Key Validation Setup
// -----------------------------------------------------------------------------
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,

            // Validate incoming JWT tokens strictly using the RSA Public Key
            IssuerSigningKey = RsaKeyManager.PublicKey,

            ClockSkew = TimeSpan.Zero
        };
    });

// Cross-Origin Resource Sharing (CORS) Configuration
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy => policy.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod());
});

// Password Hasher Registration
builder.Services.AddScoped<IPasswordHasher<UserModel>, PasswordHasher<UserModel>>();

// Custom Dynamic Permission Authorization Framework
builder.Services.AddSingleton<IAuthorizationPolicyProvider, DynamicPermissionPolicyProvider>();
builder.Services.AddScoped<IAuthorizationHandler, PermissionAuthorizationHandler>();

// Machine Learning Infrastructure Services (ML.NET)
builder.Services.AddSingleton<IAnomalyDetectionService, AnomalyDetectionService>();
builder.Services.AddSingleton<IBotDetectionService, BotDetectionService>();
builder.Services.AddSingleton<IUserRiskScoringService, UserRiskScoringService>();

var app = builder.Build();

// -----------------------------------------------------------------------------
// 4. HTTP Request Pipeline Middleware Configuration
// -----------------------------------------------------------------------------
app.UseSerilogRequestLogging();

app.UseCors();
app.UseStaticFiles();

// Enable Rate Limiter Middleware prior to routing and controller execution
app.UseRateLimiter();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

// -----------------------------------------------------------------------------
// 5. Application Lifecycle Management & Execution
// -----------------------------------------------------------------------------
try
{
    Log.Information("WebApplication API service started successfully.");
    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "WebApplication API terminated unexpectedly during startup or runtime execution.");
}
finally
{
    Log.CloseAndFlush();
}