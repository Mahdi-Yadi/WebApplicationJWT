using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using WebApplicationAPI.Authorization;
using WebApplicationAPI.Constants;
using WebApplicationAPI.DTOs;
using WebApplicationAPI.Models;
using WebApplicationAPI.Services;
using WebApplicationAPI.Services.ML;

namespace WebApplicationAPI.Controllers;

/// <summary>
/// Handles authentication, registration, token generation, multi-factor authentication (2FA), 
/// and session management with integrated machine learning security checks.
/// </summary>
[ApiController]
[Route("api/[controller]")]
[EnableRateLimiting("StrictPolicy")]
public class AuthController(
    ILogger<AuthController> logger,
    IPasswordHasher<UserModel> passwordHasher,
    IAnomalyDetectionService anomalyService,
    IConfiguration configuration,
    IBotDetectionService botService,
    IUserRiskScoringService riskService) : ControllerBase
{
    /// <summary>
    /// Registers a new user account with default roles and permissions.
    /// </summary>
    /// <param name="model">The registration payload containing credentials.</param>
    /// <returns>An action result indicating success or validation failure.</returns>
    [HttpPost("register")]
    public IActionResult Register([FromBody] RegisterDto model)
    {
        if (string.IsNullOrWhiteSpace(model.Username) || string.IsNullOrWhiteSpace(model.Password))
        {
            return BadRequest("Username and password are required.");
        }

        var existingUser = UserJsonRepository.GetByUsername(model.Username);
        if (existingUser != null)
        {
            return BadRequest("This username is already registered.");
        }

        var newUser = new UserModel
        {
            Username = model.Username,
            Role = string.Equals(model.Username, "admin", StringComparison.OrdinalIgnoreCase) ? "Admin" : "User"
        };

        newUser.Permissions = newUser.Role == "Admin"
            ? new List<string> { Permissions.ViewUsers, Permissions.ManageUsers, Permissions.DeleteUsers }
            : new List<string> { Permissions.ViewUsers };

        newUser.PasswordHash = passwordHasher.HashPassword(newUser, model.Password);

        UserJsonRepository.Add(newUser);

        logger.LogInformation("SECURITY AUDIT: New user registered with username: {Username}", model.Username);

        return Ok(new { Message = "Registration completed successfully." });
    }

    /// <summary>
    /// Authenticates user credentials, evaluates security threats using machine learning services, 
    /// and issues authentication tokens or triggers multi-factor authentication (2FA).
    /// </summary>
    /// <param name="model">The login credentials payload.</param>
    /// <returns>An HTTP response containing tokens, 2FA challenge, or lockout error status.</returns>
    [HttpPost("login")]
    [AllowAnonymous]
    public IActionResult Login([FromBody] LoginDto model)
    {
        var user = UserJsonRepository.GetByUsername(model.Username);
        if (user == null)
        {
            return Unauthorized(new { Message = "Invalid username or password." });
        }

        // 1. Evaluate account lockout status
        if (user.LockoutEnd.HasValue && user.LockoutEnd.Value > DateTimeOffset.UtcNow)
        {
            var remainingMinutes = Math.Ceiling((user.LockoutEnd.Value - DateTimeOffset.UtcNow).TotalMinutes);
            return StatusCode(StatusCodes.Status423Locked, new
            {
                Message = $"Your account is locked due to multiple failed login attempts. Please try again in {remainingMinutes} minutes."
            });
        }

        // 2. Perform automated bot and brute-force attack detection using ML.NET
        float lastFailedAttempts = user.AccessFailedCount;
        float timeDelta = 1.5f;
        float requestRate5Min = 35f;

        var (isAttack, confidence) = botService.PredictAttack(lastFailedAttempts, timeDelta, requestRate5Min);

        if (isAttack)
        {
            logger.LogError("🚨 [ML.NET Bot Detection]: Automated attack detected with confidence: {Confidence:P0}", confidence);

            user.LockoutEnd = DateTimeOffset.UtcNow.AddMinutes(30);
            UserJsonRepository.Update(user);

            return StatusCode(StatusCodes.Status429TooManyRequests, new
            {
                Message = "Your request pattern resembles automated attacks. Access has been temporarily blocked."
            });
        }

        // 3. Compute user risk score using ML.NET regression model
        bool isOffHours = DateTime.Now.Hour < 6 || DateTime.Now.Hour > 22;
        float userRiskScore = riskService.CalculateUserRiskScore(
            activeSessions: 2,
            revokedSessions: 1,
            failedAttempts: user.AccessFailedCount,
            ipChanges: 1,
            isOffHours: isOffHours
        );

        logger.LogInformation("ℹ️ [ML.NET Risk Score]: Calculated risk score for user {Username}: {Score}/100", model.Username, userRiskScore);

        if (userRiskScore > 75f)
        {
            logger.LogWarning("⚠️ User {Username} exhibited a elevated risk score: {Score}", model.Username, userRiskScore);
        }

        // 4. Verify password hash correctness
        var verificationResult = passwordHasher.VerifyHashedPassword(user, user.PasswordHash, model.Password);

        if (verificationResult == PasswordVerificationResult.Failed)
        {
            user.AccessFailedCount++;
            const int maxFailedAccessAttempts = 5;
            const int lockoutDurationMinutes = 15;

            if (user.AccessFailedCount >= maxFailedAccessAttempts)
            {
                user.LockoutEnd = DateTimeOffset.UtcNow.AddMinutes(lockoutDurationMinutes);
                UserJsonRepository.Update(user);

                logger.LogWarning("SECURITY ALERT: User account {Username} locked after {Count} failed attempts.",
                    user.Username, user.AccessFailedCount);

                return StatusCode(StatusCodes.Status423Locked, new
                {
                    Message = $"Account locked due to {maxFailedAccessAttempts} failed attempts. Please try again in {lockoutDurationMinutes} minutes."
                });
            }

            UserJsonRepository.Update(user);
            var remainingAttempts = maxFailedAccessAttempts - user.AccessFailedCount;
            return Unauthorized(new
            {
                Message = $"Invalid username or password. ({remainingAttempts} attempts remaining)"
            });
        }

        // 5. Reset lockout counter upon successful credentials verification
        if (user.AccessFailedCount > 0 || user.LockoutEnd.HasValue)
        {
            user.AccessFailedCount = 0;
            user.LockoutEnd = null;
            UserJsonRepository.Update(user);
        }

        // 6. Extract connection metadata for anomaly analysis
        string ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";
        string userAgent = Request.Headers["User-Agent"].ToString();

        // 7. Evaluate anomaly status using ML.NET Randomized PCA
        bool isSuspicious = anomalyService.IsSuspiciousLogin(model.Username, model.Password, ipAddress, userAgent);

        if (isSuspicious)
        {
            logger.LogWarning("⚠️ [ML.NET Security Alert]: Suspicious login pattern for user {Username} | IP: {IP} | UserAgent: {UA}",
                model.Username, ipAddress, userAgent);

            var otpCode = new Random().Next(100000, 999999).ToString();
            user.TwoFactorCode = otpCode;
            user.TwoFactorExpiry = DateTime.UtcNow.AddMinutes(5);
            UserJsonRepository.Update(user);

            var twoFactorToken = GenerateTwoFactorTempToken(user);

            logger.LogInformation("🔐 [2FA System]: Verification code generated for user {Username}: {Code}", user.Username, otpCode);

            return Ok(new
            {
                RequiresTwoFactor = true,
                TwoFactorToken = twoFactorToken,
                Message = "Suspicious login pattern detected. Verification code sent.",
                TestOtpCode = otpCode,
                RiskScore = userRiskScore
            });
        }

        // 8. Issue standard production authentication tokens
        var accessToken = GenerateJwtToken(user);
        var refreshToken = GenerateRefreshToken();

        return Ok(new
        {
            RequiresTwoFactor = false,
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            RiskScore = userRiskScore
        });
    }

    /// <summary>
    /// Validates the provided 2FA OTP code and issues final access and refresh tokens.
    /// </summary>
    /// <param name="model">Payload containing the username and verification code.</param>
    /// <returns>Final JWT access and refresh tokens upon successful verification.</returns>
    [HttpPost("verify-2fa")]
    [AllowAnonymous]
    public IActionResult VerifyTwoFactor([FromBody] Verify2FaDto model)
    {
        var user = UserJsonRepository.GetByUsername(model.Username);
        if (user == null) return Unauthorized(new { Message = "User not found." });

        if (string.IsNullOrEmpty(user.TwoFactorCode) ||
            user.TwoFactorCode != model.Code ||
            !user.TwoFactorExpiry.HasValue ||
            user.TwoFactorExpiry.Value < DateTime.UtcNow)
        {
            return BadRequest(new { Message = "Invalid or expired 2FA verification code." });
        }

        user.TwoFactorCode = null;
        user.TwoFactorExpiry = null;
        UserJsonRepository.Update(user);

        var accessToken = GenerateJwtToken(user);
        var refreshToken = GenerateRefreshToken();

        logger.LogInformation("✅ [2FA Verified]: User {Username} successfully completed 2FA verification.", user.Username);

        return Ok(new
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken
        });
    }

    /// <summary>
    /// Generates a short-lived temporary token restricted specifically to 2FA pending state verification.
    /// </summary>
    /// <param name="user">The user entity requiring 2FA.</param>
    /// <returns>A signed JWT string intended for 2FA scope validation.</returns>
    private string GenerateTwoFactorTempToken(UserModel user)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes(configuration["Jwt:Key"] ?? "YourSuperSecretKey_NeedsToBe32BytesLong!");

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim("purpose", "2fa_pending")
            }),
            Expires = DateTime.UtcNow.AddMinutes(5),
            Issuer = configuration["Jwt:Issuer"],
            Audience = configuration["Jwt:Audience"],
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    /// <summary>
    /// Refreshes an expired access token using a valid, non-revoked refresh token (Token Rotation).
    /// </summary>
    /// <param name="model">Payload containing the current refresh token.</param>
    /// <returns>A new pair of access and refresh tokens.</returns>
    [HttpPost("refresh")]
    public IActionResult Refresh([FromBody] RefreshRequestDto model)
    {
        var session = SessionJsonRepository.GetValidSessionByRefreshToken(model.RefreshToken);
        if (session == null)
        {
            logger.LogWarning("SECURITY AUDIT: Token refresh failed. Session is invalid or revoked. IP: {IP}",
                HttpContext.Connection.RemoteIpAddress?.ToString());

            return Unauthorized("Your session is invalid or expired.");
        }

        var user = UserJsonRepository.GetByUsername(session.Username);
        if (user == null)
        {
            return Unauthorized("User associated with this session was not found.");
        }

        var newAccessToken = GenerateJwtToken(user);
        var newRefreshToken = GenerateRefreshToken();

        SessionJsonRepository.UpdateSessionToken(model.RefreshToken, newRefreshToken, TimeSpan.FromDays(7));

        logger.LogInformation("SECURITY AUDIT: Token refreshed successfully for user {Username}", session.Username);

        return Ok(new TokenResponseDto(newAccessToken, newRefreshToken));
    }

    /// <summary>
    /// Retrieves all active and historic sessions belonging to the current authenticated user.
    /// </summary>
    /// <returns>A list of session details and active state indicators.</returns>
    [Authorize]
    [HttpGet("sessions")]
    public IActionResult GetMySessions()
    {
        var username = User.Identity?.Name;
        var sessions = SessionJsonRepository.GetAll()
            .Where(s => string.Equals(s.Username, username, StringComparison.OrdinalIgnoreCase))
            .Select(s => new
            {
                s.SessionId,
                s.UserAgent,
                s.CreatedAt,
                s.LastActivity,
                s.ExpiresAt,
                s.IsRevoked,
                IsActive = !s.IsRevoked && s.ExpiresAt > DateTime.UtcNow
            });

        return Ok(sessions);
    }

    /// <summary>
    /// Revokes a specific refresh token.
    /// </summary>
    /// <param name="model">Payload containing the refresh token to invalidate.</param>
    /// <returns>An action result indicating revocation status.</returns>
    [HttpPost("revoke")]
    public IActionResult Revoke([FromBody] RevokeTokenDto model)
    {
        if (string.IsNullOrEmpty(model.RefreshToken))
        {
            return BadRequest(new { message = "Refresh token is required." });
        }

        var result = JsonTokenRepository.Remove(model.RefreshToken);

        if (!result)
        {
            return NotFound(new { message = "Refresh token not found or already revoked." });
        }

        return Ok(new { message = "Token successfully revoked." });
    }

    /// <summary>
    /// Permanently removes a session record by its identifier.
    /// </summary>
    /// <param name="sessionId">The unique identifier of the target session.</param>
    /// <returns>An action result indicating deletion status.</returns>
    [Authorize]
    [HttpDelete("sessions/{sessionId}")]
    public IActionResult DeleteSession(string sessionId)
    {
        var username = User.Identity?.Name!;
        var result = SessionJsonRepository.HardDeleteSession(sessionId, username);
        if (!result) return NotFound("Target session not found.");

        return Ok(new { Message = "Session permanently deleted." });
    }

    /// <summary>
    /// Soft-revokes an active user session by marking it expired.
    /// </summary>
    /// <param name="sessionId">The unique identifier of the target session.</param>
    /// <returns>An action result indicating revocation status.</returns>
    [Authorize]
    [HttpPost("sessions/revoke/{sessionId}")]
    public IActionResult RevokeSession(string sessionId)
    {
        var username = User.Identity?.Name!;
        var result = SessionJsonRepository.RevokeSession(sessionId, username);
        if (!result) return NotFound("Target session not found.");

        logger.LogInformation("SECURITY AUDIT: User {Username} revoked session {SessionId}.", username, sessionId);

        return Ok(new { Message = "Session deactivated successfully." });
    }

    /// <summary>
    /// Revokes all active sessions for the current authenticated user across all devices.
    /// </summary>
    /// <returns>An action result confirming global session revocation.</returns>
    [Authorize]
    [HttpPost("sessions/revoke-all")]
    public IActionResult RevokeAllSessions()
    {
        var username = User.Identity?.Name!;
        SessionJsonRepository.RevokeAllUserSessions(username);

        logger.LogWarning("SECURITY AUDIT: User {Username} revoked all active sessions.", username);

        return Ok(new { Message = "All active sessions have been successfully revoked." });
    }

    /// <summary>
    /// Test endpoint confirming secure authorization access.
    /// </summary>
    /// <returns>A welcome message with a timestamp.</returns>
    [HttpGet("protected-data")]
    [Authorize]
    public IActionResult GetProtectedData()
    {
        var username = User.Identity?.Name;
        return Ok(new
        {
            message = $"Hello {username}! You have accessed the protected resource with a valid token.",
            timestamp = DateTime.UtcNow
        });
    }

    /// <summary>
    /// Unlocks a locked user account and resets failed access counters.
    /// </summary>
    /// <param name="username">The username of the account to unlock.</param>
    /// <returns>An action result confirming account unlock.</returns>
    [HttpPost("{username}/unlock")]
    [HasPermission(Permissions.ManageUsers)]
    public IActionResult UnlockUser(string username)
    {
        var user = UserJsonRepository.GetByUsername(username);
        if (user == null)
            return NotFound(new { Message = "Target user not found." });

        user.AccessFailedCount = 0;
        user.LockoutEnd = null;
        UserJsonRepository.Update(user);

        logger.LogInformation("SECURITY AUDIT: User account {Username} was unlocked by administrator {Admin}.",
            username, User.Identity?.Name);

        return Ok(new { Message = $"User account '{username}' has been unlocked successfully." });
    }

    /// <summary>
    /// Generates a signed JWT Access Token containing user claims, roles, and permissions.
    /// </summary>
    /// <param name="user">The target user entity.</param>
    /// <returns>A serialized JWT string.</returns>
    private string GenerateJwtToken(UserModel user)
    {
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Username),
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.Role, user.Role)
        };

        foreach (var permission in user.Permissions)
        {
            claims.Add(new Claim("permission", permission));
        }

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(15),
            SigningCredentials = new SigningCredentials(
                RsaKeyManager.PrivateKey,
                SecurityAlgorithms.RsaSha256
            )
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    /// <summary>
    /// Generates a cryptographically secure random string for use as a refresh token.
    /// </summary>
    /// <returns>A base64 encoded string.</returns>
    private static string GenerateRefreshToken()
    {
        var randomNumber = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }
}

/// <summary>
/// Data Transfer Object representing user login credentials.
/// </summary>
public record LoginDto(string Username, string Password);

/// <summary>
/// Data Transfer Object representing a token refresh request.
/// </summary>
public record RefreshRequestDto(string RefreshToken);

/// <summary>
/// Data Transfer Object representing a token revocation request.
/// </summary>
public record RevokeTokenDto(string RefreshToken);

/// <summary>
/// Data Transfer Object containing a generated access token and refresh token pair.
/// </summary>
public record TokenResponseDto(string AccessToken, string RefreshToken);