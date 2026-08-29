using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Unicode;
using WebApplicationAPI.Models;

namespace WebApplicationAPI.Services;

/// <summary>
/// Provides thread-safe data access operations for managing active user session persistence and concurrency constraints.
/// </summary>
public static class SessionJsonRepository
{
    private static readonly string FilePath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "Jsons", "user_sessions.json");
    private static readonly object LockObj = new();

    /// <summary>
    /// Specifies the maximum number of simultaneous active sessions allowed per user.
    /// </summary>
    public const int MaxConcurrentSessions = 2;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.Create(UnicodeRanges.All)
    };

    /// <summary>
    /// Retrieves all stored user sessions from disk.
    /// </summary>
    /// <returns>A list of <see cref="UserSessionModel"/> objects.</returns>
    public static List<UserSessionModel> GetAll()
    {
        lock (LockObj)
        {
            return GetAllInternal();
        }
    }

    /// <summary>
    /// Creates a new user session, automatically revoking older sessions if the maximum concurrency limit is reached.
    /// </summary>
    /// <param name="username">The username associated with the session.</param>
    /// <param name="refreshToken">The unique refresh token issued for the session.</param>
    /// <param name="userAgent">The client HTTP User-Agent string.</param>
    /// <param name="duration">The session lifespan duration.</param>
    /// <returns>The created <see cref="UserSessionModel"/> instance.</returns>
    public static UserSessionModel CreateSession(string username, string refreshToken, string userAgent, TimeSpan duration)
    {
        lock (LockObj)
        {
            var sessions = GetAllInternal();

            // Filter active non-revoked and non-expired sessions for the user ordered chronologically
            var activeSessions = sessions
                .Where(s => string.Equals(s.Username, username, StringComparison.OrdinalIgnoreCase)
                            && !s.IsRevoked
                            && s.ExpiresAt > DateTime.UtcNow)
                .OrderBy(s => s.CreatedAt)
                .ToList();

            // Enforce concurrency limit by revoking the oldest active sessions when capacity is exceeded
            if (activeSessions.Count >= MaxConcurrentSessions)
            {
                var overflowCount = activeSessions.Count - MaxConcurrentSessions + 1;
                var sessionsToRevoke = activeSessions.Take(overflowCount);
                foreach (var oldSession in sessionsToRevoke)
                {
                    oldSession.IsRevoked = true;
                }
            }

            var newSession = new UserSessionModel
            {
                Username = username,
                RefreshToken = refreshToken,
                UserAgent = userAgent,
                ExpiresAt = DateTime.UtcNow.Add(duration)
            };

            sessions.Add(newSession);
            SaveToFileInternal(sessions);

            return newSession;
        }
    }

    /// <summary>
    /// Retrieves a valid, non-expired, and non-revoked session by refresh token.
    /// </summary>
    /// <param name="refreshToken">The refresh token string to evaluate.</param>
    /// <returns>The valid <see cref="UserSessionModel"/> if active; otherwise, <c>null</c>.</returns>
    public static UserSessionModel? GetValidSessionByRefreshToken(string refreshToken)
    {
        lock (LockObj)
        {
            var sessions = GetAllInternal();
            var session = sessions.FirstOrDefault(s => s.RefreshToken == refreshToken);

            if (session == null || session.IsRevoked || session.ExpiresAt <= DateTime.UtcNow)
            {
                return null;
            }

            return session;
        }
    }

    /// <summary>
    /// Updates the refresh token value and extends the expiration duration for an active session.
    /// </summary>
    /// <param name="oldRefreshToken">The existing refresh token identifier.</param>
    /// <param name="newRefreshToken">The newly issued refresh token value.</param>
    /// <param name="newDuration">The lifespan duration for the renewed session.</param>
    public static void UpdateSessionToken(string oldRefreshToken, string newRefreshToken, TimeSpan newDuration)
    {
        lock (LockObj)
        {
            var sessions = GetAllInternal();
            var session = sessions.FirstOrDefault(s => s.RefreshToken == oldRefreshToken);

            if (session != null)
            {
                session.RefreshToken = newRefreshToken;
                session.LastActivity = DateTime.UtcNow;
                session.ExpiresAt = DateTime.UtcNow.Add(newDuration);
                SaveToFileInternal(sessions);
            }
        }
    }

    /// <summary>
    /// Revokes a specific session by session ID and username.
    /// </summary>
    /// <param name="sessionId">The session identifier string.</param>
    /// <param name="username">The associated username.</param>
    /// <returns><c>true</c> if the session was found and revoked; otherwise, <c>false</c>.</returns>
    public static bool RevokeSession(string sessionId, string username)
    {
        lock (LockObj)
        {
            var sessions = GetAllInternal();
            var session = sessions.FirstOrDefault(s => s.SessionId == sessionId && string.Equals(s.Username, username, StringComparison.OrdinalIgnoreCase));
            if (session == null)
            {
                return false;
            }

            session.IsRevoked = true;
            SaveToFileInternal(sessions);
            return true;
        }
    }

    /// <summary>
    /// Permanently removes a session record from the underlying JSON file.
    /// </summary>
    /// <param name="sessionId">The session identifier string to remove.</param>
    /// <param name="username">The associated username.</param>
    /// <returns><c>true</c> if a record was deleted; otherwise, <c>false</c>.</returns>
    public static bool HardDeleteSession(string sessionId, string username)
    {
        lock (LockObj)
        {
            var sessions = GetAllInternal();
            var removed = sessions.RemoveAll(s => s.SessionId == sessionId && string.Equals(s.Username, username, StringComparison.OrdinalIgnoreCase));
            if (removed > 0)
            {
                SaveToFileInternal(sessions);
                return true;
            }

            return false;
        }
    }

    /// <summary>
    /// Revokes all active sessions tied to a specific user.
    /// </summary>
    /// <param name="username">The target username.</param>
    public static void RevokeAllUserSessions(string username)
    {
        lock (LockObj)
        {
            var sessions = GetAllInternal();
            var userSessions = sessions.Where(s => string.Equals(s.Username, username, StringComparison.OrdinalIgnoreCase));
            foreach (var session in userSessions)
            {
                session.IsRevoked = true;
            }

            SaveToFileInternal(sessions);
        }
    }

    /// <summary>
    /// Internal non-locking reader method to load session data from disk.
    /// </summary>
    private static List<UserSessionModel> GetAllInternal()
    {
        if (!File.Exists(FilePath))
        {
            return new List<UserSessionModel>();
        }

        var json = File.ReadAllText(FilePath);
        if (string.IsNullOrWhiteSpace(json))
        {
            return new List<UserSessionModel>();
        }

        return JsonSerializer.Deserialize<List<UserSessionModel>>(json, JsonOptions) ?? new List<UserSessionModel>();
    }

    /// <summary>
    /// Internal non-locking writer method to serialize and write sessions to disk.
    /// </summary>
    private static void SaveToFileInternal(List<UserSessionModel> sessions)
    {
        var json = JsonSerializer.Serialize(sessions, JsonOptions);
        var directory = Path.GetDirectoryName(FilePath);

        if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
        {
            Directory.CreateDirectory(directory);
        }

        File.WriteAllText(FilePath, json);
    }
}