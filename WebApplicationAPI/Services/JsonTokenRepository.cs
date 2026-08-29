using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Unicode;
using WebApplicationAPI.Models;

namespace WebApplicationAPI.Services;

/// <summary>
/// Provides thread-safe data access operations for managing active refresh tokens in JSON file storage.
/// </summary>
public static class JsonTokenRepository
{
    private static readonly string FilePath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "Jsons", "refresh_tokens.json");
    private static readonly object LockObj = new();

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.Create(UnicodeRanges.All)
    };

    /// <summary>
    /// Retrieves all refresh token entries from disk.
    /// </summary>
    /// <returns>A list of <see cref="RefreshTokenModel"/> objects.</returns>
    public static List<RefreshTokenModel> GetAll()
    {
        lock (LockObj)
        {
            return GetAllInternal();
        }
    }

    /// <summary>
    /// Saves a new refresh token entry with an assigned expiration date.
    /// </summary>
    /// <param name="refreshToken">The unique refresh token string.</param>
    /// <param name="username">The username tied to the refresh token.</param>
    /// <param name="expiry">The UTC expiration date and time.</param>
    public static void Save(string refreshToken, string username, DateTime expiry)
    {
        lock (LockObj)
        {
            var tokens = GetAllInternal();

            tokens.Add(new RefreshTokenModel
            {
                RefreshToken = refreshToken,
                Username = username,
                Expiry = expiry
            });

            SaveToFileInternal(tokens);
        }
    }

    /// <summary>
    /// Retrieves a specific refresh token record by token value.
    /// </summary>
    /// <param name="refreshToken">The target refresh token string.</param>
    /// <returns>The matching <see cref="RefreshTokenModel"/> if found; otherwise, <c>null</c>.</returns>
    public static RefreshTokenModel? Get(string refreshToken)
    {
        lock (LockObj)
        {
            var tokens = GetAllInternal();
            return tokens.FirstOrDefault(t => t.RefreshToken == refreshToken);
        }
    }

    /// <summary>
    /// Deletes a specific refresh token from storage.
    /// </summary>
    /// <param name="refreshToken">The refresh token string to remove.</param>
    /// <returns><c>true</c> if the token was found and deleted; otherwise, <c>false</c>.</returns>
    public static bool Remove(string refreshToken)
    {
        lock (LockObj)
        {
            var tokens = GetAllInternal();
            var itemToRemove = tokens.FirstOrDefault(t => t.RefreshToken == refreshToken);

            if (itemToRemove == null)
            {
                return false;
            }

            tokens.Remove(itemToRemove);
            SaveToFileInternal(tokens);
            return true;
        }
    }

    /// <summary>
    /// Revokes and deletes all refresh tokens associated with a specified user.
    /// </summary>
    /// <param name="username">The target username.</param>
    public static void RemoveAllByUsername(string username)
    {
        lock (LockObj)
        {
            var tokens = GetAllInternal();

            tokens.RemoveAll(t => string.Equals(t.Username, username, StringComparison.OrdinalIgnoreCase));

            SaveToFileInternal(tokens);
        }
    }

    /// <summary>
    /// Internal non-locking helper to read token data from disk.
    /// </summary>
    private static List<RefreshTokenModel> GetAllInternal()
    {
        if (!File.Exists(FilePath))
        {
            return new List<RefreshTokenModel>();
        }

        var json = File.ReadAllText(FilePath);
        if (string.IsNullOrWhiteSpace(json))
        {
            return new List<RefreshTokenModel>();
        }

        return JsonSerializer.Deserialize<List<RefreshTokenModel>>(json, JsonOptions) ?? new List<RefreshTokenModel>();
    }

    /// <summary>
    /// Internal non-locking helper to serialize and write token data to disk.
    /// </summary>
    private static void SaveToFileInternal(List<RefreshTokenModel> tokens)
    {
        var json = JsonSerializer.Serialize(tokens, JsonOptions);
        var directory = Path.GetDirectoryName(FilePath);

        if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
        {
            Directory.CreateDirectory(directory);
        }

        File.WriteAllText(FilePath, json);
    }
}