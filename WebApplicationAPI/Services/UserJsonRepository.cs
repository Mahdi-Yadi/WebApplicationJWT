using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Unicode;
using WebApplicationAPI.Models;

namespace WebApplicationAPI.Services;

/// <summary>
/// Provides thread-safe data access operations for persisting user accounts in a local JSON file store.
/// </summary>
public static class UserJsonRepository
{
    private static readonly string FilePath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "Jsons", "users.json");
    private static readonly object LockObj = new();

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.Create(UnicodeRanges.All)
    };

    /// <summary>
    /// Retrieves all registered users from the JSON repository.
    /// </summary>
    /// <returns>A list of <see cref="UserModel"/> instances.</returns>
    public static List<UserModel> GetAll()
    {
        lock (LockObj)
        {
            return GetAllInternal();
        }
    }

    /// <summary>
    /// Retrieves a user record by username (case-insensitive).
    /// </summary>
    /// <param name="username">The username to search for.</param>
    /// <returns>The matching <see cref="UserModel"/> if found; otherwise, <c>null</c>.</returns>
    public static UserModel? GetByUsername(string username)
    {
        lock (LockObj)
        {
            var users = GetAllInternal();
            return users.FirstOrDefault(u => string.Equals(u.Username, username, StringComparison.OrdinalIgnoreCase));
        }
    }

    /// <summary>
    /// Appends a new user record to the repository and assigns an auto-incremented identifier.
    /// </summary>
    /// <param name="user">The user model instance to add.</param>
    public static void Add(UserModel user)
    {
        lock (LockObj)
        {
            var users = GetAllInternal();
            user.Id = users.Count > 0 ? users.Max(u => u.Id) + 1 : 1;
            users.Add(user);
            SaveAllInternal(users);
        }
    }

    /// <summary>
    /// Updates an existing user record identified by username.
    /// </summary>
    /// <param name="updatedUser">The updated user model object.</param>
    /// <returns><c>true</c> if the user was found and updated; otherwise, <c>false</c>.</returns>
    public static bool Update(UserModel updatedUser)
    {
        lock (LockObj)
        {
            var users = GetAllInternal();
            var index = users.FindIndex(u => string.Equals(u.Username, updatedUser.Username, StringComparison.OrdinalIgnoreCase));

            if (index == -1)
            {
                return false;
            }

            users[index] = updatedUser;
            SaveAllInternal(users);
            return true;
        }
    }

    /// <summary>
    /// Deletes a user record by username (case-insensitive).
    /// </summary>
    /// <param name="username">The username of the user to remove.</param>
    /// <returns><c>true</c> if the user was removed; otherwise, <c>false</c>.</returns>
    public static bool Remove(string username)
    {
        lock (LockObj)
        {
            var users = GetAllInternal();
            var user = users.FirstOrDefault(u => string.Equals(u.Username, username, StringComparison.OrdinalIgnoreCase));

            if (user == null)
            {
                return false;
            }

            users.Remove(user);
            SaveAllInternal(users);
            return true;
        }
    }

    /// <summary>
    /// Internal non-locking reader method to load user records from disk.
    /// </summary>
    private static List<UserModel> GetAllInternal()
    {
        if (!File.Exists(FilePath))
        {
            return new List<UserModel>();
        }

        var json = File.ReadAllText(FilePath);
        if (string.IsNullOrWhiteSpace(json))
        {
            return new List<UserModel>();
        }

        return JsonSerializer.Deserialize<List<UserModel>>(json, JsonOptions) ?? new List<UserModel>();
    }

    /// <summary>
    /// Internal non-locking writer method to save all user records to disk.
    /// </summary>
    private static void SaveAllInternal(List<UserModel> users)
    {
        var json = JsonSerializer.Serialize(users, JsonOptions);
        var directory = Path.GetDirectoryName(FilePath);

        if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
        {
            Directory.CreateDirectory(directory);
        }

        File.WriteAllText(FilePath, json);
    }
}