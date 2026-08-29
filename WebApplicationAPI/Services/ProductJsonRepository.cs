using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Unicode;
using WebApplicationAPI.Models;

namespace WebApplicationAPI.Services;

/// <summary>
/// Provides thread-safe data access operations for managing product persistence in local JSON storage.
/// </summary>
public static class ProductJsonRepository
{
    private static readonly string FilePath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "Jsons", "products.json");
    private static readonly object LockObj = new();

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.Create(UnicodeRanges.All)
    };

    /// <summary>
    /// Retrieves all products stored in the JSON repository.
    /// </summary>
    /// <returns>A list of <see cref="ProductModel"/> instances.</returns>
    public static List<ProductModel> GetAll()
    {
        lock (LockObj)
        {
            return GetAllInternal();
        }
    }

    /// <summary>
    /// Appends a new product record to the repository with an auto-incremented identifier.
    /// </summary>
    /// <param name="name">The name of the product.</param>
    /// <param name="price">The monetary price of the product.</param>
    public static void Add(string name, decimal price)
    {
        lock (LockObj)
        {
            var products = GetAllInternal();
            var newId = products.Count > 0 ? products.Max(p => p.Id) + 1 : 1;

            products.Add(new ProductModel
            {
                Id = newId,
                Name = name,
                Price = price
            });

            SaveToFileInternal(products);
        }
    }

    /// <summary>
    /// Internal non-locking helper to read products from disk.
    /// </summary>
    private static List<ProductModel> GetAllInternal()
    {
        if (!File.Exists(FilePath))
        {
            return new List<ProductModel>();
        }

        var json = File.ReadAllText(FilePath);
        if (string.IsNullOrWhiteSpace(json))
        {
            return new List<ProductModel>();
        }

        return JsonSerializer.Deserialize<List<ProductModel>>(json, JsonOptions) ?? new List<ProductModel>();
    }

    /// <summary>
    /// Internal non-locking helper to persist product data to disk.
    /// </summary>
    private static void SaveToFileInternal(List<ProductModel> products)
    {
        var json = JsonSerializer.Serialize(products, JsonOptions);
        var directory = Path.GetDirectoryName(FilePath);

        if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
        {
            Directory.CreateDirectory(directory);
        }

        File.WriteAllText(FilePath, json);
    }
}