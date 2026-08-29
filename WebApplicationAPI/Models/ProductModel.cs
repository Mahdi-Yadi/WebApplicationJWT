namespace WebApplicationAPI.Models;

/// <summary>
/// Represents a product entity managed within the application catalog.
/// </summary>
public class ProductModel
{
    /// <summary>
    /// Gets or sets the unique primary key identifier for the product.
    /// </summary>
    public int Id { get; set; }

    /// <summary>
    /// Gets or sets the descriptive display name of the product.
    /// </summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the monetary price assigned to the product.
    /// </summary>
    public decimal Price { get; set; }
}