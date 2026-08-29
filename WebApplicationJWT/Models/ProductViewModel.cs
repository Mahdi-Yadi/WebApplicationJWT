using System.ComponentModel.DataAnnotations;

namespace WebApplicationJWT.Models;

/// <summary>
/// Represents product information for display within MVC views.
/// </summary>
public class ProductViewModel
{
    /// <summary>
    /// Gets or sets the unique product identifier.
    /// </summary>
    public int Id { get; set; }

    /// <summary>
    /// Gets or sets the name of the product.
    /// </summary>
    [Display(Name = "Product Name")]
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the monetary price of the product.
    /// </summary>
    [Display(Name = "Price")]
    public decimal Price { get; set; }
}