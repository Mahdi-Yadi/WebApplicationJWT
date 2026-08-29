using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using WebApplicationAPI.Services;

namespace WebApplicationAPI.Controllers;

/// <summary>
/// Handles product management operations, including product listing and administration capabilities.
/// </summary>
[ApiController]
[Route("api/[controller]")]
[EnableRateLimiting("GeneralPolicy")]
public class ProductController : ControllerBase
{
    /// <summary>
    /// Retrieves all available products from the repository.
    /// </summary>
    /// <returns>An <see cref="IActionResult"/> containing the collection of products.</returns>
    [HttpGet]
    public IActionResult GetProducts()
    {
        var products = ProductJsonRepository.GetAll();
        return Ok(products);
    }

    /// <summary>
    /// Creates a new product item in the system repository.
    /// </summary>
    /// <param name="model">The product creation payload containing details such as name and price.</param>
    /// <returns>An <see cref="IActionResult"/> indicating successful creation or validation error details.</returns>
    [HttpPost]
    [Authorize(Roles = "Admin")]
    public IActionResult CreateProduct([FromBody] CreateProductDto model)
    {
        if (model == null || string.IsNullOrWhiteSpace(model.Name) || model.Price <= 0)
        {
            return BadRequest("Invalid product name or price.");
        }

        ProductJsonRepository.Add(model.Name, model.Price);
        return Ok(new { Message = "Product created successfully." });
    }
}

/// <summary>
/// Data Transfer Object representing the payload required to create a new product.
/// </summary>
/// <param name="Name">The display name of the product.</param>
/// <param name="Price">The monetary value assigned to the product.</param>
public record CreateProductDto(string Name, decimal Price);