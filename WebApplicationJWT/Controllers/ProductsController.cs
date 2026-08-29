using Microsoft.AspNetCore.Mvc;
using WebApplicationJWT.Models;

namespace WebApplicationJWT.Controllers;

/// <summary>
/// Manages product listing and retrieval operations via backend API communication.
/// </summary>
public class ProductsController(IHttpClientFactory httpClientFactory) : Controller
{
    /// <summary>
    /// Retrieves and displays the catalog of products from the protected backend API service.
    /// </summary>
    [HttpGet]
    [Route("Products")]
    public async Task<IActionResult> ProductList()
    {
        // Create an HTTP client configured with automatic JWT refresh token injection
        var client = httpClientFactory.CreateClient("AuthClient");

        var response = await client.GetAsync("/api/product");

        var products = new List<ProductViewModel>();

        if (response.IsSuccessStatusCode)
        {
            products = await response.Content.ReadFromJsonAsync<List<ProductViewModel>>()
                       ?? new List<ProductViewModel>();
        }
        else
        {
            ViewBag.Error = "Failed to retrieve the product list from the server.";
        }

        return View(products);
    }
}