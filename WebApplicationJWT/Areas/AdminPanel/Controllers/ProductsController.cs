using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WebApplicationJWT.Models;

namespace WebApplicationJWT.Areas.AdminPanel.Controllers;

/// <summary>
/// Manages administrative product catalog operations and inventory creation within the AdminPanel area.
/// </summary>
[Area("AdminPanel")]
[Authorize(Roles = "Admin")]
[Route("AdminPanel/[action]")]
[AutoValidateAntiforgeryToken]
public class ProductsController(IHttpClientFactory httpClientFactory) : Controller
{
    /// <summary>
    /// Retrieves and displays the complete list of products from the protected API.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> ProductList()
    {
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

    /// <summary>
    /// Displays the product creation view.
    /// </summary>
    [HttpGet]
    public IActionResult CreateProduct() => View();

    /// <summary>
    /// Processes product creation submissions with administrator authorization checks.
    /// </summary>
    /// <param name="name">The name of the product.</param>
    /// <param name="price">The price of the product.</param>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> CreateProduct(string name, decimal price)
    {
        var client = httpClientFactory.CreateClient("AuthClient");

        // The JwtRefreshTokenHandler middleware automatically injects the access token 
        // and transparently handles token renewal if expiration occurs.
        var response = await client.PostAsJsonAsync("/api/product", new { name, price });

        if (response.IsSuccessStatusCode)
        {
            ViewBag.Success = "Product registered successfully!";
        }
        else if (response.StatusCode == System.Net.HttpStatusCode.Forbidden)
        {
            ViewBag.Error = "You do not have the required permissions (Admin role) to register a product.";
        }
        else
        {
            ViewBag.Error = "An error occurred while registering the product.";
        }

        return View();
    }
}