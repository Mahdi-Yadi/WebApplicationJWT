using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace WebApplicationJWT.Areas.UserPanel.Controllers;

/// <summary>
/// Manages user dashboard views and protected resource requests within the UserPanel area.
/// </summary>
[Area("UserPanel")]
[Route("UserPanel/[action]")]
[Authorize]
public class HomeController(IHttpClientFactory httpClientFactory) : Controller
{
    /// <summary>
    /// Retrieves protected secure data from the backend API and renders the user dashboard view.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> Dashboard()
    {
        var client = httpClientFactory.CreateClient("AuthClient");

        // Authorization headers, token expiration checks, and automatic token refresh 
        // are handled transparently by the JwtRefreshTokenHandler pipeline.
        var response = await client.GetAsync("/api/auth/protected-data");

        if (response.IsSuccessStatusCode)
        {
            ViewBag.Message = await response.Content.ReadAsStringAsync();
        }
        else
        {
            ViewBag.Message = "Failed to retrieve data from the protected API service.";
        }

        ViewBag.FullName = User.FindFirst("FullName")?.Value ?? User.Identity?.Name;
        return View();
    }
}