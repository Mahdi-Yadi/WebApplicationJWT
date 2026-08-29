using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WebApplicationJWT.Models;

namespace WebApplicationJWT.Areas.UserPanel.Controllers;

/// <summary>
/// Manages user session monitoring, active device tracking, and security session revocations within the UserPanel area.
/// </summary>
[Area("UserPanel")]
[Route("UserPanel/[action]")]
[Authorize]
public class AccountController : Controller
{
    private readonly IHttpClientFactory _httpClientFactory;

    /// <summary>
    /// Initializes a new instance of the <see cref="AccountController"/> class.
    /// </summary>
    /// <param name="httpClientFactory">Factory for creating HTTP client instances.</param>
    public AccountController(IHttpClientFactory httpClientFactory)
    {
        _httpClientFactory = httpClientFactory;
    }

    /// <summary>
    /// Retrieves and displays the list of active user sessions across connected client devices.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> Sessions()
    {
        var client = _httpClientFactory.CreateClient("AuthClient");
        var response = await client.GetAsync("/api/auth/sessions");

        if (!response.IsSuccessStatusCode)
        {
            TempData["Error"] = "Failed to retrieve user session information.";
            return View(new List<UserSessionViewModel>());
        }

        var sessions = await response.Content.ReadFromJsonAsync<List<UserSessionViewModel>>();
        return View(sessions ?? new List<UserSessionViewModel>());
    }

    /// <summary>
    /// Revokes a specific user session by its unique session identifier.
    /// </summary>
    /// <param name="sessionId">The session identifier string to revoke.</param>
    [HttpPost]
    public async Task<IActionResult> RevokeSession(string sessionId)
    {
        var client = _httpClientFactory.CreateClient("AuthClient");
        var response = await client.PostAsync($"/api/auth/sessions/revoke/{sessionId}", null);

        if (response.IsSuccessStatusCode)
        {
            TempData["Success"] = "The specified session has been successfully revoked.";
        }
        else
        {
            TempData["Error"] = "Failed to revoke the session.";
        }

        return RedirectToAction(nameof(Sessions));
    }

    /// <summary>
    /// Permanently deletes a specific session record from the persistent JSON store.
    /// </summary>
    /// <param name="sessionId">The session identifier string to delete.</param>
    [HttpPost]
    public async Task<IActionResult> DeleteSession(string sessionId)
    {
        var client = _httpClientFactory.CreateClient("AuthClient");
        var response = await client.DeleteAsync($"/api/auth/sessions/{sessionId}");

        if (response.IsSuccessStatusCode)
        {
            TempData["Success"] = "The session has been permanently deleted.";
        }
        else
        {
            TempData["Error"] = "Failed to delete the session.";
        }

        return RedirectToAction(nameof(Sessions));
    }

    /// <summary>
    /// Revokes all active user sessions across all devices, clears local authentication cookies, and redirects to the home page.
    /// </summary>
    [HttpPost]
    public async Task<IActionResult> RevokeAll()
    {
        var client = _httpClientFactory.CreateClient("AuthClient");

        // 1. Submit request to server to invalidate all user sessions
        var response = await client.PostAsync("/api/auth/sessions/revoke-all", null);

        // 2. Terminate local MVC authentication session and clear browser cookies
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        TempData["Success"] = "You have been successfully logged out from all devices.";

        // Redirect to the main application homepage
        return RedirectToAction("Index", "Home", new { area = "" });
    }
}