using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WebApplicationJWT.Models;

namespace WebApplicationJWT.Areas.AdminPanel.Controllers;

/// <summary>
/// Manages user administration, account properties, permissions, and session oversight within the AdminPanel area.
/// </summary>
[Area("AdminPanel")]
[Authorize(Roles = "Admin")]
[Route("AdminPanel/[action]")]
[AutoValidateAntiforgeryToken]
public class UsersController : Controller
{
    private readonly IHttpClientFactory _httpClientFactory;

    /// <summary>
    /// Initializes a new instance of the <see cref="UsersController"/> class.
    /// </summary>
    /// <param name="httpClientFactory">Factory for creating HTTP client instances.</param>
    public UsersController(IHttpClientFactory httpClientFactory)
    {
        _httpClientFactory = httpClientFactory;
    }

    /// <summary>
    /// Retrieves and displays the list of registered user accounts.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> UsersList()
    {
        var client = _httpClientFactory.CreateClient("AuthClient");
        var response = await client.GetAsync("/api/users");

        if (!response.IsSuccessStatusCode)
        {
            TempData["Error"] = "Failed to retrieve the user list or insufficient permissions.";
            return RedirectToAction("Index", "Home");
        }

        var users = await response.Content.ReadFromJsonAsync<List<UserViewModel>>();
        return View(users ?? new List<UserViewModel>());
    }

    /// <summary>
    /// Displays the user edit form containing account details and permissions.
    /// </summary>
    /// <param name="username">The username of the user to edit.</param>
    [HttpGet]
    public async Task<IActionResult> Edit(string username)
    {
        var client = _httpClientFactory.CreateClient("AuthClient");
        var response = await client.GetAsync($"/api/users/{username}");

        if (!response.IsSuccessStatusCode)
        {
            TempData["Error"] = "User not found or access unauthorized.";
            return RedirectToAction(nameof(UsersList));
        }

        var user = await response.Content.ReadFromJsonAsync<UserViewModel>();
        if (user == null)
        {
            return RedirectToAction(nameof(UsersList));
        }

        var model = new UpdateUserViewModel
        {
            Username = user.Username,
            Role = user.Role,
            SelectedPermissions = user.Permissions
        };

        return View(model);
    }

    /// <summary>
    /// Processes user account updates, role modifications, and permission reassignments.
    /// </summary>
    /// <param name="model">The updated user view model.</param>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Edit(UpdateUserViewModel model)
    {
        var client = _httpClientFactory.CreateClient("AuthClient");

        var dto = new
        {
            role = model.Role,
            permissions = model.SelectedPermissions,
            newPassword = string.IsNullOrWhiteSpace(model.NewPassword) ? null : model.NewPassword
        };

        var response = await client.PutAsJsonAsync($"/api/users/{model.Username}", dto);

        if (response.IsSuccessStatusCode)
        {
            TempData["Success"] = $"User account '{model.Username}' has been successfully updated.";
            return RedirectToAction(nameof(UsersList));
        }

        ModelState.AddModelError(string.Empty, "Failed to update user account.");
        return View(model);
    }

    /// <summary>
    /// Deletes a specified user account from the system.
    /// </summary>
    /// <param name="username">The username of the user to delete.</param>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Delete(string username)
    {
        var client = _httpClientFactory.CreateClient("AuthClient");
        var response = await client.DeleteAsync($"/api/users/{username}");

        if (response.IsSuccessStatusCode)
        {
            TempData["Success"] = $"User '{username}' was successfully deleted.";
        }
        else
        {
            var err = await response.Content.ReadAsStringAsync();
            TempData["Error"] = err.Replace("\"", "");
        }

        return RedirectToAction(nameof(UsersList));
    }

    /// <summary>
    /// Retrieves and displays active session logs associated with a specific user.
    /// </summary>
    /// <param name="username">The target username.</param>
    [HttpGet]
    public async Task<IActionResult> Sessions(string username)
    {
        var client = _httpClientFactory.CreateClient("AuthClient");
        var response = await client.GetAsync($"/api/users/{username}/sessions");

        if (!response.IsSuccessStatusCode)
        {
            TempData["Error"] = "Unauthorized access or session records not found.";
            return RedirectToAction(nameof(UsersList));
        }

        var sessions = await response.Content.ReadFromJsonAsync<List<UserSessionViewModel>>();
        ViewBag.TargetUsername = username;
        return View(sessions ?? new List<UserSessionViewModel>());
    }
}