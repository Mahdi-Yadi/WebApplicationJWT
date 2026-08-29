using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using WebApplicationJWT.Models;

namespace WebApplicationJWT.Controllers;

/// <summary>
/// Manages user authentication, registration flows, adaptive two-factor authentication (2FA), and session termination.
/// </summary>
public class AccountController(IHttpClientFactory httpClientFactory) : Controller
{
    /// <summary>
    /// Displays the user registration view. Redirects authenticated users to the home dashboard.
    /// </summary>
    [HttpGet]
    [AllowAnonymous]
    public IActionResult Register()
    {
        if (User.Identity?.IsAuthenticated ?? false)
        {
            return RedirectToAction("Index", "Home");
        }

        return View();
    }

    /// <summary>
    /// Processes incoming user registration submissions.
    /// </summary>
    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Register(RegisterViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var client = httpClientFactory.CreateClient("AuthClient");

        var response = await client.PostAsJsonAsync("/api/auth/register", new
        {
            username = model.Username,
            password = model.Password
        });

        if (response.IsSuccessStatusCode)
        {
            TempData["Success"] = "Registration successful. You can now log in.";
            return RedirectToAction(nameof(Login));
        }

        var errorMessage = await response.Content.ReadAsStringAsync();
        ModelState.AddModelError(string.Empty, !string.IsNullOrWhiteSpace(errorMessage) ? errorMessage.Replace("\"", "") : "User registration failed.");

        return View(model);
    }

    /// <summary>
    /// Displays the user login view.
    /// </summary>
    [HttpGet]
    [AllowAnonymous]
    public IActionResult Login() => View();

    /// <summary>
    /// Processes user login requests with adaptive multi-factor authentication (2FA) triggers.
    /// </summary>
    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var client = httpClientFactory.CreateClient("AuthClient");
        var response = await client.PostAsJsonAsync("/api/auth/login", model);

        if (!response.IsSuccessStatusCode)
        {
            var errorObj = await response.Content.ReadFromJsonAsync<Dictionary<string, string>>();
            var message = errorObj != null && errorObj.TryGetValue("message", out var msg)
                ? msg
                : "Invalid username or password.";

            ModelState.AddModelError(string.Empty, message);
            return View(model);
        }

        var result = await response.Content.ReadFromJsonAsync<LoginResponseDto>();
        if (result == null)
        {
            ModelState.AddModelError(string.Empty, "Invalid response received from authentication server.");
            return View(model);
        }

        // 1. If ML.NET anomaly detection triggers a 2FA verification challenge
        if (result.RequiresTwoFactor)
        {
            TempData["TwoFactorToken"] = result.TwoFactorToken;
            TempData["Username"] = model.Username;
            TempData["InfoMessage"] = result.Message;

            if (!string.IsNullOrEmpty(result.TestOtpCode))
            {
                TempData["TestOtpCode"] = result.TestOtpCode;
            }

            return RedirectToAction(nameof(Verify2FA));
        }

        // 2. Standard login success (unconditional access)
        return await CompleteLoginAsync(result.AccessToken!, result.RefreshToken!);
    }

    /// <summary>
    /// Displays the two-factor authentication code verification view.
    /// </summary>
    [HttpGet]
    [AllowAnonymous]
    public IActionResult Verify2FA()
    {
        var token = TempData["TwoFactorToken"]?.ToString();
        var username = TempData["Username"]?.ToString();

        if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(username))
        {
            TempData["Error"] = "The two-factor authentication session has expired. Please log in again.";
            return RedirectToAction(nameof(Login));
        }

        // Preserve temporary verification context for the upcoming form post
        TempData.Keep("TwoFactorToken");
        TempData.Keep("Username");

        ViewBag.InfoMessage = TempData["InfoMessage"]?.ToString();
        ViewBag.TestOtpCode = TempData["TestOtpCode"]?.ToString();

        var model = new Verify2FaViewModel
        {
            Username = username,
            TwoFactorToken = token
        };

        return View(model);
    }

    /// <summary>
    /// Processes and verifies the submitted two-factor authentication code.
    /// </summary>
    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Verify2FA(Verify2FaViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var client = httpClientFactory.CreateClient("AuthClient");
        var response = await client.PostAsJsonAsync("/api/auth/verify-2fa", new
        {
            username = model.Username,
            code = model.Code,
            twoFactorToken = model.TwoFactorToken
        });

        if (!response.IsSuccessStatusCode)
        {
            var errorObj = await response.Content.ReadFromJsonAsync<Dictionary<string, string>>();
            var message = errorObj != null && errorObj.TryGetValue("message", out var msg)
                ? msg
                : "Invalid or expired verification code.";

            ModelState.AddModelError(string.Empty, message);
            return View(model);
        }

        var result = await response.Content.ReadFromJsonAsync<LoginResponseDto>();
        if (result == null || string.IsNullOrEmpty(result.AccessToken))
        {
            ModelState.AddModelError(string.Empty, "Failed to retrieve authentication security tokens.");
            return View(model);
        }

        return await CompleteLoginAsync(result.AccessToken, result.RefreshToken!);
    }

    /// <summary>
    /// Helper method to map JWT claims, register cookie authentication properties, and sign in the user.
    /// </summary>
    private async Task<IActionResult> CompleteLoginAsync(string accessToken, string refreshToken)
    {
        var handler = new JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(accessToken);

        var claims = new List<Claim>();
        foreach (var claim in jwtToken.Claims)
        {
            if (claim.Type == "role" || claim.Type == ClaimTypes.Role || claim.Type.EndsWith("/role"))
            {
                claims.Add(new Claim(ClaimTypes.Role, claim.Value));
            }
            else if (claim.Type == "unique_name" || claim.Type == ClaimTypes.Name || claim.Type.EndsWith("/name"))
            {
                claims.Add(new Claim(ClaimTypes.Name, claim.Value));
            }
            else
            {
                claims.Add(claim);
            }
        }

        var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme, ClaimTypes.Name, ClaimTypes.Role);
        var authProperties = new AuthenticationProperties { IsPersistent = true };

        authProperties.StoreTokens([
            new AuthenticationToken { Name = "access_token", Value = accessToken },
            new AuthenticationToken { Name = "refresh_token", Value = refreshToken }
        ]);

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(claimsIdentity),
            authProperties);

        return Redirect("/UserPanel/Dashboard");
    }

    /// <summary>
    /// Terminates the user session, revokes refresh tokens on the server, and clears authentication cookies.
    /// </summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout()
    {
        var refreshToken = await HttpContext.GetTokenAsync("refresh_token");

        if (!string.IsNullOrEmpty(refreshToken))
        {
            var client = httpClientFactory.CreateClient("AuthClient");
            await client.PostAsJsonAsync("/api/auth/revoke", new { RefreshToken = refreshToken });
        }

        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return Redirect("/");
    }

    /// <summary>
    /// Displays the authorization access denied view.
    /// </summary>
    [HttpGet]
    public IActionResult AccessDenied() => View();
}