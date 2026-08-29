using System.Net;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace WebApplicationJWT.Handlers;

/// <summary>
/// Intercepts outgoing HTTP requests to attach JWT access tokens and automatically 
/// handles token expiration by refreshing credentials or terminating the user session.
/// </summary>
public class JwtRefreshTokenHandler : DelegatingHandler
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IConfiguration _configuration;

    /// <summary>
    /// Initializes a new instance of the <see cref="JwtRefreshTokenHandler"/> class.
    /// </summary>
    /// <param name="httpContextAccessor">Provides access to the current HTTP context.</param>
    /// <param name="httpClientFactory">Factory for creating HTTP client instances.</param>
    /// <param name="configuration">Application configuration provider.</param>
    public JwtRefreshTokenHandler(
        IHttpContextAccessor httpContextAccessor,
        IHttpClientFactory httpClientFactory,
        IConfiguration configuration)
    {
        _httpContextAccessor = httpContextAccessor;
        _httpClientFactory = httpClientFactory;
        _configuration = configuration;
    }

    /// <inheritdoc />
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var httpContext = _httpContextAccessor.HttpContext;
        if (httpContext == null)
        {
            return await base.SendAsync(request, cancellationToken);
        }

        // 1. Retrieve current access token and attach it to the request authorization header
        var accessToken = await httpContext.GetTokenAsync("access_token");
        if (!string.IsNullOrEmpty(accessToken))
        {
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
        }

        // Send the primary outgoing HTTP request
        var response = await base.SendAsync(request, cancellationToken);

        // 2. Intercept 401 Unauthorized responses (indicating an expired or invalid access token)
        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            // Attempt to renew credentials using the stored refresh token
            var refreshed = await RefreshTokenAsync(httpContext, cancellationToken);

            if (refreshed)
            {
                // 3. Renewal successful: Clone the original request, apply the new access token, and retry
                var newAccessToken = await httpContext.GetTokenAsync("access_token");
                var newRequest = await CloneHttpRequestMessageAsync(request);
                newRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", newAccessToken);

                response = await base.SendAsync(newRequest, cancellationToken);
            }
            else
            {
                // 4. Renewal failed: Revoke session, clear authentication cookies, and force logout
                await httpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            }
        }

        return response;
    }

    /// <summary>
    /// Sends a refresh token request to the authentication API and updates the authentication cookie store.
    /// </summary>
    private async Task<bool> RefreshTokenAsync(HttpContext httpContext, CancellationToken cancellationToken)
    {
        var refreshToken = await httpContext.GetTokenAsync("refresh_token");
        if (string.IsNullOrEmpty(refreshToken))
        {
            return false;
        }

        var client = _httpClientFactory.CreateClient();
        var baseUrl = _configuration["ApiSettings:BaseUrl"] ?? "https://localhost:7089";

        var refreshResponse = await client.PostAsJsonAsync(
            $"{baseUrl}/api/auth/refresh",
            new { RefreshToken = refreshToken },
            cancellationToken);

        if (!refreshResponse.IsSuccessStatusCode)
        {
            return false;
        }

        var tokenResponse = await refreshResponse.Content.ReadFromJsonAsync<TokenResponseDto>(cancellationToken: cancellationToken);
        if (tokenResponse == null)
        {
            return false;
        }

        // Retrieve current authentication result to update stored tokens in the MVC cookie
        var authResult = await httpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        if (!authResult.Succeeded || authResult.Properties == null)
        {
            return false;
        }

        authResult.Properties.UpdateTokenValue("access_token", tokenResponse.AccessToken);
        authResult.Properties.UpdateTokenValue("refresh_token", tokenResponse.RefreshToken);

        await httpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            authResult.Principal!,
            authResult.Properties);

        return true;
    }

    /// <summary>
    /// Deep-clones an <see cref="HttpRequestMessage"/> instance to allow safe retry executions.
    /// </summary>
    private async Task<HttpRequestMessage> CloneHttpRequestMessageAsync(HttpRequestMessage req)
    {
        var clone = new HttpRequestMessage(req.Method, req.RequestUri);

        if (req.Content != null)
        {
            var ms = new MemoryStream();
            await req.Content.CopyToAsync(ms);
            ms.Position = 0;
            clone.Content = new StreamContent(ms);

            if (req.Content.Headers != null)
            {
                foreach (var header in req.Content.Headers)
                {
                    clone.Content.Headers.Add(header.Key, header.Value);
                }
            }
        }

        clone.Version = req.Version;

        foreach (var header in req.Headers)
        {
            clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }

        return clone;
    }

    /// <summary>
    /// Data transfer object representing the refreshed token response payload.
    /// </summary>
    private record TokenResponseDto(string AccessToken, string RefreshToken);
}