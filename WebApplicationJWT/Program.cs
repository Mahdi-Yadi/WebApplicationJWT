using Microsoft.AspNetCore.Authentication.Cookies;
using WebApplicationJWT.Handlers;

var builder = WebApplication.CreateBuilder(args);

// -----------------------------------------------------------------------------
// 1. MVC Controllers and View Services Configuration
// -----------------------------------------------------------------------------
builder.Services.AddControllersWithViews();

// Register HttpContextAccessor required for accessing HttpContext within DelegatingHandlers
builder.Services.AddHttpContextAccessor();

// Register custom JWT token refresh delegating handler
builder.Services.AddTransient<JwtRefreshTokenHandler>();

// Configure HttpClient with automatic token refresh message handler middleware
builder.Services.AddHttpClient("AuthClient", client =>
{
    client.BaseAddress = new Uri(builder.Configuration["ApiSettings:BaseUrl"] ?? "https://localhost:7089");
})
.AddHttpMessageHandler<JwtRefreshTokenHandler>();

// -----------------------------------------------------------------------------
// 2. Cookie Authentication Security Configuration
// -----------------------------------------------------------------------------
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Login";
        options.AccessDeniedPath = "/AccessDenied";
        options.ExpireTimeSpan = TimeSpan.FromDays(7);

        // 1. Prevent client-side JavaScript access to cookies (mitigates XSS attacks)
        options.Cookie.HttpOnly = true;

        // 2. Transmit cookies strictly over secure HTTPS connections in production environments
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;

        // 3. Restrict cross-site cookie transmission (mitigates CSRF attacks)
        options.Cookie.SameSite = SameSiteMode.Strict;

        // Assign a dedicated custom name for the authentication cookie
        options.Cookie.Name = ".AspNetCore.AuthToken.Session";
    });

var app = builder.Build();

// -----------------------------------------------------------------------------
// 3. HTTP Request Pipeline Middleware Configuration
// -----------------------------------------------------------------------------
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // Enforce HTTP Strict Transport Security (HSTS) in production
    app.UseHsts();
}

app.UseHttpsRedirection();

// Serve static files prior to routing execution for optimized asset delivery
app.UseStaticFiles();

app.UseRouting();

// Authentication and Authorization middleware must be executed in sequence
app.UseAuthentication();
app.UseAuthorization();

// -----------------------------------------------------------------------------
// 4. Endpoint Routing and Area Configuration
// -----------------------------------------------------------------------------
app.MapControllerRoute(
    name: "areas",
    pattern: "{area:exists}/{controller=Home}/{action=Index}/{id?}");

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();