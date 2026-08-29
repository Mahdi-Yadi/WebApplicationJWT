using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
namespace WebApplicationJWT.Areas.AdminPanel.Controllers;

[Area("AdminPanel")]
[Authorize(Roles = "Admin")]
[Route("AdminPanel/[action]")]
public class HomeController : Controller
{
    public IActionResult Index()
    {
        ViewBag.Message = "به پنل مدیریت سیستم خوش آمدید.";
        return View();
    }
}