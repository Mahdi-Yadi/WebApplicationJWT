using Microsoft.AspNetCore.Mvc;
namespace WebApplicationJWT.Controllers;
public class HomeController : Controller
{
    public IActionResult Index() => View();
}