using Microsoft.AspNetCore.Mvc;

namespace OrderApp.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AdminController : ControllerBase
{
    // CODE-13b (CWE-284): admin-only operation with no [Authorize],
    // no role check - anyone who finds the route can call it.
    [HttpPost("purge-cache")]
    public IActionResult PurgeCache()
    {
        return Ok(new { status = "cache purged" });
    }
}
