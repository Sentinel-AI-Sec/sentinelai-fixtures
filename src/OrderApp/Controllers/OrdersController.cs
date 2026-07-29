using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

namespace OrderApp.Controllers;

[ApiController]
[Route("api/[controller]")]
public class OrdersController : ControllerBase
{
    // CODE-01 (flagship, CWE-502): TypeNameHandling.All lets the request
    // body specify arbitrary .NET types to instantiate during
    // deserialization - classic unsafe-deserialization RCE pattern.
    // Pairs with DEP-01 (old Newtonsoft.Json) for the flagship chain.
    private static readonly JsonSerializerSettings UnsafeSettings = new()
    {
        TypeNameHandling = TypeNameHandling.All
    };

    [HttpPost("import")]
    public IActionResult ImportOrder([FromBody] string rawJson)
    {
        try
        {
            var order = JsonConvert.DeserializeObject(rawJson, UnsafeSettings);
            return Ok(order);
        }
        catch (Exception ex)
        {
            // CODE-12 (CWE-209): raw exception detail returned to the
            // caller - leaks internal implementation/stack info.
            return StatusCode(500, new { error = ex.ToString() });
        }
    }

    [HttpGet("{id}")]
    public IActionResult GetOrder(int id)
    {
        // Placeholder read path - not part of any deliberate vuln.
        return Ok(new { id, status = "pending" });
    }
}
