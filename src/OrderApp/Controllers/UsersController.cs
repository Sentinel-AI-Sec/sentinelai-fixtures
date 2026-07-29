using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;

namespace OrderApp.Controllers;

[ApiController]
[Route("api/[controller]")]
public class UsersController : ControllerBase
{
    private const string ConnString =
        "Server=fixture-db;Database=OrderApp;User Id=svc_order;Password=DemoFixtureP@ssw0rd123;";

    // CODE-02 (CWE-89): string-concatenated SQL built directly from
    // user-controlled input, executed via raw SqlCommand.
    [HttpGet("search")]
    public IActionResult SearchUsers([FromQuery] string name)
    {
        using var conn = new SqlConnection(ConnString);
        conn.Open();

        var query = "SELECT Id, Email, Role FROM Users WHERE Name = '" + name + "'";
        using var cmd = new SqlCommand(query, conn);
        using var reader = cmd.ExecuteReader();

        var results = new List<object>();
        while (reader.Read())
        {
            results.Add(new { Id = reader.GetInt32(0), Email = reader.GetString(1) });
        }

        return Ok(results);
    }

    // CODE-13 (CWE-284): sensitive account-listing endpoint with no
    // [Authorize] attribute at all - anyone can call it.
    [HttpGet("all")]
    public IActionResult GetAllUsers()
    {
        return Ok(new[] { new { Id = 1, Email = "admin@example.com", Role = "Admin" } });
    }
}
