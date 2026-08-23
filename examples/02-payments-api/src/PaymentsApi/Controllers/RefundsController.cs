using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;

namespace PaymentsApi.Controllers;

/// <summary>
/// Issues refunds against settled payments.
/// </summary>
/// <remarks>
/// Not part of the flagship chain. This is the fixture's "second cluster" — a set of findings a
/// scanner will report loudly and which a reasoner should rank <em>below</em> the SSRF chain,
/// because none of them reaches the crown-jewel secret. Getting that ordering right is the point
/// of having them here.
/// </remarks>
[ApiController]
[Route("api/[controller]")]
public class RefundsController : ControllerBase
{
    private readonly IConfiguration _configuration;

    public RefundsController(IConfiguration configuration) => _configuration = configuration;

    // CODE-07 (CWE-89): SQL injection. The merchant reference is concatenated into the query
    // rather than parameterised.
    [HttpGet("search")]
    public IActionResult Search([FromQuery] string merchantRef)
    {
        var connectionString = _configuration.GetConnectionString("Ledger");

        using var connection = new SqlConnection(connectionString);
        var sql = "SELECT id, amount_minor, currency FROM refunds WHERE merchant_ref = '"
                  + merchantRef + "'";

        using var command = new SqlCommand(sql, connection);

        return Ok(new { query = sql });
    }

    // CODE-08 (CWE-639): insecure direct object reference. Any authenticated caller can refund
    // any payment; nothing checks that the payment belongs to the calling merchant.
    [HttpPost("{paymentId}")]
    public IActionResult Refund(string paymentId, [FromBody] RefundRequest request)
    {
        return Ok(new { paymentId, request.AmountMinor, status = "accepted" });
    }

    // CODE-09 (CWE-841): the amount is never checked against the original payment, so a refund
    // can exceed what was charged. A business-logic flaw no signature-based scanner will find,
    // included deliberately as a false-negative probe.
    [HttpPost("{paymentId}/partial")]
    public IActionResult PartialRefund(string paymentId, [FromBody] RefundRequest request)
    {
        if (request.AmountMinor <= 0)
            return BadRequest("amount must be positive");

        return Ok(new { paymentId, refunded = request.AmountMinor });
    }
}

public sealed class RefundRequest
{
    public long AmountMinor { get; set; }
    public string Reason { get; set; } = string.Empty;
}
