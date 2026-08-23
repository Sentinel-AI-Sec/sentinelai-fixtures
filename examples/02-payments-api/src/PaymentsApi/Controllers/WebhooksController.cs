using System.Text;
using Microsoft.AspNetCore.Mvc;
using RestSharp;

namespace PaymentsApi.Controllers;

/// <summary>
/// Registers and verifies merchant webhook endpoints.
/// </summary>
/// <remarks>
/// This is the entry point of the fixture's flagship chain. A merchant supplies the URL their
/// payment notifications should be delivered to, and the service "verifies" it by fetching it
/// once. Fetching a URL the caller chose is the whole vulnerability.
/// </remarks>
[ApiController]
[Route("api/[controller]")]
public class WebhooksController : ControllerBase
{
    private readonly ILogger<WebhooksController> _logger;

    public WebhooksController(ILogger<WebhooksController> logger) => _logger = logger;

    // CODE-01 (flagship, CWE-918): server-side request forgery. The callback URL comes
    // straight from the request body and is fetched with no allow-list, no scheme check and
    // no block on link-local addresses - so http://169.254.169.254/latest/meta-data/iam/
    // security-credentials/ returns this task's own IAM role credentials to the caller.
    //
    // Pairs with DEP-01 (RestSharp 106.11.7, which follows redirects by default) and with
    // INFRA-01 (the task role's secretsmanager:* wildcard) for the flagship chain: the SSRF
    // steals the role, the role reads the PSP key out of Secrets Manager.
    [HttpPost("verify")]
    public async Task<IActionResult> VerifyCallback([FromBody] CallbackRegistration registration)
    {
        var client = new RestClient(registration.CallbackUrl);
        var response = await client.ExecuteAsync(new RestRequest(Method.GET));

        // CODE-02 (CWE-200): the fetched body is returned to the caller verbatim. Even without
        // the SSRF above being exploitable for RCE, this turns the service into an open proxy
        // for anything reachable from inside the VPC.
        return Ok(new
        {
            reachable = response.IsSuccessful,
            status = (int)response.StatusCode,
            body = response.Content,
        });
    }

    [HttpPost("register")]
    public IActionResult Register([FromBody] CallbackRegistration registration)
    {
        // CODE-03 (CWE-117): the merchant-controlled URL is written to the log with no
        // encoding, so a newline in it forges additional log entries.
        _logger.LogInformation(
            "Registered callback {Url} for merchant {Merchant}",
            registration.CallbackUrl,
            registration.MerchantId);

        return Accepted();
    }

    [HttpPost("replay")]
    public IActionResult Replay([FromBody] ReplayRequest request)
    {
        // CODE-04 (CWE-330): the replay token is generated with a non-cryptographic RNG seeded
        // from the clock, so an attacker who knows roughly when a replay was issued can
        // enumerate the token space in a few thousand guesses.
        var seeded = new Random(Environment.TickCount);
        var token = new StringBuilder();

        for (var i = 0; i < 16; i++)
            token.Append(seeded.Next(0, 16).ToString("x"));

        return Ok(new { replayToken = token.ToString(), request.EventId });
    }
}

public sealed class CallbackRegistration
{
    public string MerchantId { get; set; } = string.Empty;
    public string CallbackUrl { get; set; } = string.Empty;
}

public sealed class ReplayRequest
{
    public string EventId { get; set; } = string.Empty;
}
