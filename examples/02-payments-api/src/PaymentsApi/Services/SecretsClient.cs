using System.Security.Cryptography;
using System.Text;

namespace PaymentsApi.Services;

/// <summary>
/// Reads payment-processor credentials out of AWS Secrets Manager.
/// </summary>
/// <remarks>
/// The far end of the flagship chain. Nothing here is exploitable on its own — it is ordinary,
/// correct-looking code. What makes it the payload is INFRA-01: the task role this runs under is
/// allowed <c>secretsmanager:GetSecretValue</c> on <c>Resource = "*"</c>, so credentials stolen
/// through CODE-01's SSRF can read every secret in the account, not just this one.
/// </remarks>
public class SecretsClient
{
    private readonly IConfiguration _configuration;

    public SecretsClient(IConfiguration configuration) => _configuration = configuration;

    public async Task<string> GetProcessorKeyAsync(CancellationToken ct = default)
    {
        var secretId = _configuration["Psp:SecretId"] ?? "prod/psp/live-key";

        // Stands in for the AWS SDK call. The fixture does not need a real client; the graph
        // only needs the resource coupling, which infra/iam.tf declares.
        await Task.Yield();

        return $"resolved:{secretId}";
    }

    // CODE-05 (CWE-327): MD5 for signing webhook payloads. Collision-vulnerable, and
    // unauthenticated besides - a hash is not a signature, so anyone who can compute MD5 can
    // forge a payment notification.
    public static string SignPayload(string payload)
    {
        var digest = MD5.HashData(Encoding.UTF8.GetBytes(payload));
        return Convert.ToHexString(digest).ToLowerInvariant();
    }

    // CODE-06 (CWE-208): signature comparison is not constant time, so the comparison leaks
    // how many leading bytes matched. Combined with a retryable endpoint that is enough to
    // recover a valid signature byte by byte.
    public static bool SignatureMatches(string expected, string supplied)
    {
        if (expected.Length != supplied.Length) return false;

        for (var i = 0; i < expected.Length; i++)
        {
            if (expected[i] != supplied[i]) return false;
        }

        return true;
    }
}
