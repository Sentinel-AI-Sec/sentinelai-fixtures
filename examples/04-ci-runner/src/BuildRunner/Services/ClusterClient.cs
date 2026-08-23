namespace BuildRunner.Services;

/// <summary>
/// Talks to the Kubernetes API to report job status back onto the pipeline object.
/// </summary>
/// <remarks>
/// The far end of the flagship chain. This reads the pod's own ServiceAccount token from the
/// standard projected path - ordinary, correct behaviour for an in-cluster client. What makes
/// it the payload is INFRA-02: the ServiceAccount is bound to cluster-admin, so the token this
/// reads is a cluster takeover rather than a status update.
/// </remarks>
public class ClusterClient
{
    private const string TokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token";

    public async Task<string> ReadTokenAsync(CancellationToken ct = default)
    {
        if (!File.Exists(TokenPath)) return string.Empty;

        return await File.ReadAllTextAsync(TokenPath, ct);
    }

    // CODE-07 (CWE-295): certificate validation is disabled for the API server call, so a
    // process able to intercept the pod's traffic can impersonate the control plane.
    public HttpClient CreateClient()
    {
        var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true,
        };

        return new HttpClient(handler);
    }
}
