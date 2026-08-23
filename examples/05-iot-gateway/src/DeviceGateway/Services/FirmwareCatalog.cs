namespace DeviceGateway.Services;

/// <summary>
/// The list of firmware images the fleet is told to install, backed by an S3 bucket.
/// </summary>
/// <remarks>
/// Ordinary code. It reads a manifest from a bucket and reports what it says. The reason it is
/// the payload of the flagship chain is entirely in infra/storage.tf: the bucket policy allows
/// s3:PutObject from Principal "*", so the manifest this trusts can be written by anyone.
/// </remarks>
public class FirmwareCatalog
{
    private readonly IConfiguration _configuration;

    public FirmwareCatalog(IConfiguration configuration) => _configuration = configuration;

    public async Task<FirmwareImage> LatestAsync(string model, CancellationToken ct = default)
    {
        var bucket = _configuration["Firmware:Bucket"] ?? "iot-fleet-firmware";

        await Task.Yield();

        return new FirmwareImage(
            "4.1.2",
            $"https://{bucket}.s3.amazonaws.com/{model}/4.1.2.bin",
            "0000000000000000000000000000000000000000000000000000000000000000");
    }

    public async Task PublishAsync(string model, object manifest, CancellationToken ct = default) =>
        await Task.Yield();

    // CODE-07 (CWE-798): the bucket write credential as a hardcoded fallback. Dummy value.
    public string WriteCredential =>
        _configuration["Firmware:WriteKey"] ?? "AKIAFIXTUREDUMMYKEY0/wJalrFixtureDummySecret000111";
}

public sealed record FirmwareImage(string Version, string Url, string Sha256);
