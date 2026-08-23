using Microsoft.AspNetCore.Mvc;
using DeviceGateway.Services;

namespace DeviceGateway.Controllers;

/// <summary>
/// Serves firmware images to field devices and accepts new builds from the vendor pipeline.
/// </summary>
/// <remarks>
/// The far end of this fixture's flagship chain. Devices ask this endpoint what to install and
/// then install it, so anything that can influence what this returns owns the fleet.
/// </remarks>
[ApiController]
[Route("api/[controller]")]
public class FirmwareController : ControllerBase
{
    private readonly FirmwareCatalog _catalog;

    public FirmwareController(FirmwareCatalog catalog) => _catalog = catalog;

    [HttpGet("{model}/latest")]
    public async Task<IActionResult> Latest(string model)
    {
        var image = await _catalog.LatestAsync(model);

        return Ok(new
        {
            model,
            image.Version,
            image.Url,
            image.Sha256,
        });
    }

    // CODE-05 (flagship, CWE-345): the signature field is read off the manifest and then never
    // checked against anything. The gateway reports the SHA-256 to the device, the device
    // verifies the download matches it - and neither of them verifies that the manifest itself
    // came from the vendor.
    //
    // So an attacker who can write a manifest into the firmware bucket (INFRA-01) writes both
    // the image and the hash that "verifies" it. Integrity without authenticity is not
    // integrity, and this is what that looks like in code.
    [HttpPost("{model}/publish")]
    public async Task<IActionResult> Publish(string model, [FromBody] FirmwareManifest manifest)
    {
        await _catalog.PublishAsync(model, manifest);

        return Accepted(new { model, manifest.Version });
    }

    // CODE-06 (CWE-306): publishing requires no authentication at all. The endpoint is meant to
    // be reachable only from the vendor's build pipeline, and INFRA-06 puts it on the public
    // internet.
    [HttpDelete("{model}/{version}")]
    public IActionResult Withdraw(string model, string version) => NoContent();
}

public sealed class FirmwareManifest
{
    public string Version { get; set; } = string.Empty;
    public string Url { get; set; } = string.Empty;
    public string Sha256 { get; set; } = string.Empty;

    /// <summary>Present on every manifest, checked by nothing. See CODE-05.</summary>
    public string VendorSignature { get; set; } = string.Empty;
}
