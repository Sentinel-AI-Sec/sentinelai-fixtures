using System.Xml;
using Microsoft.AspNetCore.Mvc;
using DeviceGateway.Services;

namespace DeviceGateway.Controllers;

/// <summary>
/// Registers field devices and accepts their telemetry.
/// </summary>
/// <remarks>
/// The start of the flagship chain. Devices register by POSTing an XML descriptor, which is the
/// one place the gateway parses attacker-controlled structured input.
/// </remarks>
[ApiController]
[Route("api/[controller]")]
public class DevicesController : ControllerBase
{
    private readonly FirmwareCatalog _catalog;

    public DevicesController(FirmwareCatalog catalog) => _catalog = catalog;

    // CODE-01 (flagship, CWE-611): XXE. XmlDocument with an XmlUrlResolver and DTD processing
    // left on, so a device descriptor can declare an external entity.
    //
    // Two payloads matter here. file:///proc/self/environ reads the gateway's own environment,
    // which is where INFRA-05 puts the bucket write credential. http://169.254.169.254/ reaches
    // instance metadata. Either one ends with credentials that can write to the firmware
    // bucket, which is the chain's target.
    [HttpPost("register")]
    public IActionResult Register([FromBody] string descriptorXml)
    {
        var document = new XmlDocument
        {
            XmlResolver = new XmlUrlResolver(),
        };

        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Parse,
            XmlResolver = new XmlUrlResolver(),
        };

        using var stringReader = new StringReader(descriptorXml);
        using var reader = XmlReader.Create(stringReader, settings);
        document.Load(reader);

        var serial = document.SelectSingleNode("//serial")?.InnerText ?? "unknown";

        return Ok(new { registered = serial });
    }

    // CODE-02 (CWE-287): device authentication is the serial number, which is printed on the
    // outside of the device and sequential. Knowing one device's serial lets you impersonate
    // its neighbours.
    [HttpPost("{serial}/telemetry")]
    public IActionResult Telemetry(string serial, [FromBody] object payload)
    {
        return Accepted(new { serial });
    }

    // CODE-03 (CWE-639): any device can read any other device's configuration, including the
    // provisioning keys inside it.
    [HttpGet("{serial}/config")]
    public IActionResult Config(string serial) =>
        Ok(new { serial, mqttEndpoint = "mqtt://gateway.internal:1883", provisioningKey = "prov-fixture-dummy-000111" });

    // CODE-04 (CWE-319): the MQTT endpoint handed to devices is plaintext, so telemetry and the
    // provisioning key above cross the network unencrypted.
    [HttpGet("bootstrap")]
    public IActionResult Bootstrap() => Ok(new { endpoint = "mqtt://gateway.internal:1883", tls = false });
}
