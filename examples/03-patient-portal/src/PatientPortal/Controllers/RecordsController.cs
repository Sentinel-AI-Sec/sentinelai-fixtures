using System.Xml;
using Microsoft.AspNetCore.Mvc;
using PatientPortal.Services;

namespace PatientPortal.Controllers;

/// <summary>
/// Serves patient records, discharge summaries and imaging.
/// </summary>
/// <remarks>
/// The middle of the flagship chain. The authorization here is written correctly — it checks the
/// role and the patient id before returning anything. It is just checking claims that
/// <see cref="TokenValidator"/> never verified, which is why the correctness does not help.
/// </remarks>
[ApiController]
[Route("api/[controller]")]
public class RecordsController : ControllerBase
{
    private readonly TokenValidator _tokens;
    private readonly BlobArchive _archive;

    public RecordsController(TokenValidator tokens, BlobArchive archive)
    {
        _tokens = tokens;
        _archive = archive;
    }

    [HttpGet("{patientId}")]
    public IActionResult Get(string patientId, [FromHeader(Name = "Authorization")] string authorization)
    {
        var token = authorization.Replace("Bearer ", string.Empty, StringComparison.OrdinalIgnoreCase);
        var claims = _tokens.Validate(token);

        // Correct authorization, on claims nobody verified. A forged token saying
        // role=clinician reads every record in the system.
        if (claims.Role != "clinician" && claims.PatientId != patientId)
            return Forbid();

        return Ok(new { patientId, summary = "discharge summary", clinician = claims.Subject });
    }

    // CODE-04 (CWE-611): XXE. The XML reader resolves external entities and has no DTD
    // prohibition, so an uploaded referral document can read files off the container or make
    // the server fetch internal URLs.
    [HttpPost("referral")]
    public IActionResult ImportReferral([FromBody] string referralXml)
    {
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Parse,
            XmlResolver = new XmlUrlResolver(),
        };

        using var stringReader = new StringReader(referralXml);
        using var reader = XmlReader.Create(stringReader, settings);

        var document = new XmlDocument { XmlResolver = new XmlUrlResolver() };
        document.Load(reader);

        return Ok(new { imported = document.DocumentElement?.Name });
    }

    // CODE-05 (CWE-22): path traversal. The document name is concatenated into a blob path with
    // no normalization, so "../" walks out of the patient's own container prefix.
    [HttpGet("{patientId}/documents/{name}")]
    public async Task<IActionResult> GetDocument(string patientId, string name)
    {
        var path = $"{patientId}/{name}";
        var content = await _archive.ReadAsync(path);

        return Ok(new { path, content });
    }

    // CODE-06 (CWE-532): the full record, including identifiers, is written to the application
    // log on every read. Logs in this deployment go to a storage account with a 365-day
    // retention and no access restriction (INFRA-08).
    [HttpGet("{patientId}/audit")]
    public IActionResult Audit(string patientId, [FromServices] ILogger<RecordsController> logger)
    {
        logger.LogInformation(
            "Record access: patient={PatientId} nhsNumber={Nhs} dob={Dob}",
            patientId, "943-476-5919", "1971-04-02");

        return Ok();
    }
}
