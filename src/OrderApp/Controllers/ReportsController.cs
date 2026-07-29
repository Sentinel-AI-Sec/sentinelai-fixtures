using System.Xml;
using Microsoft.AspNetCore.Mvc;

namespace OrderApp.Controllers;

[ApiController]
[Route("api/[controller]")]
public class ReportsController : ControllerBase
{
    // CODE-03 (CWE-79): user input reflected directly into an HTML
    // response with no encoding.
    [HttpGet("greeting")]
    public ContentResult Greeting([FromQuery] string name)
    {
        var html = $"<html><body><h1>Welcome, {name}!</h1></body></html>";
        return Content(html, "text/html");
    }

    // CODE-08 (CWE-611): XML parsed with DTD processing enabled and
    // external entity resolution allowed - classic XXE.
    [HttpPost("parse")]
    public IActionResult ParseReportXml([FromBody] string xmlBody)
    {
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Parse,
            XmlResolver = new XmlUrlResolver()
        };

        using var stringReader = new StringReader(xmlBody);
        using var reader = XmlReader.Create(stringReader, settings);

        var doc = new XmlDocument { XmlResolver = new XmlUrlResolver() };
        doc.Load(reader);

        return Ok(new { root = doc.DocumentElement?.Name });
    }

    // CODE-10 (CWE-918): server fetches a caller-supplied URL with no
    // allow-list / host validation - SSRF.
    [HttpGet("fetch-external")]
    public async Task<IActionResult> FetchExternal([FromQuery] string url)
    {
        using var client = new HttpClient();
        var response = await client.GetStringAsync(url);
        return Ok(response);
    }
}
