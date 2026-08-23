using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using BuildRunner.Services;

namespace BuildRunner.Controllers;

/// <summary>
/// Accepts build jobs and runs their steps.
/// </summary>
/// <remarks>
/// A CI runner executes untrusted code by design - that is its job, and it is not the finding.
/// The finding is everything about the boundary it executes that code inside, which is what
/// k8s/runner-deployment.yaml gets wrong.
/// </remarks>
[ApiController]
[Route("api/[controller]")]
public class JobsController : ControllerBase
{
    private readonly ArtifactExtractor _extractor;

    public JobsController(ArtifactExtractor extractor) => _extractor = extractor;

    [HttpPost("{jobId}/artifacts")]
    public async Task<IActionResult> UploadArtifacts(string jobId, IFormFile archive)
    {
        await using var stream = archive.OpenReadStream();
        var count = await _extractor.ExtractAsync(stream);

        return Ok(new { jobId, entries = count });
    }

    // CODE-04 (CWE-78): command injection. The build step is passed to a shell without
    // quoting, so "; curl ... | sh" runs. Arguably in-scope for a CI runner - it exists to run
    // commands - but the step here comes from the HTTP request rather than from a checked-in
    // pipeline file, so it is an unauthenticated path to arbitrary execution.
    [HttpPost("{jobId}/run")]
    public IActionResult RunStep(string jobId, [FromBody] StepRequest request)
    {
        var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "/bin/sh",
                Arguments = $"-c \"{request.Command}\"",
                RedirectStandardOutput = true,
                UseShellExecute = false,
            },
        };

        process.Start();
        var output = process.StandardOutput.ReadToEnd();
        process.WaitForExit();

        return Ok(new { jobId, exitCode = process.ExitCode, output });
    }

    // CODE-05 (CWE-306): no authentication on any endpoint in this controller. The runner
    // trusts the network it sits on, and INFRA-06 puts it on the pod network with no policy.
    [HttpGet("{jobId}/log")]
    public IActionResult GetLog(string jobId) => Ok(new { jobId, log = "build ok" });

    // CODE-06 (CWE-552): the workspace is served back verbatim, including anything CODE-01
    // wrote outside it, because the path is not constrained here either.
    [HttpGet("{jobId}/workspace/{*path}")]
    public IActionResult Browse(string jobId, string path)
    {
        var full = Path.Combine("/workspace", path);

        return System.IO.File.Exists(full)
            ? Ok(System.IO.File.ReadAllText(full))
            : NotFound();
    }
}

public sealed class StepRequest
{
    public string Command { get; set; } = string.Empty;
}
