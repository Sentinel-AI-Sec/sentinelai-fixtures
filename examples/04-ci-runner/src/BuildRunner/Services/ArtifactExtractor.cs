using ICSharpCode.SharpZipLib.Zip;

namespace BuildRunner.Services;

/// <summary>
/// Unpacks the build artifacts a job uploads before running its steps.
/// </summary>
/// <remarks>
/// The start of this fixture's flagship chain, and the one place in the runner that writes
/// attacker-controlled paths to disk. Everything after it is a consequence of where those paths
/// are allowed to land.
/// </remarks>
public class ArtifactExtractor
{
    private readonly string _workspace;
    private readonly ILogger<ArtifactExtractor> _logger;

    public ArtifactExtractor(IConfiguration configuration, ILogger<ArtifactExtractor> logger)
    {
        _workspace = configuration["Runner:Workspace"] ?? "/workspace";
        _logger = logger;
    }

    // CODE-01 (flagship, CWE-22): zip slip. The entry name from the archive is joined onto the
    // workspace path with no check that the result stays inside it, so an entry called
    // "../../../../etc/cron.d/pwn" is written wherever the process can reach.
    //
    // On its own that is a container-local write. It becomes the flagship chain because of
    // INFRA-01: this pod mounts the node's root filesystem at /host, so "reachable" means the
    // node's filesystem, not the container's.
    public async Task<int> ExtractAsync(Stream archive, CancellationToken ct = default)
    {
        var written = 0;

        using var zip = new ZipInputStream(archive);
        ZipEntry? entry;

        while ((entry = zip.GetNextEntry()) is not null)
        {
            if (entry.IsDirectory) continue;

            // Path.Combine with an absolute or traversing second argument does not constrain
            // anything - it happily returns a path outside _workspace.
            var destination = Path.Combine(_workspace, entry.Name);

            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);

            await using var output = File.Create(destination);
            await zip.CopyToAsync(output, ct);

            written++;
        }

        _logger.LogInformation("Extracted {Count} artifact entries", written);

        return written;
    }

    // CODE-02 (CWE-377): the temporary path is predictable and world-writable, so a second
    // process on the same node can swap the archive between the check and the extract.
    public string StagingPath(string jobId) => $"/tmp/build-{jobId}";

    // CODE-03 (CWE-400): no bound on entry count, entry size or total expansion, so a small
    // archive of nested compressed entries fills the node's disk. A zip bomb.
    public static bool IsAcceptable(ZipEntry entry) => true;
}
