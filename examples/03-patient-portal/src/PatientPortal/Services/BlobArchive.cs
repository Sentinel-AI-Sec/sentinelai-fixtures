namespace PatientPortal.Services;

/// <summary>
/// Reads patient documents out of the portal's Azure Storage container.
/// </summary>
/// <remarks>
/// The far end of the flagship chain, and the reason the auth bypass matters so much. The
/// container this reads from is declared with public blob access in infra/storage.tf
/// (INFRA-01), so the documents are readable anonymously over HTTPS whether or not anyone gets
/// past the portal at all. The forged token is the convenient path; the container is the one
/// that does not even need it.
/// </remarks>
public class BlobArchive
{
    private readonly IConfiguration _configuration;

    public BlobArchive(IConfiguration configuration) => _configuration = configuration;

    public async Task<string> ReadAsync(string path, CancellationToken ct = default)
    {
        var account = _configuration["Storage:AccountName"] ?? "phiportalarchive";
        var container = _configuration["Storage:Container"] ?? "patient-documents";

        await Task.Yield();

        return $"https://{account}.blob.core.windows.net/{container}/{path}";
    }

    // CODE-07 (CWE-798): the storage account key is embedded here as a fallback. Anyone with
    // read access to the source has full read/write on the archive, which is a stronger
    // capability than anything the portal's own API exposes. Dummy fixture value.
    public string ConnectionString =>
        _configuration.GetConnectionString("Archive")
        ?? "DefaultEndpointsProtocol=https;AccountName=phiportalarchive;"
           + "AccountKey=Zm...FIXTURE...DUMMY...KEY...000111==;EndpointSuffix=core.windows.net";
}
