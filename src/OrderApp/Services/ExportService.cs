namespace OrderApp.Services;

public class ExportService
{
    private readonly string _exportBasePath = "/app/exports/";

    // CODE-09 (CWE-22): file name comes straight from caller input and is
    // concatenated into a filesystem path with no sanitization - a
    // "../../etc/passwd"-style value escapes the intended directory.
    public string ReadExportFile(string fileName)
    {
        var fullPath = _exportBasePath + fileName;
        return File.ReadAllText(fullPath);
    }
}
