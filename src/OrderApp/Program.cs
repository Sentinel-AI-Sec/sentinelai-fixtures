using OrderApp.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddSingleton<AuthService>();
builder.Services.AddSingleton<ExportService>();
builder.Services.AddSingleton<PricingService>();

var app = builder.Build();

// CODE-11 (CWE-732): export directory created with world-writable
// permissions at startup - any local user/process can tamper with
// exported reports.
var exportDir = "/app/exports/";
Directory.CreateDirectory(exportDir);
if (OperatingSystem.IsLinux())
{
    File.SetUnixFileMode(exportDir,
        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
        UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
        UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute);
}

app.MapControllers();
app.Run();
