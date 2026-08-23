using PatientPortal.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddSingleton<TokenValidator>();
builder.Services.AddSingleton<BlobArchive>();

var app = builder.Build();

// CODE-08 (CWE-319): HTTPS redirection is deliberately not enabled, and the ingress in front of
// this (INFRA-05) terminates on HTTP anyway - so PHI crosses the network in the clear.
app.MapControllers();

app.Run();
