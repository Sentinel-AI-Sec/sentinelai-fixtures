using BuildRunner.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddSingleton<ArtifactExtractor>();
builder.Services.AddSingleton<ClusterClient>();

var app = builder.Build();

app.MapControllers();

app.Run();
