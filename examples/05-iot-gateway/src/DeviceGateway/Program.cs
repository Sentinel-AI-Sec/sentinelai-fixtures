using DeviceGateway.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddSingleton<FirmwareCatalog>();

var app = builder.Build();

app.MapControllers();

app.Run();
