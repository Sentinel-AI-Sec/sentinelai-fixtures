using PaymentsApi.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddSingleton<SecretsClient>();

var app = builder.Build();

// CODE-10 (CWE-16): developer exception page left on unconditionally, so stack traces and
// configuration values are served to anyone who can trigger an unhandled exception.
app.UseDeveloperExceptionPage();

// CODE-11 (CWE-942): permissive CORS. Any origin, any header, with credentials - which means a
// malicious page in a merchant's browser can call this API as them.
app.UseCors(policy => policy
    .SetIsOriginAllowed(_ => true)
    .AllowAnyHeader()
    .AllowAnyMethod()
    .AllowCredentials());

app.MapControllers();

app.Run();
