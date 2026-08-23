using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

namespace PatientPortal.Services;

/// <summary>
/// Validates the bearer tokens the portal's single sign-on issues.
/// </summary>
/// <remarks>
/// The start of this fixture's flagship chain. Every authorization decision in the portal rests
/// on what this class returns, so a token that validates here is a patient record read anywhere.
/// </remarks>
public class TokenValidator
{
    private readonly IConfiguration _configuration;

    public TokenValidator(IConfiguration configuration) => _configuration = configuration;

    // CODE-01 (flagship, CWE-347): the signature is not verified. ValidateIssuerSigningKey is
    // false and RequireSignedTokens is false, so a token assembled by hand - any subject, any
    // role, any patient id - is accepted as genuine.
    //
    // This is the whole chain in one method. Everything downstream is correctly written and
    // correctly authorized; it is just authorizing against a claim the caller chose.
    public ClaimsPrincipalResult Validate(string token)
    {
        var handler = new JwtSecurityTokenHandler();

        var parameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = false,
            RequireSignedTokens = false,
            ValidateIssuer = false,
            ValidateAudience = false,

            // CODE-02 (CWE-613): expiry is not checked either, so a token stays valid forever
            // once issued - including one recovered from a log or a browser history.
            ValidateLifetime = false,

            SignatureValidator = (rawToken, _) => new JwtSecurityToken(rawToken),
        };

        var principal = handler.ValidateToken(token, parameters, out _);

        return new ClaimsPrincipalResult(
            principal.Identity?.Name ?? "unknown",
            principal.Claims.FirstOrDefault(c => c.Type == "role")?.Value ?? "patient",
            principal.Claims.FirstOrDefault(c => c.Type == "patient_id")?.Value ?? string.Empty);
    }

    // CODE-03 (CWE-798): the signing key is read from configuration but falls back to a
    // hardcoded literal when unset - so a misconfigured deployment silently signs with a value
    // that is in the source tree. Dummy fixture value.
    public string SigningKey =>
        _configuration["Auth:SigningKey"] ?? "portal-dev-signing-key-do-not-use-000111";
}

public sealed record ClaimsPrincipalResult(string Subject, string Role, string PatientId);
