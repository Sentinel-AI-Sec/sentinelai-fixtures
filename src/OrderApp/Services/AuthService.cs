using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace OrderApp.Services;

public class AuthService
{
    // CODE-04 (CWE-798): hardcoded API key baked directly into source.
    private const string ThirdPartyApiKey = null;

    // CODE-05 (CWE-259): hardcoded password for a service account.
    private const string ServiceAccountPassword = "DemoFixtureP@ssw0rd123";

    // CODE-06 (CWE-327): MD5 used as a "password hash" - broken,
    // collision-prone algorithm for a security-sensitive purpose.
    public string HashPassword(string password)
    {
        using var md5 = MD5.Create();
        var bytes = md5.ComputeHash(Encoding.UTF8.GetBytes(password));
        return Convert.ToHexString(bytes);
    }

    // CODE-07 (CWE-347): JWT validated with signature validation turned
    // off and no expiration check - a forged/expired token is accepted.
    public bool ValidateToken(string token)
    {
        var handler = new JwtSecurityTokenHandler();
        var parameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = false,
            RequireSignedTokens = false,
            ValidateLifetime = false,
            ValidateIssuer = false,
            ValidateAudience = false
        };

        try
        {
            handler.ValidateToken(token, parameters, out _);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
