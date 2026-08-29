using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace WebApplicationAPI.Services;

/// <summary>
/// Provides centralized management for asymmetric RSA cryptographic keys used in JWT signing and validation.
/// </summary>
public static class RsaKeyManager
{
    private static readonly RSA Rsa;

    /// <summary>
    /// Gets the asymmetric RSA private key used for digital token signing.
    /// </summary>
    public static RsaSecurityKey PrivateKey { get; }

    /// <summary>
    /// Gets the asymmetric RSA public key used for token signature validation.
    /// </summary>
    public static RsaSecurityKey PublicKey { get; }

    /// <summary>
    /// Static constructor to initialize 2048-bit RSA keys upon application startup.
    /// </summary>
    static RsaKeyManager()
    {
        // Generate a 2048-bit RSA key pair instance
        Rsa = RSA.Create(2048);

        // Private key initialization for token signing operations
        PrivateKey = new RsaSecurityKey(Rsa);

        // Public key initialization containing parameters required for token verification
        PublicKey = new RsaSecurityKey(Rsa.ExportParameters(false));
    }
}