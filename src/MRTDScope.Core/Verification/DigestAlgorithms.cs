using System.Security.Cryptography;

namespace MRTDScope.Core.Verification;

/// <summary>
/// Maps the digest OIDs that appear in security objects to concrete hash algorithms.
/// </summary>
/// <remarks>
/// SHA-1 is included deliberately. A large population of in-service passports was issued
/// with SHA-1 security objects, and an inspection tool that cannot compute the digest a
/// document actually uses is useless on those documents. What matters is that MRTDScope
/// never <em>chooses</em> SHA-1 — it only recomputes whatever the issuer signed with, in
/// order to detect tampering. That is a collision-irrelevant use.
/// </remarks>
public static class DigestAlgorithms
{
    public const string Sha1 = "1.3.14.3.2.26";
    public const string Sha224 = "2.16.840.1.101.3.4.2.4";
    public const string Sha256 = "2.16.840.1.101.3.4.2.1";
    public const string Sha384 = "2.16.840.1.101.3.4.2.2";
    public const string Sha512 = "2.16.840.1.101.3.4.2.3";

    /// <summary>Resolves a digest OID to its algorithm name.</summary>
    /// <exception cref="NotSupportedException">The OID is unknown to this build.</exception>
    public static HashAlgorithmName Resolve(string oid) => oid switch
    {
        Sha1 => HashAlgorithmName.SHA1,
        Sha256 => HashAlgorithmName.SHA256,
        Sha384 => HashAlgorithmName.SHA384,
        Sha512 => HashAlgorithmName.SHA512,
        _ => throw new NotSupportedException($"Unsupported digest algorithm OID '{oid}'."),
    };

    /// <summary>Computes a digest with the named algorithm.</summary>
    public static byte[] ComputeHash(HashAlgorithmName algorithm, ReadOnlySpan<byte> data)
    {
        if (algorithm == HashAlgorithmName.SHA1)
        {
            return SHA1.HashData(data);
        }

        if (algorithm == HashAlgorithmName.SHA256)
        {
            return SHA256.HashData(data);
        }

        if (algorithm == HashAlgorithmName.SHA384)
        {
            return SHA384.HashData(data);
        }

        if (algorithm == HashAlgorithmName.SHA512)
        {
            return SHA512.HashData(data);
        }

        throw new NotSupportedException($"Unsupported digest algorithm '{algorithm.Name}'.");
    }
}
