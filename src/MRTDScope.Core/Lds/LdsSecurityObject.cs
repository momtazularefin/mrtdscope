using MRTDScope.Core.Errors;
using Org.BouncyCastle.Asn1;

namespace MRTDScope.Core.Lds;

/// <summary>
/// The LDS Security Object: the signed list of data-group digests that makes tampering
/// detectable (ICAO Doc 9303 Part 10 §4.6.2).
/// </summary>
/// <remarks>
/// ASN.1 per Doc 9303 Part 10:
/// <c>LDSSecurityObject ::= SEQUENCE { version, hashAlgorithm, dataGroupHashValues,
/// ldsVersionInfo OPTIONAL }</c>.
/// <para>
/// This object is the whole point of Passive Authentication. Verifying the SOD's
/// signature proves the issuer signed <em>this list of digests</em>; it says nothing
/// about whether the data groups on the chip still match them. That comparison is
/// <see cref="Verification.PassiveAuthenticator"/>'s third check, and skipping it is the
/// defect that lets a substituted portrait pass (D004).
/// </para>
/// </remarks>
public sealed class LdsSecurityObject
{
    private LdsSecurityObject(
        int version,
        string digestAlgorithmOid,
        IReadOnlyDictionary<int, ReadOnlyMemory<byte>> dataGroupHashes,
        string? ldsVersion,
        string? unicodeVersion)
    {
        Version = version;
        DigestAlgorithmOid = digestAlgorithmOid;
        DataGroupHashes = dataGroupHashes;
        LdsVersion = ldsVersion;
        UnicodeVersion = unicodeVersion;
    }

    /// <summary>Security object version: 0 for V0, 1 for V1.</summary>
    public int Version { get; }

    /// <summary>OID of the digest algorithm covering every data group.</summary>
    public string DigestAlgorithmOid { get; }

    /// <summary>Data-group number to its expected digest.</summary>
    public IReadOnlyDictionary<int, ReadOnlyMemory<byte>> DataGroupHashes { get; }

    /// <summary>LDS version from the optional ldsVersionInfo, present only in V1.</summary>
    public string? LdsVersion { get; }

    /// <summary>Unicode version from the optional ldsVersionInfo.</summary>
    public string? UnicodeVersion { get; }

    /// <summary>The data groups this security object protects.</summary>
    public IReadOnlyList<int> ProtectedDataGroups => [.. DataGroupHashes.Keys.Order()];

    /// <summary>Parses the DER-encoded eContent of the SOD's SignedData.</summary>
    public static LdsSecurityObject Parse(ReadOnlySpan<byte> encodedContent)
    {
        Asn1Sequence sequence;
        try
        {
            sequence = Asn1Sequence.GetInstance(Asn1Object.FromByteArray(encodedContent.ToArray()));
        }
        catch (Exception exception) when (exception is IOException or ArgumentException or InvalidCastException)
        {
            throw new MrtdEncodingException(
                "The security object content is not a well-formed LDSSecurityObject.", exception);
        }

        if (sequence.Count < 3)
        {
            throw new MrtdEncodingException(
                $"LDSSecurityObject requires at least 3 elements; found {sequence.Count}.");
        }

        int version = DerInteger.GetInstance(sequence[0]).IntValueExact;

        Asn1Sequence algorithm = Asn1Sequence.GetInstance(sequence[1]);
        string digestOid = DerObjectIdentifier.GetInstance(algorithm[0]).Id;

        Asn1Sequence hashValues = Asn1Sequence.GetInstance(sequence[2]);
        Dictionary<int, ReadOnlyMemory<byte>> hashes = [];

        foreach (Asn1Encodable entry in hashValues)
        {
            Asn1Sequence pair = Asn1Sequence.GetInstance(entry);

            if (pair.Count < 2)
            {
                throw new MrtdEncodingException("A DataGroupHash entry is missing its digest.");
            }

            int number = DerInteger.GetInstance(pair[0]).IntValueExact;
            byte[] digest = Asn1OctetString.GetInstance(pair[1]).GetOctets();

            // A chip that lists the same data group twice with different digests is
            // making the comparison ambiguous. Refuse rather than pick one.
            if (!hashes.TryAdd(number, digest))
            {
                throw new MrtdEncodingException(
                    $"The security object lists DG{number} more than once.");
            }
        }

        if (hashes.Count == 0)
        {
            throw new MrtdEncodingException("The security object protects no data groups.");
        }

        string? ldsVersion = null;
        string? unicodeVersion = null;

        if (sequence.Count > 3 && sequence[3] is Asn1Sequence versionInfo && versionInfo.Count >= 2)
        {
            ldsVersion = DerPrintableString.GetInstance(versionInfo[0]).GetString();
            unicodeVersion = DerPrintableString.GetInstance(versionInfo[1]).GetString();
        }

        return new LdsSecurityObject(version, digestOid, hashes, ldsVersion, unicodeVersion);
    }
}
