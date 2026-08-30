namespace MRTDScope.Core.Protocol.Pace;

/// <summary>The key-agreement family a PACE variant uses.</summary>
public enum PaceMapping
{
    /// <summary>Generic Mapping — the nonce maps the base point by a shared secret.</summary>
    Generic,

    /// <summary>Integrated Mapping — the nonce maps directly onto the curve.</summary>
    Integrated,

    /// <summary>Chip Authentication Mapping — Generic Mapping that also authenticates the chip.</summary>
    ChipAuthentication,
}

/// <summary>The cipher and MAC a PACE variant establishes.</summary>
public enum PaceCipher
{
    /// <summary>3DES-CBC with the ISO/IEC 9797-1 retail MAC.</summary>
    TripleDes,

    /// <summary>AES-CBC with CMAC, 128-bit keys.</summary>
    Aes128,

    /// <summary>AES-CBC with CMAC, 192-bit keys.</summary>
    Aes192,

    /// <summary>AES-CBC with CMAC, 256-bit keys.</summary>
    Aes256,
}

/// <summary>
/// The PACE object identifiers, from ICAO Doc 9303 Part 11 §9.2.3.
/// </summary>
/// <remarks>
/// The OID is not decoration: it selects the mapping, the cipher, the key length and the
/// MAC in one value. Parsing it into <see cref="PaceAlgorithm"/> rather than passing the
/// string around keeps every downstream decision derived from what the chip actually
/// advertised.
/// </remarks>
public static class PaceOids
{
    /// <summary>bsi-de protocols(2) smartcard(2) 4.</summary>
    public const string Pace = "0.4.0.127.0.7.2.2.4";

    public const string DhGm = Pace + ".1";
    public const string EcdhGm = Pace + ".2";
    public const string DhIm = Pace + ".3";
    public const string EcdhIm = Pace + ".4";
    public const string EcdhCam = Pace + ".6";

    /// <summary>Chip Authentication, used by DG14 at M5.</summary>
    public const string ChipAuthentication = "0.4.0.127.0.7.2.2.3";

    /// <summary>Active Authentication info, used by DG15 at M5.</summary>
    public const string ActiveAuthentication = "2.23.136.1.1.5";
}

/// <summary>
/// A PACE variant decomposed from its object identifier.
/// </summary>
/// <param name="Oid">The full protocol OID as advertised.</param>
/// <param name="Mapping">How the nonce is mapped.</param>
/// <param name="UsesEllipticCurve">Whether key agreement is ECDH rather than DH.</param>
/// <param name="Cipher">The cipher and MAC the session will use.</param>
public readonly record struct PaceAlgorithm(
    string Oid,
    PaceMapping Mapping,
    bool UsesEllipticCurve,
    PaceCipher Cipher)
{
    /// <summary>
    /// Decomposes a PACE protocol OID, or returns <c>null</c> when it is not one.
    /// </summary>
    public static PaceAlgorithm? FromOid(string oid)
    {
        ArgumentNullException.ThrowIfNull(oid);

        if (!oid.StartsWith(PaceOids.Pace + ".", StringComparison.Ordinal))
        {
            return null;
        }

        string[] tail = oid[(PaceOids.Pace.Length + 1)..].Split('.');

        if (tail.Length != 2
            || !int.TryParse(tail[0], out int family)
            || !int.TryParse(tail[1], out int cipher))
        {
            return null;
        }

        (PaceMapping mapping, bool ec)? selected = family switch
        {
            1 => (PaceMapping.Generic, false),
            2 => (PaceMapping.Generic, true),
            3 => (PaceMapping.Integrated, false),
            4 => (PaceMapping.Integrated, true),
            6 => (PaceMapping.ChipAuthentication, true),
            _ => null,
        };

        if (selected is not { } family2)
        {
            return null;
        }

        PaceCipher? algorithm = cipher switch
        {
            1 => PaceCipher.TripleDes,
            2 => PaceCipher.Aes128,
            3 => PaceCipher.Aes192,
            4 => PaceCipher.Aes256,
            _ => null,
        };

        return algorithm is { } value
            ? new PaceAlgorithm(oid, family2.mapping, family2.ec, value)
            : null;
    }

    /// <summary>Whether this build can execute this variant.</summary>
    /// <remarks>
    /// Generic Mapping over elliptic curves with AES is what deployed documents
    /// overwhelmingly use. Integrated and Chip Authentication Mapping are recognized and
    /// reported rather than silently treated as unsupported — a document that offers only
    /// those deserves a precise answer, not a generic failure (D003).
    /// </remarks>
    public bool IsSupported =>
        Mapping == PaceMapping.Generic
        && UsesEllipticCurve
        && Cipher != PaceCipher.TripleDes;

    public override string ToString() =>
        $"{(UsesEllipticCurve ? "ECDH" : "DH")}-{Mapping}-{Cipher}";
}
