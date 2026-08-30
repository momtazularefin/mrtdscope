using MRTDScope.Core.Errors;
using Org.BouncyCastle.Asn1;

namespace MRTDScope.Core.Protocol.Pace;

/// <summary>One entry from a SecurityInfos set.</summary>
/// <param name="Protocol">The protocol object identifier.</param>
/// <param name="RequiredData">The mandatory second element, already decoded.</param>
/// <param name="OptionalData">The optional third element, when present.</param>
public sealed record SecurityInfo(
    string Protocol,
    Asn1Encodable RequiredData,
    Asn1Encodable? OptionalData);

/// <summary>What a chip advertises about PACE, in the form it advertised it.</summary>
/// <param name="Algorithm">The decomposed variant.</param>
/// <param name="Version">Protocol version; 2 for current documents.</param>
/// <param name="ParameterId">
/// Standardized domain-parameter identifier from Doc 9303 Part 11 §9.5.1, when given.
/// </param>
public sealed record PaceInfo(PaceAlgorithm Algorithm, int Version, int? ParameterId)
{
    /// <summary>The named curve for this parameter set, or <c>null</c> when unknown.</summary>
    public string? CurveName => ParameterId is { } id ? PaceDomainParameters.CurveFor(id) : null;
}

/// <summary>
/// The SecurityInfos structure shared by EF.CardAccess and DG14
/// (ICAO Doc 9303 Part 11 §9.2).
/// </summary>
/// <remarks>
/// <c>SecurityInfos ::= SET OF SecurityInfo</c>, and
/// <c>SecurityInfo ::= SEQUENCE { protocol OBJECT IDENTIFIER, requiredData ANY,
/// optionalData ANY OPTIONAL }</c>.
/// <para>
/// The deliberately open shape means a chip may advertise protocols this build has never
/// heard of. Unknown entries are kept rather than discarded, so the inspection can report
/// what a document actually offers instead of silently narrowing it to what happens to be
/// implemented.
/// </para>
/// </remarks>
public sealed class SecurityInfos
{
    private SecurityInfos(IReadOnlyList<SecurityInfo> entries, IReadOnlyList<PaceInfo> paceInfos)
    {
        Entries = entries;
        PaceInfos = paceInfos;
    }

    /// <summary>Every entry, including protocols this build does not implement.</summary>
    public IReadOnlyList<SecurityInfo> Entries { get; }

    /// <summary>The PACE variants the chip advertises.</summary>
    public IReadOnlyList<PaceInfo> PaceInfos { get; }

    /// <summary>Whether the chip advertises PACE at all.</summary>
    public bool SupportsPace => PaceInfos.Count > 0;

    /// <summary>
    /// Whether these SecurityInfos advertise Chip Authentication (M5).
    /// </summary>
    /// <remarks>
    /// Meaningful only when read from <b>DG14</b>. EF.CardAccess carries just the
    /// SecurityInfos a terminal needs before access control — in practice PACE — so
    /// asking it about Chip Authentication yields a confident <c>false</c> that says
    /// nothing about the document. DG14 is where the answer lives, and it sits behind the
    /// secure channel.
    /// </remarks>
    public bool SupportsChipAuthentication => Entries.Any(
        entry => entry.Protocol.StartsWith(PaceOids.ChipAuthentication, StringComparison.Ordinal));

    /// <summary>
    /// Whether these SecurityInfos advertise Active Authentication (M5). As with
    /// <see cref="SupportsChipAuthentication"/>, only DG14 can answer this.
    /// </summary>
    public bool SupportsActiveAuthentication => Entries.Any(
        entry => entry.Protocol.StartsWith(PaceOids.ActiveAuthentication, StringComparison.Ordinal));

    /// <summary>
    /// Whether more than one set of domain parameters is on offer.
    /// </summary>
    /// <remarks>
    /// This decides whether MSE:Set AT carries the domain-parameter reference. Doc 9303
    /// Part 11 §4.4.4.1 makes tag 0x84 <b>conditional</b>: required only when the
    /// parameters are ambiguous. Sending it to a chip offering a single set asks it to
    /// resolve a reference it has no table for, and the documented answer is 6A88,
    /// "referenced data not found".
    /// </remarks>
    public bool DomainParametersAreAmbiguous =>
        PaceInfos.Select(info => info.ParameterId).Distinct().Count() > 1;

    /// <summary>
    /// The PACE variant this build should attempt, preferring the strongest supported
    /// cipher, or <c>null</c> when none is executable.
    /// </summary>
    public PaceInfo? PreferredPace => PaceInfos
        .Where(info => info.Algorithm.IsSupported)
        .OrderByDescending(info => info.Algorithm.Cipher)
        .FirstOrDefault();

    /// <summary>Parses a DER-encoded SecurityInfos set.</summary>
    public static SecurityInfos Parse(ReadOnlySpan<byte> encoded)
    {
        Asn1Object root;
        try
        {
            root = Asn1Object.FromByteArray(encoded.ToArray());
        }
        catch (Exception exception) when (exception is IOException or ArgumentException)
        {
            throw new MrtdEncodingException("SecurityInfos is not well-formed DER.", exception);
        }

        // Doc 9303 specifies a SET, but chips have been observed emitting a SEQUENCE.
        // Accepting both costs nothing and avoids rejecting a readable document over a
        // constructed-type nicety.
        IEnumerable<Asn1Encodable> items = root switch
        {
            Asn1Set set => set.Cast<Asn1Encodable>(),
            Asn1Sequence sequence => sequence.Cast<Asn1Encodable>(),
            _ => throw new MrtdEncodingException(
                $"SecurityInfos must be a SET or SEQUENCE; found {root.GetType().Name}."),
        };

        List<SecurityInfo> entries = [];
        List<PaceInfo> paceInfos = [];

        foreach (Asn1Encodable item in items)
        {
            if (item is not Asn1Sequence entry || entry.Count < 2)
            {
                continue;
            }

            if (entry[0] is not DerObjectIdentifier oid)
            {
                continue;
            }

            SecurityInfo info = new(
                oid.Id,
                entry[1],
                entry.Count > 2 ? entry[2] : null);

            entries.Add(info);

            if (PaceAlgorithm.FromOid(oid.Id) is { } algorithm)
            {
                paceInfos.Add(ToPaceInfo(algorithm, info));
            }
        }

        return new SecurityInfos(entries, paceInfos);
    }

    private static PaceInfo ToPaceInfo(PaceAlgorithm algorithm, SecurityInfo info)
    {
        int version = info.RequiredData is DerInteger versionValue
            ? versionValue.IntValueExact
            : 0;

        int? parameterId = info.OptionalData is DerInteger parameter
            ? parameter.IntValueExact
            : null;

        return new PaceInfo(algorithm, version, parameterId);
    }
}

/// <summary>
/// The standardized domain parameters of ICAO Doc 9303 Part 11 §9.5.1, Table
/// "Standardized Domain Parameters".
/// </summary>
public static class PaceDomainParameters
{
    private static readonly Dictionary<int, string> Curves = new()
    {
        [8] = "secp192r1",
        [9] = "brainpoolP192r1",
        [10] = "secp224r1",
        [11] = "brainpoolP224r1",
        [12] = "secp256r1",
        [13] = "brainpoolP256r1",
        [14] = "brainpoolP320r1",
        [15] = "secp384r1",
        [16] = "brainpoolP384r1",
        [17] = "brainpoolP512r1",
        [18] = "secp521r1",
    };

    /// <summary>
    /// The named elliptic curve for a parameter identifier, or <c>null</c>.
    /// </summary>
    /// <remarks>
    /// Identifiers 0 to 2 are finite-field MODP groups rather than curves, and 3 to 7 and
    /// 19 to 31 are reserved. Returning null for those is correct: they are not curves,
    /// and inventing one would be worse than saying so.
    /// </remarks>
    public static string? CurveFor(int parameterId) =>
        Curves.TryGetValue(parameterId, out string? curve) ? curve : null;

    /// <summary>Whether an identifier denotes an elliptic curve this build can use.</summary>
    public static bool IsSupportedCurve(int parameterId) => Curves.ContainsKey(parameterId);
}
