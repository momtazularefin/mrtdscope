using System.Diagnostics;
using MRTDScope.Core.Apdu;
using MRTDScope.Core.Errors;
using MRTDScope.Core.Lds;
using MRTDScope.Core.Mrz;
using MRTDScope.Core.Protocol;
using MRTDScope.Core.Protocol.Bac;
using MRTDScope.Core.Protocol.Pace;
using MRTDScope.Core.Protocol.SecureMessaging;
using MRTDScope.Core.Transport;
using MRTDScope.Core.Verification;

namespace MRTDScope.Core.Inspection;

/// <summary>
/// What an inspection recovered from the chip, alongside its report.
/// </summary>
/// <param name="Report">Every check, in order.</param>
/// <param name="Mrz">DG1 as read, when it could be parsed.</param>
/// <param name="Portrait">The DG2 portrait, when present and parseable.</param>
/// <param name="DataGroupsRead">Raw content of every data group successfully read.</param>
public sealed record InspectionOutcome(
    InspectionReport Report,
    MrzInfo? Mrz,
    FaceImage? Portrait,
    IReadOnlyDictionary<int, ReadOnlyMemory<byte>> DataGroupsRead);

/// <summary>
/// Drives a complete inspection: select, access control, read, verify, report.
/// </summary>
/// <remarks>
/// The session never throws for a document that fails inspection. Anything the document
/// does wrong becomes a reported check (NFR5), because a border officer needs a reading,
/// not a stack trace. Exceptions escape only for a genuine transport breakdown.
/// </remarks>
public sealed class InspectionSession
{
    private readonly TrustStore _trustStore;
    private readonly TimeProvider _timeProvider;

    public InspectionSession(TrustStore trustStore, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(trustStore);

        _trustStore = trustStore;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>
    /// Inspects the document on the given transport using an MRZ-derived key.
    /// </summary>
    public InspectionOutcome Inspect(ICardTransport transport, MrzKey mrzKey)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(mrzKey);

        long startedAt = Stopwatch.GetTimestamp();
        List<InspectionCheck> checks = [];

        // Order matters and is not arbitrary. ICAO Doc 9303 Part 11 numbers the
        // inspection flow: read EF.CardAccess, then PACE, then select the eMRTD
        // application, then BAC only if PACE was not used. PACE establishes its security
        // context in the Master File (§4.4), so attempting it after selecting the
        // application asks the chip to do something it cannot, and a real chip answers
        // 6985 — "conditions of use not satisfied".
        ChipCapabilities capabilities = ChipCapabilityProbe.Probe(transport);
        PaceInfo? paceInfo = capabilities.SecurityInfos?.PreferredPace;

        ISecureMessaging? channel = null;

        // Step 2: PACE, at the Master File, before any application is selected. It is
        // preferred over BAC because the BAC key derives entirely from MRZ data with low
        // enough entropy to attack offline from a recorded session.
        if (paceInfo is not null)
        {
            PaceResult pace = PaceProtocol
                .FromMrz(
                    paceInfo,
                    mrzKey,
                    domainParametersAreAmbiguous:
                        capabilities.SecurityInfos!.DomainParametersAreAmbiguous)
                .Establish(transport);

            checks.Add(pace.Succeeded
                ? InspectionCheck.Passed(
                    CheckIds.AccessControlPace,
                    pace.Detail,
                    Evidence.Of("algorithm", pace.SecureMessaging!.Algorithm),
                    Evidence.Of("variant", paceInfo.Algorithm.ToString()),
                    Evidence.Of("curve", paceInfo.CurveName ?? "unknown"))
                : InspectionCheck.Failed(
                    CheckIds.AccessControlPace,
                    pace.FailureReason ?? ReasonCodes.AccessDenied,
                    pace.Detail));

            channel = pace.SecureMessaging;
        }
        else
        {
            checks.Add(DescribePaceSupport(capabilities));
        }

        // Step 3: select the eMRTD application — through the PACE channel when one
        // exists, because PACE has already restricted access to require secure messaging.
        ICardTransport applicationTransport = channel is null
            ? transport
            : new SecureMessagingTransport(transport, channel);

        ResponseApdu selected = MrtdApplication.Select(applicationTransport);

        if (!selected.IsSuccess)
        {
            checks.Add(InspectionCheck.Failed(
                CheckIds.AccessControlBac,
                ReasonCodes.TransportFailure,
                $"The eMRTD application could not be selected; the chip returned " +
                $"{selected.StatusWord}."));

            return Finish(checks, startedAt, null, null, new Dictionary<int, ReadOnlyMemory<byte>>());
        }

        // Step 4: BAC, only when PACE did not establish the session.
        if (channel is null)
        {
            BacResult bac = new BacProtocol(mrzKey).Authenticate(transport);

            checks.Add(bac.Succeeded
                ? InspectionCheck.Passed(
                    CheckIds.AccessControlBac,
                    bac.Detail,
                    Evidence.Of("algorithm", bac.SecureMessaging!.Algorithm))
                : InspectionCheck.Failed(
                    CheckIds.AccessControlBac,
                    bac.FailureReason ?? ReasonCodes.AccessDenied,
                    bac.Detail));

            channel = bac.SecureMessaging;
        }
        else
        {
            checks.Add(InspectionCheck.NotApplicable(
                CheckIds.AccessControlBac,
                ReasonCodes.ProtocolNotOffered,
                "PACE established the session, so the weaker BAC path was not used."));
        }

        if (channel is null)
        {
            return Finish(checks, startedAt, null, null, new Dictionary<int, ReadOnlyMemory<byte>>());
        }

        using SecureMessagingTransport secure = new(transport, channel);
        LdsReader reader = new(secure);

        Dictionary<int, ReadOnlyMemory<byte>> dataGroups = [];
        MrzInfo? mrz = null;
        FaceImage? portrait = null;

        try
        {
            checks.AddRange(ReadAndVerify(reader, dataGroups, ref mrz, ref portrait));

            // Retrospective, and required by Doc 9303 Part 11: the unsigned file the
            // session was negotiated from must agree with the signed copy in DG14.
            checks.Add(CheckCardAccessAuthenticity(capabilities, dataGroups));
        }
        catch (SecureMessagingException exception)
        {
            // The channel's integrity broke mid-session. Nothing read after this point
            // could be trusted, so the session ends here — but it ends with a report.
            checks.Add(InspectionCheck.Failed(
                CheckIds.SecureMessaging,
                ReasonCodes.SecureMessagingIntegrity,
                exception.Message));
        }

        return Finish(checks, startedAt, mrz, portrait, dataGroups);
    }

    private IEnumerable<InspectionCheck> ReadAndVerify(
        LdsReader reader,
        Dictionary<int, ReadOnlyMemory<byte>> dataGroups,
        ref MrzInfo? mrz,
        ref FaceImage? portrait)
    {
        List<InspectionCheck> checks = [];

        LdsReader.ReadResult sodFile = reader.ReadFile(DataGroup.Sod);

        if (!sodFile.Success)
        {
            checks.Add(InspectionCheck.Failed(
                CheckIds.PassiveAuthSodSignature,
                ReasonCodes.DataGroupAbsent,
                $"EF.SOD could not be read, so Passive Authentication is impossible. " +
                sodFile.Detail));
            return checks;
        }

        EfSod sod;
        try
        {
            sod = EfSod.Parse(sodFile.Content.Span);
        }
        catch (MrtdEncodingException exception)
        {
            checks.Add(InspectionCheck.Failed(
                CheckIds.PassiveAuthSodSignature,
                ReasonCodes.MalformedData,
                $"EF.SOD could not be parsed: {exception.Message}"));
            return checks;
        }

        checks.Add(CheckComSodConsistency(reader, sod));

        // Read exactly what the security object protects. EF.COM is unsigned, so it is
        // read for comparison but never used to decide what to verify.
        foreach (int number in sod.SecurityObject.ProtectedDataGroups)
        {
            DataGroup? group = DataGroup.FromNumber(number);

            if (group is null || group.RequiresExtendedAccessControl)
            {
                continue;
            }

            LdsReader.ReadResult file = reader.ReadFile(group);

            if (!file.Success)
            {
                continue;
            }

            dataGroups[number] = file.Content;

            if (number == 1)
            {
                mrz = TryParse(() => MrzInfo.Parse(file.Content.Span));
            }
            else if (number == 2)
            {
                portrait = TryParse(() => FacialRecord.Parse(file.Content.Span))?.Primary;
            }
        }

        checks.AddRange(new PassiveAuthenticator(_trustStore, _timeProvider)
            .Verify(sod, dataGroups));

        return checks;
    }

    /// <summary>
    /// Reports the chip's PACE posture from what it advertised, not from assumption.
    /// </summary>
    /// <remarks>
    /// Three genuinely different answers hide behind "PACE did not run", and an operator
    /// needs to tell them apart: the chip does not offer it, the chip offers a variant
    /// this build cannot execute, or this build has not implemented the protocol yet.
    /// Reporting all three as one status would be the same conflation D003 forbids.
    /// </remarks>
    private static InspectionCheck DescribePaceSupport(ChipCapabilities capabilities)
    {
        if (!capabilities.CardAccessPresent)
        {
            return InspectionCheck.NotApplicable(
                CheckIds.AccessControlPace,
                ReasonCodes.ProtocolNotOffered,
                capabilities.Detail);
        }

        SecurityInfos? infos = capabilities.SecurityInfos;

        if (infos is null || !infos.SupportsPace)
        {
            return InspectionCheck.NotApplicable(
                CheckIds.AccessControlPace,
                ReasonCodes.ProtocolNotOffered,
                capabilities.Detail);
        }

        string advertised = string.Join(
            ", ",
            infos.PaceInfos.Select(info =>
                info.CurveName is null
                    ? info.Algorithm.ToString()
                    : $"{info.Algorithm} on {info.CurveName}"));

        return InspectionCheck.Unavailable(
            CheckIds.AccessControlPace,
            ReasonCodes.NotImplemented,
            $"The chip advertises PACE ({advertised}), but this build does not yet " +
            "execute it. Access control fell back to BAC.",
            Evidence.Of("advertised", advertised));
    }


    /// <summary>
    /// Verifies EF.CardAccess against the signed copy of the same information in DG14.
    /// </summary>
    /// <remarks>
    /// ICAO Doc 9303 Part 11 requires this: an inspection system MUST verify the contents
    /// of EF.CardAccess using DG14. The reason is that EF.CardAccess is <b>unsigned</b>
    /// and readable before any authentication, while DG14 carries the same SecurityInfos
    /// and is covered by the Document Security Object.
    /// <para>
    /// That asymmetry is a downgrade path. An attacker who can present a modified
    /// EF.CardAccess can strip the strong PACE variant from it, leaving a weaker one the
    /// terminal then negotiates in good faith — and nothing in the session itself would
    /// ever reveal it, because the weaker session is cryptographically sound. Only
    /// comparing against the signed record exposes it, and only after the fact.
    /// </para>
    /// <para>
    /// The check is therefore retrospective by nature: it cannot prevent the downgrade,
    /// it reports that one occurred. Saying so precisely is the point.
    /// </para>
    /// </remarks>
    private static InspectionCheck CheckCardAccessAuthenticity(
        ChipCapabilities capabilities,
        IReadOnlyDictionary<int, ReadOnlyMemory<byte>> dataGroups)
    {
        if (capabilities.SecurityInfos is not { } advertised)
        {
            return InspectionCheck.NotApplicable(
                CheckIds.LdsCardAccessAuthenticity,
                ReasonCodes.ProtocolNotOffered,
                "The chip carries no EF.CardAccess, so there is nothing to cross-check.");
        }

        if (!dataGroups.TryGetValue(14, out ReadOnlyMemory<byte> dg14Content))
        {
            return InspectionCheck.Inconclusive(
                CheckIds.LdsCardAccessAuthenticity,
                ReasonCodes.DataGroupAbsent,
                "DG14 was not read, so EF.CardAccess cannot be checked against a signed " +
                "copy. Its contents remain unverified.");
        }

        SecurityInfos signed;
        try
        {
            IReadOnlyList<Tlv.BerTlv> wrapper = Tlv.BerTlv.Parse(dg14Content.Span);
            Tlv.BerTlv? inner = Tlv.BerTlv.Find(wrapper, DataGroup.Dg14.Tag);

            if (inner is null)
            {
                return InspectionCheck.Inconclusive(
                    CheckIds.LdsCardAccessAuthenticity,
                    ReasonCodes.MalformedData,
                    "DG14 is not wrapped in its expected tag, so it could not be compared.");
            }

            signed = SecurityInfos.Parse(inner.Value.Span);
        }
        catch (MrtdEncodingException exception)
        {
            return InspectionCheck.Inconclusive(
                CheckIds.LdsCardAccessAuthenticity,
                ReasonCodes.MalformedData,
                $"DG14 could not be parsed: {exception.Message}");
        }

        // Compare the PACE offers by variant and domain parameters together: the same
        // algorithm on a weaker curve is still a downgrade.
        HashSet<string> advertisedPace = Describe(advertised);
        HashSet<string> signedPace = Describe(signed);

        string[] onlySigned = [.. signedPace.Except(advertisedPace).Order()];
        string[] onlyAdvertised = [.. advertisedPace.Except(signedPace).Order()];

        List<Evidence> evidence =
        [
            Evidence.Of("ef.cardaccess", advertisedPace.Count == 0
                ? "none" : string.Join(", ", advertisedPace.Order())),
            Evidence.Of("dg14-signed", signedPace.Count == 0
                ? "none" : string.Join(", ", signedPace.Order())),
        ];

        // The dangerous direction: the signed record offers something the unsigned file
        // withheld, so the terminal was steered away from a protocol the issuer provided.
        if (onlySigned.Length > 0)
        {
            return InspectionCheck.Failed(
                CheckIds.LdsCardAccessAuthenticity,
                ReasonCodes.ProtocolDowngrade,
                $"DG14 is signed by the issuer and offers {string.Join(", ", onlySigned)}, " +
                "but EF.CardAccess did not advertise " +
                (onlySigned.Length == 1 ? "it" : "them") +
                ". EF.CardAccess is unsigned, so this is consistent with an attacker " +
                "removing the stronger option to force a weaker session.",
                [.. evidence]);
        }

        if (onlyAdvertised.Length > 0)
        {
            return InspectionCheck.Failed(
                CheckIds.LdsCardAccessAuthenticity,
                ReasonCodes.UnsignedContent,
                $"EF.CardAccess advertises {string.Join(", ", onlyAdvertised)}, which the " +
                "issuer never signed into DG14. That offer carries no authority.",
                [.. evidence]);
        }

        return InspectionCheck.Passed(
            CheckIds.LdsCardAccessAuthenticity,
            "EF.CardAccess matches the signed copy of the same information in DG14, so the " +
            "protocol offer the session was negotiated from is authentic.",
            [.. evidence]);
    }

    /// <summary>Renders a chip's PACE offers as comparable strings.</summary>
    private static HashSet<string> Describe(SecurityInfos infos) =>
        [.. infos.PaceInfos.Select(info =>
            $"{info.Algorithm}/{info.CurveName ?? info.ParameterId?.ToString(
                System.Globalization.CultureInfo.InvariantCulture) ?? "unspecified"}")];

    /// <summary>
    /// Compares what EF.COM advertises against what the security object actually protects.
    /// </summary>
    /// <remarks>
    /// This is the only reason to read EF.COM at all. EF.COM is unsigned, so it proves
    /// nothing by itself — but a data group the chip advertises and the issuer never
    /// signed is content nobody vouched for, and the hash check cannot see it: the
    /// security object simply has nothing to say about a group it does not list.
    /// <para>
    /// Without this comparison, that group is not "verified" — it is invisible, which is
    /// worse, because the report would look complete while a whole file went unexamined.
    /// </para>
    /// </remarks>
    private static InspectionCheck CheckComSodConsistency(LdsReader reader, EfSod sod)
    {
        LdsReader.ReadResult comFile = reader.ReadFile(DataGroup.Com);

        if (!comFile.Success)
        {
            return InspectionCheck.Inconclusive(
                CheckIds.LdsComSodConsistency,
                ReasonCodes.DataGroupAbsent,
                $"EF.COM could not be read, so its data-group list cannot be compared " +
                $"against the security object. {comFile.Detail}");
        }

        EfCom com;
        try
        {
            com = EfCom.Parse(comFile.Content.Span);
        }
        catch (MrtdEncodingException exception)
        {
            return InspectionCheck.Inconclusive(
                CheckIds.LdsComSodConsistency,
                ReasonCodes.MalformedData,
                $"EF.COM could not be parsed: {exception.Message}");
        }

        HashSet<int> advertised = [.. com.DataGroups.Select(group => group.Number)];
        HashSet<int> protectedGroups = [.. sod.SecurityObject.ProtectedDataGroups];

        int[] unsigned = [.. advertised.Except(protectedGroups).Order()];
        int[] missing = [.. protectedGroups.Except(advertised).Order()];

        if (unsigned.Length > 0)
        {
            return InspectionCheck.Failed(
                CheckIds.LdsComSodConsistency,
                ReasonCodes.UnsignedContent,
                $"The chip advertises {string.Join(", ", unsigned.Select(n => $"DG{n}"))} " +
                "in EF.COM, but the security object does not protect " +
                (unsigned.Length == 1 ? "it" : "them") +
                ". That content carries no issuer signature and cannot be verified.",
                [.. unsigned.Select(n => Evidence.Of($"DG{n}", "advertised but unsigned"))]);
        }

        if (missing.Length > 0)
        {
            return InspectionCheck.Failed(
                CheckIds.LdsComSodConsistency,
                ReasonCodes.DataGroupAbsent,
                $"The security object protects {string.Join(", ", missing.Select(n => $"DG{n}"))} " +
                "but EF.COM does not list " + (missing.Length == 1 ? "it" : "them") + ".",
                [.. missing.Select(n => Evidence.Of($"DG{n}", "signed but unadvertised"))]);
        }

        return InspectionCheck.Passed(
            CheckIds.LdsComSodConsistency,
            "EF.COM's data-group list matches the security object exactly.",
            Evidence.Of(
                "data-groups",
                string.Join(", ", protectedGroups.Order().Select(n => $"DG{n}"))));
    }

    private static T? TryParse<T>(Func<T> parse) where T : class
    {
        try
        {
            return parse();
        }
        catch (MrtdEncodingException)
        {
            // A data group that will not parse is still hashed and still verified; only
            // the convenience projection is lost.
            return null;
        }
    }

    private InspectionOutcome Finish(
        List<InspectionCheck> checks,
        long startedAt,
        MrzInfo? mrz,
        FaceImage? portrait,
        IReadOnlyDictionary<int, ReadOnlyMemory<byte>> dataGroups)
    {
        // Extended Access Control is a permanent boundary, so it is always reported
        // rather than silently omitted (D008).
        checks.Add(InspectionCheck.Unavailable(
            CheckIds.TerminalAuth,
            ReasonCodes.CredentialsNotHeld,
            "MRTDScope holds no Inspection System certificate chain, so Extended Access " +
            "Control was not attempted and DG3/DG4 were not read."));

        long elapsed = (long)Stopwatch.GetElapsedTime(startedAt).TotalMilliseconds;

        return new InspectionOutcome(
            InspectionReport.Create(checks, elapsed),
            mrz,
            portrait,
            dataGroups);
    }
}
