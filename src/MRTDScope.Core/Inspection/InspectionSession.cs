using System.Diagnostics;
using MRTDScope.Core.Apdu;
using MRTDScope.Core.Errors;
using MRTDScope.Core.Lds;
using MRTDScope.Core.Mrz;
using MRTDScope.Core.Protocol;
using MRTDScope.Core.Protocol.Bac;
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

        ResponseApdu selected = MrtdApplication.Select(transport);

        if (!selected.IsSuccess)
        {
            checks.Add(InspectionCheck.Failed(
                CheckIds.AccessControlBac,
                ReasonCodes.TransportFailure,
                $"The eMRTD application could not be selected; the chip returned " +
                $"{selected.StatusWord}."));

            return Finish(checks, startedAt, null, null, new Dictionary<int, ReadOnlyMemory<byte>>());
        }

        BacResult bac = new BacProtocol(mrzKey).Authenticate(transport);

        if (!bac.Succeeded || bac.SecureMessaging is null)
        {
            checks.Add(InspectionCheck.Failed(
                CheckIds.AccessControlBac,
                bac.FailureReason ?? ReasonCodes.AccessDenied,
                bac.Detail));

            // PACE is the other way in. Until M4 it is unavailable, and saying so is more
            // useful than silently reporting only that BAC failed.
            checks.Add(InspectionCheck.Unavailable(
                CheckIds.AccessControlPace,
                ReasonCodes.NotImplemented,
                "PACE is not implemented in this build, so no alternative access-control " +
                "path was attempted."));

            return Finish(checks, startedAt, null, null, new Dictionary<int, ReadOnlyMemory<byte>>());
        }

        checks.Add(InspectionCheck.Passed(
            CheckIds.AccessControlBac,
            bac.Detail,
            Evidence.Of("algorithm", bac.SecureMessaging.Algorithm)));

        using SecureMessagingTransport secure = new(transport, bac.SecureMessaging);
        LdsReader reader = new(secure);

        Dictionary<int, ReadOnlyMemory<byte>> dataGroups = [];
        MrzInfo? mrz = null;
        FaceImage? portrait = null;

        try
        {
            checks.AddRange(ReadAndVerify(reader, dataGroups, ref mrz, ref portrait));
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
