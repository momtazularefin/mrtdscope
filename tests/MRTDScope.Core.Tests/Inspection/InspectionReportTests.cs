using MRTDScope.Core.Inspection;

namespace MRTDScope.Core.Tests.Inspection;

/// <summary>
/// Tests for report determinism (NFR4) and for the deliberate absence of a single
/// overall verdict.
/// </summary>
public sealed class InspectionReportTests
{
    [Fact]
    public void DeterministicJson_IgnoresTiming()
    {
        string fast = Report(elapsedMilliseconds: 12).ToDeterministicJson();
        string slow = Report(elapsedMilliseconds: 9_999).ToDeterministicJson();

        Assert.Equal(fast, slow);
    }

    [Fact]
    public void DeterministicJson_IsStableAcrossRuns()
    {
        Assert.Equal(Report().ToDeterministicJson(), Report().ToDeterministicJson());
    }

    [Fact]
    public void DeterministicJson_OmitsReasonCodeForPassingChecks()
    {
        string json = InspectionReport
            .Create([PassingCheck()])
            .ToDeterministicJson();

        Assert.DoesNotContain("ReasonCode", json, StringComparison.Ordinal);
        Assert.Contains("Passed", json, StringComparison.Ordinal);
    }

    [Fact]
    public void HasFailure_IsTrueOnlyForActiveRejection()
    {
        Assert.True(InspectionReport.Create([FailingCheck()]).HasFailure);
        Assert.False(InspectionReport.Create([PassingCheck()]).HasFailure);
        Assert.False(InspectionReport.Create([InconclusiveCheck()]).HasFailure);
        Assert.False(InspectionReport.Create([UnavailableCheck()]).HasFailure);
    }

    [Fact]
    public void Summary_CountsEveryStatus()
    {
        InspectionReport report = Report();

        Assert.Equal(1, report.Summary[nameof(CheckStatus.Passed)]);
        Assert.Equal(1, report.Summary[nameof(CheckStatus.Failed)]);
        Assert.Equal(1, report.Summary[nameof(CheckStatus.Inconclusive)]);
        Assert.Equal(1, report.Summary[nameof(CheckStatus.Unavailable)]);
    }

    [Fact]
    public void Create_RejectsNegativeElapsedTime()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            InspectionReport.Create([PassingCheck()], elapsedMilliseconds: -1));
    }

    private static InspectionReport Report(long elapsedMilliseconds = 0) =>
        InspectionReport.Create(
            [PassingCheck(), FailingCheck(), InconclusiveCheck(), UnavailableCheck()],
            elapsedMilliseconds);

    private static InspectionCheck PassingCheck() => InspectionCheck.Passed(
        CheckIds.PassiveAuthSodSignature,
        "SOD signature verified.",
        Evidence.Of("algorithm", "SHA256withRSA"));

    private static InspectionCheck FailingCheck() => InspectionCheck.Failed(
        CheckIds.PassiveAuthDataGroupHashes,
        ReasonCodes.HashMismatch,
        "DG2 does not match the LDS Security Object.",
        Evidence.Of("data-group", "DG2"));

    private static InspectionCheck InconclusiveCheck() => InspectionCheck.Inconclusive(
        CheckIds.PassiveAuthDocumentSignerChain,
        ReasonCodes.NoTrustAnchor,
        "No CSCA anchor configured for the issuing authority.");

    private static InspectionCheck UnavailableCheck() => InspectionCheck.Unavailable(
        CheckIds.TerminalAuth,
        ReasonCodes.CredentialsNotHeld,
        "No Inspection System certificate chain is held.");
}
