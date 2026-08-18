using System.Reflection;
using MRTDScope.Core.Inspection;

namespace MRTDScope.Core.Tests.Inspection;

/// <summary>
/// Tests for the project's binding correctness rule (NFR1, D003): no check may report
/// success without having performed it.
/// </summary>
public sealed class InspectionCheckTests
{
    [Fact]
    public void Passed_RequiresEvidence()
    {
        ArgumentException error = Assert.Throws<ArgumentException>(() =>
            InspectionCheck.Passed(CheckIds.PassiveAuthSodSignature, "SOD signature verified."));

        Assert.Contains("without evidence", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Passed_CarriesItsEvidence()
    {
        InspectionCheck check = InspectionCheck.Passed(
            CheckIds.PassiveAuthSodSignature,
            "SOD signature verified under the embedded Document Signer.",
            Evidence.Of("algorithm", "SHA256withRSA"),
            Evidence.Of("signer-serial", "0x2A17"));

        Assert.Equal(CheckStatus.Passed, check.Status);
        Assert.Null(check.ReasonCode);
        Assert.Equal(2, check.Evidence.Count);
    }

    /// <summary>
    /// The rule is structural, not conventional. If a public constructor ever appears,
    /// a caller could fabricate a passing check with no evidence and this test must fail
    /// before that reaches a release.
    /// </summary>
    [Fact]
    public void Passed_IsUnreachableExceptThroughTheGuardedFactory()
    {
        ConstructorInfo[] publicConstructors = typeof(InspectionCheck)
            .GetConstructors(BindingFlags.Public | BindingFlags.Instance);

        Assert.Empty(publicConstructors);

        MethodInfo[] factoriesReturningChecks = [.. typeof(InspectionCheck)
            .GetMethods(BindingFlags.Public | BindingFlags.Static)
            .Where(method => method.ReturnType == typeof(InspectionCheck))];

        Assert.Equal(
            ["Failed", "Inconclusive", "NotApplicable", "Passed", "Unavailable"],
            factoriesReturningChecks.Select(method => method.Name).Order());
    }

    [Theory]
    [InlineData(CheckStatus.Failed)]
    [InlineData(CheckStatus.Inconclusive)]
    [InlineData(CheckStatus.NotApplicable)]
    [InlineData(CheckStatus.Unavailable)]
    public void NonPassingStatuses_RequireAReasonCode(CheckStatus status)
    {
        Assert.Throws<ArgumentException>(() => Build(status, reasonCode: "  "));
    }

    [Fact]
    public void Inconclusive_IsNotAFailure()
    {
        InspectionCheck check = InspectionCheck.Inconclusive(
            CheckIds.PassiveAuthDocumentSignerChain,
            ReasonCodes.NoTrustAnchor,
            "No CSCA anchor configured for the issuing authority.");

        Assert.Equal(CheckStatus.Inconclusive, check.Status);
        Assert.NotEqual(CheckStatus.Failed, check.Status);
        Assert.Equal(ReasonCodes.NoTrustAnchor, check.ReasonCode);
    }

    [Fact]
    public void Unavailable_NeverReportsSuccess()
    {
        InspectionCheck check = InspectionCheck.Unavailable(
            CheckIds.TerminalAuth,
            ReasonCodes.CredentialsNotHeld,
            "No Inspection System certificate chain is held.");

        Assert.Equal(CheckStatus.Unavailable, check.Status);
        Assert.Empty(check.Evidence);
    }

    private static InspectionCheck Build(CheckStatus status, string reasonCode) => status switch
    {
        CheckStatus.Failed => InspectionCheck.Failed(CheckIds.ActiveAuth, reasonCode, "detail"),
        CheckStatus.Inconclusive => InspectionCheck.Inconclusive(CheckIds.ActiveAuth, reasonCode, "detail"),
        CheckStatus.NotApplicable => InspectionCheck.NotApplicable(CheckIds.ActiveAuth, reasonCode, "detail"),
        CheckStatus.Unavailable => InspectionCheck.Unavailable(CheckIds.ActiveAuth, reasonCode, "detail"),
        _ => throw new ArgumentOutOfRangeException(nameof(status)),
    };
}
