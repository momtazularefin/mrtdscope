using MRTDScope.Core.Inspection;
using MRTDScope.Core.Verification;
using MRTDScope.Synthetic;

namespace MRTDScope.Core.Tests.Protocol;

/// <summary>
/// Active Authentication: proving the chip is the original, not a copy of its data.
/// </summary>
/// <remarks>
/// Passive Authentication proves a document's contents are authentic and unaltered. It
/// says nothing about the silicon, so a byte-for-byte clone onto a blank chip passes it
/// completely. These are the checks that close that gap.
/// </remarks>
public sealed class ActiveAuthenticationTests
{
    private static InspectionOutcome Inspect(SyntheticChip chip)
    {
        chip.Connect();

        return new InspectionSession(new TrustStore([chip.Document.Csca]))
            .Inspect(chip, chip.Document.MrzKey);
    }

    private static InspectionCheck Check(InspectionOutcome outcome, string id) =>
        outcome.Report.Checks.Single(check => check.Id == id);

    [Fact]
    public void GenuineChip_ProducesAVerifiableSignatureOverTheChallenge()
    {
        using SyntheticChip chip = SyntheticDocument.Build()
            .WithActiveAuthentication()
            .CreateChip();

        InspectionCheck active = Check(Inspect(chip), CheckIds.ActiveAuth);

        Assert.Equal(CheckStatus.Passed, active.Status);
        Assert.Contains(active.Evidence, item => item.Label == "algorithm");

        // The recovered nonce length is recorded, which is only meaningful if message
        // recovery genuinely ran rather than a plain signature check.
        Assert.Contains(
            active.Evidence,
            item => item.Label == "digest" && item.Value.Contains("recovered", StringComparison.Ordinal));
    }

    /// <summary>
    /// The replay a cloned chip can mount without holding the private key: answer with a
    /// genuine signature captured from an earlier session.
    /// </summary>
    /// <remarks>
    /// The signature verifies under DG15 perfectly. What it does not do is bind to the
    /// nonce this terminal just generated — and only ISO/IEC 9796-2 message recovery,
    /// which folds the terminal's challenge into the hash, can tell the difference. A
    /// plain signature check over the challenge would also catch this, but the harvested
    /// code's plain <c>SHA1withRSA</c> check would have rejected genuine documents too.
    /// </remarks>
    [Fact]
    public void ReplayedResponse_FailsTheChallengeBinding()
    {
        using SyntheticChip chip = SyntheticDocument.Build()
            .WithFault(DocumentFault.ReplayedActiveAuthentication)
            .CreateChip();

        InspectionOutcome outcome = Inspect(chip);
        InspectionCheck active = Check(outcome, CheckIds.ActiveAuth);

        Assert.Equal(CheckStatus.Failed, active.Status);
        Assert.Equal(ReasonCodes.SignatureInvalid, active.ReasonCode);

        // Everything else about the document is genuine, so this must be the only failure.
        Assert.Equal(CheckStatus.Passed, Check(outcome, CheckIds.PassiveAuthSodSignature).Status);
        Assert.Equal(CheckStatus.Passed, Check(outcome, CheckIds.PassiveAuthDataGroupHashes).Status);
        Assert.Single(outcome.Report.Checks, c => c.Status == CheckStatus.Failed);
    }

    [Fact]
    public void DocumentWithoutDg15_ReportsNotApplicable()
    {
        using SyntheticChip chip = SyntheticDocument.Build().CreateChip();

        InspectionCheck active = Check(Inspect(chip), CheckIds.ActiveAuth);

        Assert.Equal(CheckStatus.NotApplicable, active.Status);
        Assert.Equal(ReasonCodes.DataGroupAbsent, active.ReasonCode);
        Assert.NotEqual(CheckStatus.Failed, active.Status);
    }

    /// <summary>
    /// DG15 is covered by the security object, so a tampered public key is caught by the
    /// hash check before Active Authentication can be misled by it.
    /// </summary>
    [Fact]
    public void TamperedDg15_IsCaughtByTheDataGroupHashes()
    {
        using SyntheticChip chip = SyntheticDocument.Build()
            .WithActiveAuthentication()
            .WithFault(DocumentFault.TamperedDataGroup, dataGroup: 15)
            .CreateChip();

        InspectionOutcome outcome = Inspect(chip);

        InspectionCheck hashes = Check(outcome, CheckIds.PassiveAuthDataGroupHashes);
        Assert.Equal(CheckStatus.Failed, hashes.Status);
        Assert.Contains(hashes.Evidence, item => item.Label == "DG15" && item.Value == "MISMATCH");
    }
}

/// <summary>
/// Chip Authentication: clone detection that also produces stronger session keys.
/// </summary>
public sealed class ChipAuthenticationTests
{
    private static InspectionOutcome Inspect(SyntheticChip chip)
    {
        chip.Connect();

        return new InspectionSession(new TrustStore([chip.Document.Csca]))
            .Inspect(chip, chip.Document.MrzKey);
    }

    private static InspectionCheck Check(InspectionOutcome outcome, string id) =>
        outcome.Report.Checks.Single(check => check.Id == id);

    [Fact]
    public void DocumentWithoutDg14_ReportsNotApplicable()
    {
        using SyntheticChip chip = SyntheticDocument.Build().CreateChip();

        InspectionCheck chipAuth = Check(Inspect(chip), CheckIds.ChipAuth);

        Assert.Equal(CheckStatus.NotApplicable, chipAuth.Status);
        Assert.NotEqual(CheckStatus.Failed, chipAuth.Status);
    }

    /// <summary>
    /// A DG14 carrying only PACE information offers no Chip Authentication, which is a
    /// fact about the document rather than a limitation of this build.
    /// </summary>
    [Fact]
    public void Dg14WithoutChipAuthentication_ReportsProtocolNotOffered()
    {
        using SyntheticChip chip = SyntheticDocument.Build().AdvertisingPace().CreateChip();

        InspectionCheck chipAuth = Check(Inspect(chip), CheckIds.ChipAuth);

        Assert.Equal(CheckStatus.NotApplicable, chipAuth.Status);
        Assert.Equal(ReasonCodes.ProtocolNotOffered, chipAuth.ReasonCode);
    }

    /// <summary>
    /// Chip Authentication parameters must be readable from a DG14 that carries them,
    /// including the static public key the issuer signed.
    /// </summary>
    [Fact]
    public void Dg14WithChipAuthentication_YieldsUsableParameters()
    {
        using SyntheticChip chip = SyntheticDocument.Build()
            .WithChipAuthentication()
            .CreateChip();

        InspectionOutcome outcome = Inspect(chip);

        Assert.Contains(14, outcome.DataGroupsRead.Keys);

        MRTDScope.Core.Protocol.ChipAuth.ChipAuthenticationParameters? parameters =
            MRTDScope.Core.Protocol.ChipAuth.ChipAuthenticationProtocol.FromDg14(
                outcome.DataGroupsRead[14].Span);

        Assert.NotNull(parameters);
        Assert.Equal("0.4.0.127.0.7.2.2.3.2.2", parameters!.ProtocolOid);
        Assert.Equal(MRTDScope.Core.Protocol.Pace.PaceCipher.Aes128, parameters.Cipher);
        Assert.Equal(256, parameters.PublicKey.Parameters.Curve.FieldSize);
    }

    [Fact]
    public void GenuineChip_AgreesAKeyAndRestartsSecureMessaging()
    {
        using SyntheticChip chip = SyntheticDocument.Build()
            .WithChipAuthentication()
            .CreateChip();

        InspectionOutcome outcome = Inspect(chip);
        InspectionCheck chipAuth = Check(outcome, CheckIds.ChipAuth);

        Assert.Equal(CheckStatus.Passed, chipAuth.Status);
        Assert.Contains(chipAuth.Evidence, item => item.Label == "protocol");
        Assert.Contains(
            chipAuth.Evidence,
            item => item.Label == "algorithm" && item.Value.Contains("AES", StringComparison.Ordinal));
    }

    /// <summary>
    /// Chip Authentication restarts secure messaging rather than layering on top of the
    /// access-control channel. Getting that wrong double-protects every later command,
    /// and the chip rejects it with a checksum failure that reads like a key-derivation
    /// bug — which is exactly how it presented before this was fixed.
    /// </summary>
    [Fact]
    public void AfterChipAuthentication_TheSessionContinuesOnTheNewChannel()
    {
        using SyntheticChip chip = SyntheticDocument.Build()
            .WithChipAuthentication()
            .WithActiveAuthentication()
            .CreateChip();

        InspectionOutcome outcome = Inspect(chip);

        // Active Authentication runs after Chip Authentication, so a successful result
        // proves the restarted channel is the one actually carrying traffic.
        Assert.Equal(CheckStatus.Passed, Check(outcome, CheckIds.ChipAuth).Status);
        Assert.Equal(CheckStatus.Passed, Check(outcome, CheckIds.ActiveAuth).Status);
        Assert.False(outcome.Report.HasFailure);
    }

    /// <summary>
    /// Both clone-detection protocols on one document, over PACE, with everything else
    /// verified — the strongest posture this build can report.
    /// </summary>
    [Fact]
    public void FullyEquippedDocument_PassesEveryImplementedCheck()
    {
        using SyntheticChip chip = SyntheticDocument.Build()
            .AdvertisingPace()
            .WithChipAuthentication()
            .WithActiveAuthentication()
            .CreateChip();

        InspectionOutcome outcome = Inspect(chip);

        Assert.False(outcome.Report.HasFailure);

        foreach (string id in new[]
        {
            CheckIds.AccessControlPace,
            CheckIds.LdsComSodConsistency,
            CheckIds.PassiveAuthSodSignature,
            CheckIds.PassiveAuthDocumentSignerChain,
            CheckIds.PassiveAuthDataGroupHashes,
            CheckIds.LdsCardAccessAuthenticity,
            CheckIds.ChipAuth,
            CheckIds.ActiveAuth,
        })
        {
            Assert.Equal(CheckStatus.Passed, Check(outcome, id).Status);
        }

        // Extended Access Control stays a permanent boundary, never quietly omitted.
        Assert.Equal(CheckStatus.Unavailable, Check(outcome, CheckIds.TerminalAuth).Status);
    }
}
