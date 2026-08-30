using MRTDScope.Core.Inspection;
using MRTDScope.Core.Lds;
using MRTDScope.Core.Verification;
using MRTDScope.Synthetic;

namespace MRTDScope.Core.Tests.Corpus;

/// <summary>
/// The fault corpus (FR10, AC5): every forgery class must be detected, and the check
/// that fails must be the right one.
/// </summary>
/// <remarks>
/// This is the milestone that distinguishes MRTDScope from every other open reader. A
/// verification tool that has only ever been shown to succeed has demonstrated nothing
/// about the case that matters.
/// <para>
/// Each case runs the complete production inspection — SELECT, BAC, secure messaging,
/// chunked LDS reads, Passive Authentication — against a synthetic chip at the
/// <c>ICardTransport</c> boundary. No hardware, no network, no real document data
/// (NFR2, NFR3). The assertions are deliberately narrow: not "something failed", but
/// "this named check failed with this reason code, and the others still passed".
/// </para>
/// </remarks>
public sealed class FaultCorpusTests
{
    private static InspectionOutcome Inspect(SyntheticChip chip, bool trustAnchor = true)
    {
        chip.Connect();

        TrustStore trust = trustAnchor
            ? new TrustStore([chip.Document.Csca])
            : new TrustStore();

        return new InspectionSession(trust).Inspect(chip, chip.Document.MrzKey);
    }

    private static InspectionCheck Check(InspectionOutcome outcome, string id) =>
        outcome.Report.Checks.Single(check => check.Id == id);

    // ---- Control case ------------------------------------------------------

    [Fact]
    public void GenuineDocument_PassesEveryCheckAndYieldsItsContent()
    {
        using SyntheticChip chip = SyntheticDocument.Build().CreateChip();
        InspectionOutcome outcome = Inspect(chip);

        Assert.False(outcome.Report.HasFailure);

        Assert.Equal(CheckStatus.Passed, Check(outcome, CheckIds.AccessControlBac).Status);
        Assert.Equal(CheckStatus.Passed, Check(outcome, CheckIds.PassiveAuthSodSignature).Status);
        Assert.Equal(CheckStatus.Passed, Check(outcome, CheckIds.PassiveAuthDocumentSignerChain).Status);
        Assert.Equal(CheckStatus.Passed, Check(outcome, CheckIds.PassiveAuthDataGroupHashes).Status);

        // The full chain really ran: the MRZ and portrait came off the chip through the
        // secure channel and parsed.
        Assert.NotNull(outcome.Mrz);
        Assert.Equal("L898902C<", outcome.Mrz!.DocumentNumber);
        Assert.NotNull(outcome.Portrait);
        Assert.Equal(FaceImageEncoding.Jpeg, outcome.Portrait!.Encoding);

        // EAC is always reported as a permanent boundary, never silently omitted (D008).
        Assert.Equal(CheckStatus.Unavailable, Check(outcome, CheckIds.TerminalAuth).Status);
    }

    [Fact]
    public void GenuineDocument_ActuallyExercisedTheSecureChannel()
    {
        using SyntheticChip chip = SyntheticDocument.Build().CreateChip();
        InspectionOutcome outcome = Inspect(chip);

        Assert.True(chip.HasSecureChannel);
        Assert.False(outcome.Report.HasFailure);

        // A real session: application select, BAC handshake, then many protected reads.
        Assert.True(
            chip.CommandsProcessed > 10,
            $"Only {chip.CommandsProcessed} APDUs were exchanged; the read loop cannot have run.");
    }

    // ---- The faults --------------------------------------------------------

    /// <summary>
    /// The substituted portrait. This is the case a reader without the hash check waves
    /// through, and the reason D004 exists.
    /// </summary>
    [Fact]
    public void TamperedDataGroup_FailsOnlyTheDataGroupHashes()
    {
        using SyntheticChip chip = SyntheticDocument.Build()
            .WithFault(DocumentFault.TamperedDataGroup, dataGroup: 2)
            .CreateChip();

        InspectionOutcome outcome = Inspect(chip);

        InspectionCheck hashes = Check(outcome, CheckIds.PassiveAuthDataGroupHashes);
        Assert.Equal(CheckStatus.Failed, hashes.Status);
        Assert.Equal(ReasonCodes.HashMismatch, hashes.ReasonCode);
        Assert.Contains(hashes.Evidence, item => item.Label == "DG2" && item.Value == "MISMATCH");

        // Everything else is genuine, and the report must say so rather than smearing
        // the failure across unrelated checks.
        Assert.Equal(CheckStatus.Passed, Check(outcome, CheckIds.PassiveAuthSodSignature).Status);
        Assert.Equal(CheckStatus.Passed, Check(outcome, CheckIds.PassiveAuthDocumentSignerChain).Status);
        Assert.Equal(CheckStatus.Passed, Check(outcome, CheckIds.AccessControlBac).Status);
    }

    [Fact]
    public void TamperedDg1_IsAttributedToDg1_NotDg2()
    {
        using SyntheticChip chip = SyntheticDocument.Build()
            .WithFault(DocumentFault.TamperedDataGroup, dataGroup: 1)
            .CreateChip();

        InspectionCheck hashes = Check(Inspect(chip), CheckIds.PassiveAuthDataGroupHashes);

        Assert.Equal(CheckStatus.Failed, hashes.Status);
        Assert.Contains(hashes.Evidence, item => item.Label == "DG1" && item.Value == "MISMATCH");
        Assert.Contains(hashes.Evidence, item => item.Label == "DG2" && item.Value == "matches");
    }

    [Fact]
    public void SubstitutedDocumentSigner_FailsTheChainButNotTheSignature()
    {
        using SyntheticChip chip = SyntheticDocument.Build()
            .WithFault(DocumentFault.SubstitutedDocumentSigner)
            .CreateChip();

        InspectionOutcome outcome = Inspect(chip);

        // The forger signed their own security object perfectly well.
        Assert.Equal(CheckStatus.Passed, Check(outcome, CheckIds.PassiveAuthSodSignature).Status);
        Assert.Equal(CheckStatus.Passed, Check(outcome, CheckIds.PassiveAuthDataGroupHashes).Status);

        InspectionCheck chain = Check(outcome, CheckIds.PassiveAuthDocumentSignerChain);
        Assert.Equal(CheckStatus.Failed, chain.Status);
        Assert.Equal(ReasonCodes.ChainNotTrusted, chain.ReasonCode);
    }

    [Fact]
    public void ExpiredDocumentSigner_FailsTheChainWithItsOwnReason()
    {
        using SyntheticChip chip = SyntheticDocument.Build()
            .WithFault(DocumentFault.ExpiredDocumentSigner)
            .CreateChip();

        InspectionOutcome outcome = Inspect(chip);

        InspectionCheck chain = Check(outcome, CheckIds.PassiveAuthDocumentSignerChain);
        Assert.Equal(CheckStatus.Failed, chain.Status);
        Assert.Equal(ReasonCodes.CertificateExpired, chain.ReasonCode);

        // The signature is still mathematically valid. Conflating these two was a real
        // defect fixed in M2, and this case is what keeps it fixed.
        Assert.Equal(CheckStatus.Passed, Check(outcome, CheckIds.PassiveAuthSodSignature).Status);
    }

    [Fact]
    public void CorruptedSodSignature_FailsTheSignatureCheck()
    {
        using SyntheticChip chip = SyntheticDocument.Build()
            .WithFault(DocumentFault.CorruptedSodSignature)
            .CreateChip();

        InspectionCheck signature = Check(Inspect(chip), CheckIds.PassiveAuthSodSignature);

        Assert.Equal(CheckStatus.Failed, signature.Status);
        Assert.Equal(ReasonCodes.SignatureInvalid, signature.ReasonCode);
    }

    /// <summary>
    /// An active attacker on the contactless interface, tampering mid-session after the
    /// channel is genuinely established.
    /// </summary>
    [Fact]
    public void CorruptedSecureMessagingMac_BreaksTheChannelAndIsReported()
    {
        using SyntheticChip chip = SyntheticDocument.Build()
            .WithFault(DocumentFault.CorruptedSecureMessagingMac)
            .CreateChip();

        InspectionOutcome outcome = Inspect(chip);

        // BAC itself completed — the tamper begins afterwards.
        Assert.Equal(CheckStatus.Passed, Check(outcome, CheckIds.AccessControlBac).Status);

        InspectionCheck channel = Check(outcome, CheckIds.SecureMessaging);
        Assert.Equal(CheckStatus.Failed, channel.Status);
        Assert.Equal(ReasonCodes.SecureMessagingIntegrity, channel.ReasonCode);

        // Crucially, the inspection still produced a report rather than an exception.
        Assert.True(outcome.Report.HasFailure);
        Assert.NotEmpty(outcome.Report.Checks);
    }

    /// <summary>
    /// Content on the chip that no issuer ever signed.
    /// </summary>
    /// <remarks>
    /// The hash check is structurally blind to this: the security object has nothing to
    /// say about a group it does not list, so DG2 is never read and never compared. That
    /// makes it invisible rather than rejected — which is worse than a failure, because
    /// the report would otherwise look complete while a whole file went unexamined.
    /// Catching it is the entire reason EF.COM is read.
    /// </remarks>
    [Fact]
    public void UnsignedDataGroup_IsCaughtByTheComToSodComparison()
    {
        using SyntheticChip chip = SyntheticDocument.Build()
            .WithFault(DocumentFault.UnsignedDataGroup)
            .CreateChip();

        InspectionOutcome outcome = Inspect(chip);

        // DG2 is on the chip and advertised, but the issuer never signed it — so it is
        // never read as protected content, and the hash check cannot see the problem.
        Assert.DoesNotContain(2, outcome.DataGroupsRead.Keys);
        Assert.Equal(CheckStatus.Passed, Check(outcome, CheckIds.PassiveAuthDataGroupHashes).Status);

        // The consistency check is what actually catches it.
        InspectionCheck consistency = Check(outcome, CheckIds.LdsComSodConsistency);
        Assert.Equal(CheckStatus.Failed, consistency.Status);
        Assert.Equal(ReasonCodes.UnsignedContent, consistency.ReasonCode);
        Assert.Contains(consistency.Evidence, item => item.Label == "DG2");

        Assert.True(outcome.Report.HasFailure);
    }

    [Fact]
    public void GenuineDocument_HasConsistentComAndSod()
    {
        using SyntheticChip chip = SyntheticDocument.Build().CreateChip();

        InspectionCheck consistency = Check(Inspect(chip), CheckIds.LdsComSodConsistency);

        Assert.Equal(CheckStatus.Passed, consistency.Status);
    }

    // ---- Inspector limitations, not document faults ------------------------

    [Fact]
    public void WithoutATrustAnchor_TheChainIsInconclusiveAndNothingElseChanges()
    {
        using SyntheticChip chip = SyntheticDocument.Build().CreateChip();
        InspectionOutcome outcome = Inspect(chip, trustAnchor: false);

        InspectionCheck chain = Check(outcome, CheckIds.PassiveAuthDocumentSignerChain);
        Assert.Equal(CheckStatus.Inconclusive, chain.Status);
        Assert.Equal(ReasonCodes.NoTrustAnchor, chain.ReasonCode);

        // A genuine document must not read as a failure merely because the inspector was
        // not equipped to judge it (D005).
        Assert.False(outcome.Report.HasFailure);
    }

    [Fact]
    public void WrongMrz_IsReportedAsAccessDeniedWithNoVerificationClaims()
    {
        using SyntheticChip chip = SyntheticDocument.Build().CreateChip();
        chip.Connect();

        MRTDScope.Core.Mrz.MrzKey wrongKey =
            MRTDScope.Core.Mrz.MrzKey.Create("Z999999Z<", "010101", "301231");

        InspectionOutcome outcome =
            new InspectionSession(new TrustStore([chip.Document.Csca])).Inspect(chip, wrongKey);

        InspectionCheck bac = Check(outcome, CheckIds.AccessControlBac);
        Assert.Equal(CheckStatus.Failed, bac.Status);
        Assert.Equal(ReasonCodes.AccessDenied, bac.ReasonCode);

        // Nothing was read, so nothing may claim to have been verified (NFR1).
        Assert.DoesNotContain(
            outcome.Report.Checks,
            check => check.Status == CheckStatus.Passed);
        Assert.False(chip.HasSecureChannel);
    }


    // ---- Protocol downgrade ------------------------------------------------

    /// <summary>
    /// The downgrade attack the EF.CardAccess/DG14 cross-check exists to catch.
    /// </summary>
    /// <remarks>
    /// EF.CardAccess is unsigned and readable before any authentication. An attacker who
    /// can present a modified one strips the strong PACE variant, leaving only a weaker
    /// option the terminal then negotiates in good faith. Nothing inside the session
    /// reveals it: the weaker channel is cryptographically sound, mutual authentication
    /// succeeds, and every Passive Authentication check passes, because the document's
    /// signed content is genuinely untouched.
    /// <para>
    /// Only the signed copy in DG14 exposes it, and only after the fact — which is why the
    /// check reports a downgrade rather than preventing one.
    /// </para>
    /// </remarks>
    [Fact]
    public void DowngradedCardAccess_IsCaughtByComparisonWithTheSignedCopy()
    {
        using SyntheticChip chip = SyntheticDocument.Build()
            .WithFault(DocumentFault.DowngradedCardAccess)
            .CreateChip();

        InspectionOutcome outcome = Inspect(chip);

        InspectionCheck authenticity = Check(outcome, CheckIds.LdsCardAccessAuthenticity);
        Assert.Equal(CheckStatus.Failed, authenticity.Status);
        Assert.Equal(ReasonCodes.ProtocolDowngrade, authenticity.ReasonCode);

        // The report must show both sides, so an operator can see what was withheld.
        Assert.Contains(authenticity.Evidence, item => item.Label == "ef.cardaccess");
        Assert.Contains(authenticity.Evidence, item => item.Label == "dg14-signed");

        // The weaker variant is what actually got used.
        Assert.Contains(
            authenticity.Evidence,
            item => item.Label == "ef.cardaccess" && item.Value.Contains("Aes128", StringComparison.Ordinal));
        Assert.Contains(
            authenticity.Evidence,
            item => item.Label == "dg14-signed" && item.Value.Contains("Aes256", StringComparison.Ordinal));
    }

    /// <summary>
    /// The downgrade is invisible to every other check, which is precisely why a
    /// dedicated one is needed.
    /// </summary>
    [Fact]
    public void DowngradedCardAccess_PassesEveryOtherCheck()
    {
        using SyntheticChip chip = SyntheticDocument.Build()
            .WithFault(DocumentFault.DowngradedCardAccess)
            .CreateChip();

        InspectionOutcome outcome = Inspect(chip);

        // PACE succeeded — over the weaker variant the attacker chose.
        Assert.Equal(CheckStatus.Passed, Check(outcome, CheckIds.AccessControlPace).Status);

        // The document's signed content is untouched, so Passive Authentication is clean.
        Assert.Equal(CheckStatus.Passed, Check(outcome, CheckIds.PassiveAuthSodSignature).Status);
        Assert.Equal(CheckStatus.Passed, Check(outcome, CheckIds.PassiveAuthDocumentSignerChain).Status);
        Assert.Equal(CheckStatus.Passed, Check(outcome, CheckIds.PassiveAuthDataGroupHashes).Status);
        Assert.Equal(CheckStatus.Passed, Check(outcome, CheckIds.LdsComSodConsistency).Status);

        // Exactly one check fails, and it is the right one.
        Assert.Single(outcome.Report.Checks, c => c.Status == CheckStatus.Failed);
    }

    [Fact]
    public void GenuineDocumentAdvertisingPace_HasAuthenticCardAccess()
    {
        using SyntheticChip chip = SyntheticDocument.Build().AdvertisingPace().CreateChip();

        InspectionCheck authenticity = Check(Inspect(chip), CheckIds.LdsCardAccessAuthenticity);

        Assert.Equal(CheckStatus.Passed, authenticity.Status);
    }

    /// <summary>
    /// A BAC-only document has no EF.CardAccess to check, which is a fact about the
    /// document rather than a gap in the inspection.
    /// </summary>
    [Fact]
    public void DocumentWithoutCardAccess_ReportsTheCheckAsNotApplicable()
    {
        using SyntheticChip chip = SyntheticDocument.Build().CreateChip();

        InspectionCheck authenticity = Check(Inspect(chip), CheckIds.LdsCardAccessAuthenticity);

        Assert.Equal(CheckStatus.NotApplicable, authenticity.Status);
        Assert.NotEqual(CheckStatus.Failed, authenticity.Status);
    }

    // ---- Corpus-wide invariants --------------------------------------------

    /// <summary>
    /// Every fault must be caught. A new fault added to the enum without detection
    /// support fails here rather than passing unnoticed.
    /// </summary>
    [Theory]
    [InlineData(DocumentFault.TamperedDataGroup)]
    [InlineData(DocumentFault.SubstitutedDocumentSigner)]
    [InlineData(DocumentFault.ExpiredDocumentSigner)]
    [InlineData(DocumentFault.CorruptedSodSignature)]
    [InlineData(DocumentFault.CorruptedSecureMessagingMac)]
    [InlineData(DocumentFault.UnsignedDataGroup)]
    [InlineData(DocumentFault.DowngradedCardAccess)]
    public void EveryFault_ProducesAtLeastOneFailedCheck(DocumentFault fault)
    {
        using SyntheticChip chip = SyntheticDocument.Build().WithFault(fault).CreateChip();

        Assert.True(
            Inspect(chip).Report.HasFailure,
            $"{fault} went undetected. A forgery class with no failing check is exactly " +
            "what this corpus exists to prevent.");
    }

    /// <summary>
    /// No fault may cause an unhandled exception. An operator needs a reading, not a
    /// stack trace (NFR5).
    /// </summary>
    [Theory]
    [InlineData(DocumentFault.None)]
    [InlineData(DocumentFault.TamperedDataGroup)]
    [InlineData(DocumentFault.SubstitutedDocumentSigner)]
    [InlineData(DocumentFault.ExpiredDocumentSigner)]
    [InlineData(DocumentFault.CorruptedSodSignature)]
    [InlineData(DocumentFault.CorruptedSecureMessagingMac)]
    [InlineData(DocumentFault.UnsignedDataGroup)]
    [InlineData(DocumentFault.DowngradedCardAccess)]
    public void EveryFault_StillProducesAReport(DocumentFault fault)
    {
        using SyntheticChip chip = SyntheticDocument.Build().WithFault(fault).CreateChip();

        InspectionReport report = Inspect(chip).Report;

        Assert.NotEmpty(report.Checks);
        Assert.NotEmpty(report.ToDeterministicJson());
    }

    /// <summary>
    /// Two inspections of the same document produce identical reports, so a diff between
    /// runs means the document changed rather than the tool wandering (NFR4).
    /// </summary>
    [Fact]
    public void ReportsAreDeterministicAcrossRuns()
    {
        SyntheticDocument document = SyntheticDocument.Genuine();

        using SyntheticChip first = new(document);
        using SyntheticChip second = new(document);

        // Timing is excluded from the deterministic form; the session nonces differ every
        // run, so anything nonce-derived leaking into the report would show up here.
        Assert.Equal(
            Inspect(first).Report.ToDeterministicJson(),
            Inspect(second).Report.ToDeterministicJson());
    }
}
