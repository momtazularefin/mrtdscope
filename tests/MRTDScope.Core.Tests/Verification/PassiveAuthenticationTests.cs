using MRTDScope.Core.Inspection;
using MRTDScope.Core.Lds;
using MRTDScope.Core.Tests.Support;
using MRTDScope.Core.Verification;

namespace MRTDScope.Core.Tests.Verification;

/// <summary>
/// Passive Authentication over a real, run-time-generated signing hierarchy (AC4).
/// </summary>
/// <remarks>
/// Every case here runs the production verifier against a genuine CMS SignedData over a
/// genuine LDSSecurityObject. The failure cases matter more than the success case: they
/// are what distinguishes a verifier from something that merely reports success.
/// </remarks>
public sealed class PassiveAuthenticationTests
{
    private static Dictionary<int, byte[]> DataGroups() => new()
    {
        [1] = LdsFixtures.Dg1(),
        [2] = LdsFixtures.Dg2(),
    };

    private static Dictionary<int, ReadOnlyMemory<byte>> AsContents(
        IReadOnlyDictionary<int, byte[]> groups) =>
        groups.ToDictionary(pair => pair.Key, pair => (ReadOnlyMemory<byte>)pair.Value);

    private static InspectionCheck Check(IReadOnlyList<InspectionCheck> checks, string id) =>
        checks.Single(check => check.Id == id);

    [Fact]
    public void GenuineDocument_PassesAllThreeChecks()
    {
        TestPki pki = TestPki.Create();
        Dictionary<int, byte[]> groups = DataGroups();
        EfSod sod = EfSod.Parse(pki.BuildSod(groups));

        TrustStore trust = new([pki.Csca]);
        IReadOnlyList<InspectionCheck> checks =
            new PassiveAuthenticator(trust).Verify(sod, AsContents(groups));

        Assert.Equal(3, checks.Count);
        Assert.All(checks, check => Assert.Equal(CheckStatus.Passed, check.Status));
        Assert.All(checks, check => Assert.NotEmpty(check.Evidence));
    }

    /// <summary>
    /// The check the harvested code did not have. Without it, a chip whose portrait has
    /// been replaced passes Passive Authentication (D004).
    /// </summary>
    [Fact]
    public void SubstitutedPortrait_FailsOnlyTheDataGroupHashes()
    {
        TestPki pki = TestPki.Create();
        Dictionary<int, byte[]> genuine = DataGroups();
        EfSod sod = EfSod.Parse(pki.BuildSod(genuine));

        // The chip now presents a different DG2. The SOD is untouched and still genuine.
        Dictionary<int, byte[]> presented = new(genuine)
        {
            [2] = LdsFixtures.Dg2(imageBytes: [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33]),
        };

        IReadOnlyList<InspectionCheck> checks =
            new PassiveAuthenticator(new TrustStore([pki.Csca]))
                .Verify(sod, AsContents(presented));

        // The signature and the chain are still perfectly valid — which is exactly why
        // reporting them separately matters.
        Assert.Equal(CheckStatus.Passed, Check(checks, CheckIds.PassiveAuthSodSignature).Status);
        Assert.Equal(CheckStatus.Passed, Check(checks, CheckIds.PassiveAuthDocumentSignerChain).Status);

        InspectionCheck hashes = Check(checks, CheckIds.PassiveAuthDataGroupHashes);
        Assert.Equal(CheckStatus.Failed, hashes.Status);
        Assert.Equal(ReasonCodes.HashMismatch, hashes.ReasonCode);

        // The report must name which data group, not merely that something differed.
        Assert.Contains(hashes.Evidence, item => item.Label == "DG2" && item.Value == "MISMATCH");
        Assert.Contains(hashes.Evidence, item => item.Label == "DG1" && item.Value == "matches");
    }

    [Fact]
    public void NoTrustAnchor_IsInconclusive_NotFailed()
    {
        TestPki pki = TestPki.Create();
        Dictionary<int, byte[]> groups = DataGroups();
        EfSod sod = EfSod.Parse(pki.BuildSod(groups));

        IReadOnlyList<InspectionCheck> checks =
            new PassiveAuthenticator(new TrustStore()).Verify(sod, AsContents(groups));

        InspectionCheck chain = Check(checks, CheckIds.PassiveAuthDocumentSignerChain);

        // D005: this is a statement about the inspector, never about the document.
        Assert.Equal(CheckStatus.Inconclusive, chain.Status);
        Assert.NotEqual(CheckStatus.Failed, chain.Status);
        Assert.Equal(ReasonCodes.NoTrustAnchor, chain.ReasonCode);

        // The other two checks are unaffected: they need no anchor.
        Assert.Equal(CheckStatus.Passed, Check(checks, CheckIds.PassiveAuthSodSignature).Status);
        Assert.Equal(CheckStatus.Passed, Check(checks, CheckIds.PassiveAuthDataGroupHashes).Status);
    }

    /// <summary>
    /// A self-signed forgery: internally consistent, but vouched for by nobody. This is
    /// the case the chain check exists to catch.
    /// </summary>
    [Fact]
    public void ForgedDocumentSigner_FailsTheChainButNotTheSignature()
    {
        TestPki genuine = TestPki.Create();
        TestPki forger = TestPki.Create(cscaSubject: "CN=Unrelated Authority,C=ZZ");

        Dictionary<int, byte[]> groups = DataGroups();
        EfSod forgedSod = EfSod.Parse(forger.BuildSod(groups));

        // Only the genuine CSCA is trusted.
        IReadOnlyList<InspectionCheck> checks =
            new PassiveAuthenticator(new TrustStore([genuine.Csca]))
                .Verify(forgedSod, AsContents(groups));

        // The forger signed their own SOD correctly, so this passes. On its own it would
        // be a green light — which is why a single "PA passed" verdict is not enough.
        Assert.Equal(CheckStatus.Passed, Check(checks, CheckIds.PassiveAuthSodSignature).Status);
        Assert.Equal(CheckStatus.Passed, Check(checks, CheckIds.PassiveAuthDataGroupHashes).Status);

        InspectionCheck chain = Check(checks, CheckIds.PassiveAuthDocumentSignerChain);
        Assert.Equal(CheckStatus.Failed, chain.Status);
        Assert.Equal(ReasonCodes.ChainNotTrusted, chain.ReasonCode);
    }

    [Fact]
    public void ExpiredDocumentSigner_IsReportedDistinctlyFromUntrusted()
    {
        DateTime now = DateTime.UtcNow;
        TestPki pki = TestPki.Create(
            documentSignerNotBefore: now.AddYears(-5),
            documentSignerNotAfter: now.AddYears(-1));

        Dictionary<int, byte[]> groups = DataGroups();
        EfSod sod = EfSod.Parse(pki.BuildSod(groups));

        IReadOnlyList<InspectionCheck> checks =
            new PassiveAuthenticator(new TrustStore([pki.Csca])).Verify(sod, AsContents(groups));

        InspectionCheck chain = Check(checks, CheckIds.PassiveAuthDocumentSignerChain);

        Assert.Equal(CheckStatus.Failed, chain.Status);

        // Distinct from chain-not-trusted: it chains fine, it is simply out of date.
        Assert.Equal(ReasonCodes.CertificateExpired, chain.ReasonCode);
        Assert.NotEqual(ReasonCodes.ChainNotTrusted, chain.ReasonCode);
    }

    [Fact]
    public void ExpiredSignerIsAcceptedWhenInspectingAtAHistoricalTime()
    {
        DateTime issued = DateTime.UtcNow.AddYears(-5);

        // The anchor must span the historical window too. A CSCA that had not yet been
        // issued at inspection time is itself a finding, which the previous version of
        // this fixture tripped over.
        TestPki pki = TestPki.Create(
            documentSignerNotBefore: issued.AddDays(-1),
            documentSignerNotAfter: issued.AddYears(1),
            cscaNotBefore: issued.AddYears(-1),
            cscaNotAfter: issued.AddYears(10));

        Dictionary<int, byte[]> groups = DataGroups();
        EfSod sod = EfSod.Parse(pki.BuildSod(groups));

        // Inspecting as of a date when the signer was valid.
        FakeTimeProvider clock = new(issued.AddMonths(1));

        InspectionCheck chain = Check(
            new PassiveAuthenticator(new TrustStore([pki.Csca]), clock)
                .Verify(sod, AsContents(groups)),
            CheckIds.PassiveAuthDocumentSignerChain);

        Assert.Equal(CheckStatus.Passed, chain.Status);
    }

    [Fact]
    public void UnreadableProtectedGroup_IsReportedWithoutImplyingFullCoverage()
    {
        TestPki pki = TestPki.Create();

        // The SOD protects DG1, DG2 and DG3, but DG3 needs Extended Access Control and
        // so is never read (D008).
        Dictionary<int, byte[]> signed = new(DataGroups())
        {
            [3] = LdsFixtures.Filler(DataGroup.Dg3, 0x33),
        };

        EfSod sod = EfSod.Parse(pki.BuildSod(signed));

        Dictionary<int, byte[]> read = DataGroups();

        InspectionCheck hashes = Check(
            new PassiveAuthenticator(new TrustStore([pki.Csca])).Verify(sod, AsContents(read)),
            CheckIds.PassiveAuthDataGroupHashes);

        Assert.Equal(CheckStatus.Passed, hashes.Status);
        Assert.Contains(hashes.Evidence, item => item.Label == "not-compared" && item.Value.Contains("DG3", StringComparison.Ordinal));
        Assert.Contains("not read", hashes.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void NoReadableGroups_IsInconclusiveRatherThanPassing()
    {
        TestPki pki = TestPki.Create();
        Dictionary<int, byte[]> groups = DataGroups();
        EfSod sod = EfSod.Parse(pki.BuildSod(groups));

        InspectionCheck hashes = Check(
            new PassiveAuthenticator(new TrustStore([pki.Csca]))
                .Verify(sod, new Dictionary<int, ReadOnlyMemory<byte>>()),
            CheckIds.PassiveAuthDataGroupHashes);

        // Comparing nothing must never look like comparing everything successfully.
        Assert.Equal(CheckStatus.Inconclusive, hashes.Status);
        Assert.NotEqual(CheckStatus.Passed, hashes.Status);
    }

    [Fact]
    public void CorruptedSodSignature_FailsTheSignatureCheck()
    {
        TestPki pki = TestPki.Create();
        Dictionary<int, byte[]> groups = DataGroups();

        byte[] sodBytes = pki.BuildSod(groups);

        // Flip a byte deep inside the signature blob, leaving the structure parseable.
        sodBytes[^20] ^= 0xFF;

        EfSod sod = EfSod.Parse(sodBytes);

        InspectionCheck signature = Check(
            new PassiveAuthenticator(new TrustStore([pki.Csca])).Verify(sod, AsContents(groups)),
            CheckIds.PassiveAuthSodSignature);

        Assert.Equal(CheckStatus.Failed, signature.Status);
        Assert.Equal(ReasonCodes.SignatureInvalid, signature.ReasonCode);
    }

    [Fact]
    public void Sha1SecurityObjects_AreStillVerifiable()
    {
        // A large in-service population was issued with SHA-1 security objects. A tool
        // that cannot recompute the issuer's digest is useless on those documents.
        TestPki pki = TestPki.Create();
        Dictionary<int, byte[]> groups = DataGroups();

        EfSod sod = EfSod.Parse(pki.BuildSod(groups, DigestAlgorithms.Sha1));

        InspectionCheck hashes = Check(
            new PassiveAuthenticator(new TrustStore([pki.Csca])).Verify(sod, AsContents(groups)),
            CheckIds.PassiveAuthDataGroupHashes);

        Assert.Equal(CheckStatus.Passed, hashes.Status);
        Assert.Equal(DigestAlgorithms.Sha1, sod.SecurityObject.DigestAlgorithmOid);
    }
}

/// <summary>A fixed clock, so certificate-validity behaviour is testable.</summary>
internal sealed class FakeTimeProvider(DateTime utcNow) : TimeProvider
{
    public override DateTimeOffset GetUtcNow() => new(utcNow, TimeSpan.Zero);
}
