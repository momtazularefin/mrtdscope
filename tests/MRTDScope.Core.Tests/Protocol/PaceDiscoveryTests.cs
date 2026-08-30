using MRTDScope.Core.Inspection;
using MRTDScope.Core.Protocol.Pace;
using MRTDScope.Core.Verification;
using MRTDScope.Synthetic;

namespace MRTDScope.Core.Tests.Protocol;

/// <summary>
/// PACE capability discovery: what a chip advertises, decoded from its own EF.CardAccess.
/// </summary>
public sealed class PaceOidTests
{
    /// <summary>
    /// The OID is not a label — it encodes the mapping, the key-agreement family, the
    /// cipher and the MAC in one value, and every downstream decision derives from it.
    /// </summary>
    [Theory]
    [InlineData("0.4.0.127.0.7.2.2.4.1.1", PaceMapping.Generic, false, PaceCipher.TripleDes)]
    [InlineData("0.4.0.127.0.7.2.2.4.1.2", PaceMapping.Generic, false, PaceCipher.Aes128)]
    [InlineData("0.4.0.127.0.7.2.2.4.2.2", PaceMapping.Generic, true, PaceCipher.Aes128)]
    [InlineData("0.4.0.127.0.7.2.2.4.2.4", PaceMapping.Generic, true, PaceCipher.Aes256)]
    [InlineData("0.4.0.127.0.7.2.2.4.3.4", PaceMapping.Integrated, false, PaceCipher.Aes256)]
    [InlineData("0.4.0.127.0.7.2.2.4.4.2", PaceMapping.Integrated, true, PaceCipher.Aes128)]
    [InlineData("0.4.0.127.0.7.2.2.4.6.4", PaceMapping.ChipAuthentication, true, PaceCipher.Aes256)]
    public void DecomposesEveryPaceVariant(
        string oid, PaceMapping mapping, bool ellipticCurve, PaceCipher cipher)
    {
        PaceAlgorithm? algorithm = PaceAlgorithm.FromOid(oid);

        Assert.NotNull(algorithm);
        Assert.Equal(mapping, algorithm!.Value.Mapping);
        Assert.Equal(ellipticCurve, algorithm.Value.UsesEllipticCurve);
        Assert.Equal(cipher, algorithm.Value.Cipher);
    }

    [Theory]
    [InlineData("2.23.136.1.1.1")]
    [InlineData("0.4.0.127.0.7.2.2.3.2")]
    [InlineData("not-an-oid")]
    public void NonPaceOidsAreRejected(string oid)
    {
        Assert.Null(PaceAlgorithm.FromOid(oid));
    }

    [Fact]
    public void OnlyEcdhGenericMappingWithAesIsExecutableByThisBuild()
    {
        Assert.True(PaceAlgorithm.FromOid("0.4.0.127.0.7.2.2.4.2.4")!.Value.IsSupported);

        // Recognized but not executable — reported precisely rather than as a generic
        // failure (D003).
        Assert.False(PaceAlgorithm.FromOid("0.4.0.127.0.7.2.2.4.2.1")!.Value.IsSupported);
        Assert.False(PaceAlgorithm.FromOid("0.4.0.127.0.7.2.2.4.1.2")!.Value.IsSupported);
        Assert.False(PaceAlgorithm.FromOid("0.4.0.127.0.7.2.2.4.4.2")!.Value.IsSupported);
    }

    /// <summary>Doc 9303 Part 11 §9.5.1, standardized domain parameters.</summary>
    [Theory]
    [InlineData(12, "secp256r1")]
    [InlineData(13, "brainpoolP256r1")]
    [InlineData(17, "brainpoolP512r1")]
    [InlineData(18, "secp521r1")]
    public void MapsStandardizedDomainParametersToCurves(int parameterId, string curve)
    {
        Assert.Equal(curve, PaceDomainParameters.CurveFor(parameterId));
    }

    [Theory]
    [InlineData(0)]  // 1024-bit MODP: a finite-field group, not a curve.
    [InlineData(5)]  // Reserved.
    [InlineData(25)] // Reserved.
    public void NonCurveParameterIdsYieldNothingRatherThanAGuess(int parameterId)
    {
        Assert.Null(PaceDomainParameters.CurveFor(parameterId));
    }
}

public sealed class SecurityInfosTests
{
    [Fact]
    public void ParsesAPaceInfoFromEfCardAccess()
    {
        SecurityInfos infos = SecurityInfos.Parse(
            SyntheticDocument.BuildEfCardAccess(parameterId: 13));

        Assert.True(infos.SupportsPace);
        PaceInfo pace = Assert.Single(infos.PaceInfos);

        Assert.Equal(2, pace.Version);
        Assert.Equal(13, pace.ParameterId);
        Assert.Equal("brainpoolP256r1", pace.CurveName);
        Assert.True(pace.Algorithm.IsSupported);
    }

    [Fact]
    public void PrefersTheStrongestExecutableVariant()
    {
        SecurityInfos infos = SecurityInfos.Parse(
            SyntheticDocument.BuildEfCardAccess("0.4.0.127.0.7.2.2.4.2.2", parameterId: 12));

        Assert.Equal(PaceCipher.Aes128, infos.PreferredPace!.Algorithm.Cipher);
    }

    /// <summary>
    /// A chip may advertise protocols this build has never heard of. Keeping them means
    /// the report can say what the document offers rather than narrowing it to what
    /// happens to be implemented.
    /// </summary>
    [Fact]
    public void UnknownProtocolsAreRetainedNotDiscarded()
    {
        SecurityInfos infos = SecurityInfos.Parse(
            SyntheticDocument.BuildEfCardAccess("1.2.3.4.5", parameterId: 13));

        Assert.Single(infos.Entries);
        Assert.False(infos.SupportsPace);
        Assert.Null(infos.PreferredPace);
    }

    [Fact]
    public void MalformedContentIsRejected()
    {
        Assert.Throws<MRTDScope.Core.Errors.MrtdEncodingException>(
            () => SecurityInfos.Parse([0x01, 0x02, 0x03]));
    }
}

public sealed class ChipCapabilityProbeTests
{
    private static InspectionCheck PaceCheck(SyntheticChip chip)
    {
        chip.Connect();

        return new InspectionSession(new TrustStore([chip.Document.Csca]))
            .Inspect(chip, chip.Document.MrzKey)
            .Report.Checks.Single(check => check.Id == CheckIds.AccessControlPace);
    }

    /// <summary>
    /// A chip with no EF.CardAccess predates Supplemental Access Control. That is a fact
    /// about the document, so it is <c>NotApplicable</c> rather than a gap in this build.
    /// </summary>
    [Fact]
    public void ChipWithoutCardAccess_IsReportedAsNotOfferingPace()
    {
        using SyntheticChip chip = SyntheticDocument.Build().CreateChip();

        InspectionCheck pace = PaceCheck(chip);

        Assert.Equal(CheckStatus.NotApplicable, pace.Status);
        Assert.Equal(ReasonCodes.ProtocolNotOffered, pace.ReasonCode);
    }

    /// <summary>
    /// A chip that offers an executable variant gets PACE, not BAC. That is a security
    /// decision: the BAC key derives entirely from MRZ data with low enough entropy to
    /// attack offline from a recorded session.
    /// </summary>
    [Fact]
    public void ChipAdvertisingPace_GetsPaceAndNotBac()
    {
        using SyntheticChip chip = SyntheticDocument.Build().AdvertisingPace().CreateChip();
        chip.Connect();

        InspectionOutcome outcome = new InspectionSession(new TrustStore([chip.Document.Csca]))
            .Inspect(chip, chip.Document.MrzKey);

        InspectionCheck pace = outcome.Report.Checks.Single(c => c.Id == CheckIds.AccessControlPace);
        Assert.Equal(CheckStatus.Passed, pace.Status);
        Assert.Contains(pace.Evidence, item => item.Value.Contains("AES", StringComparison.Ordinal));
        Assert.Contains(pace.Evidence, item => item.Value == "brainpoolP256r1");

        // BAC was not merely skipped; the report says why.
        InspectionCheck bac = outcome.Report.Checks.Single(c => c.Id == CheckIds.AccessControlBac);
        Assert.Equal(CheckStatus.NotApplicable, bac.Status);

        Assert.True(chip.UsedPace);
    }

    /// <summary>
    /// The whole chain over a PACE-established AES channel: chunked reads and Passive
    /// Authentication must work identically to the 3DES one, since everything above
    /// ICardTransport is written once.
    /// </summary>
    [Fact]
    public void PaceEstablishedSession_ReadsAndVerifiesTheWholeDocument()
    {
        using SyntheticChip chip = SyntheticDocument.Build().AdvertisingPace().CreateChip();
        chip.Connect();

        InspectionOutcome outcome = new InspectionSession(new TrustStore([chip.Document.Csca]))
            .Inspect(chip, chip.Document.MrzKey);

        Assert.False(outcome.Report.HasFailure);
        Assert.Equal(2, outcome.DataGroupsRead.Count);
        Assert.NotNull(outcome.Mrz);
        Assert.NotNull(outcome.Portrait);

        Assert.Equal(
            CheckStatus.Passed,
            outcome.Report.Checks.Single(c => c.Id == CheckIds.PassiveAuthDataGroupHashes).Status);
    }

    [Theory]
    [InlineData("0.4.0.127.0.7.2.2.4.2.2", 12)]  // AES-128 on NIST P-256
    [InlineData("0.4.0.127.0.7.2.2.4.2.4", 13)]  // AES-256 on BrainpoolP256r1
    [InlineData("0.4.0.127.0.7.2.2.4.2.3", 16)]  // AES-192 on BrainpoolP384r1
    public void PaceWorksAcrossCipherAndCurveCombinations(string oid, int parameterId)
    {
        using SyntheticChip chip = SyntheticDocument.Build()
            .AdvertisingPace(oid, parameterId)
            .CreateChip();
        chip.Connect();

        InspectionOutcome outcome = new InspectionSession(new TrustStore([chip.Document.Csca]))
            .Inspect(chip, chip.Document.MrzKey);

        Assert.Equal(
            CheckStatus.Passed,
            outcome.Report.Checks.Single(c => c.Id == CheckIds.AccessControlPace).Status);
        Assert.False(outcome.Report.HasFailure);
    }

    /// <summary>
    /// A wrong password decrypts the chip's nonce to noise, so the mapped generator
    /// differs, so the session keys differ, and the token is rejected. PACE gives an
    /// attacker one online guess per session rather than an offline attack.
    /// </summary>
    [Fact]
    public void WrongPassword_IsRejectedAtTheTokenExchange()
    {
        using SyntheticChip chip = SyntheticDocument.Build().AdvertisingPace().CreateChip();
        chip.Connect();

        MRTDScope.Core.Mrz.MrzKey wrongKey =
            MRTDScope.Core.Mrz.MrzKey.Create("Z999999Z<", "010101", "301231");

        InspectionOutcome outcome = new InspectionSession(new TrustStore([chip.Document.Csca]))
            .Inspect(chip, wrongKey);

        InspectionCheck pace = outcome.Report.Checks.Single(c => c.Id == CheckIds.AccessControlPace);
        Assert.Equal(CheckStatus.Failed, pace.Status);

        // Nothing may claim to have been verified after access control failed (NFR1).
        Assert.DoesNotContain(
            outcome.Report.Checks,
            check => check.Id.StartsWith("passive-auth", StringComparison.Ordinal)
                && check.Status == CheckStatus.Passed);
    }

    /// <summary>
    /// A variant this build recognizes but cannot execute must be reported as such, and
    /// the inspection must still complete over BAC rather than giving up.
    /// </summary>
    [Fact]
    public void UnsupportedVariant_FallsBackToBacAndSaysSo()
    {
        // ECDH Integrated Mapping: recognized, not implemented.
        using SyntheticChip chip = SyntheticDocument.Build()
            .AdvertisingPace("0.4.0.127.0.7.2.2.4.4.2", 12)
            .CreateChip();
        chip.Connect();

        InspectionOutcome outcome = new InspectionSession(new TrustStore([chip.Document.Csca]))
            .Inspect(chip, chip.Document.MrzKey);

        InspectionCheck pace = outcome.Report.Checks.Single(c => c.Id == CheckIds.AccessControlPace);
        Assert.Equal(CheckStatus.Unavailable, pace.Status);
        Assert.Equal(ReasonCodes.NotImplemented, pace.ReasonCode);

        // The document is still fully inspected over the fallback path.
        Assert.Equal(
            CheckStatus.Passed,
            outcome.Report.Checks.Single(c => c.Id == CheckIds.AccessControlBac).Status);
        Assert.False(outcome.Report.HasFailure);
    }

    /// <summary>
    /// Regression guard for a bug that reached real hardware: MSE:Set AT carried the
    /// conditional domain-parameter reference to a chip offering a single parameter set,
    /// and the chip answered 6A88. The synthetic chip was too permissive to notice, so it
    /// is now strict about the same condition.
    /// </summary>
    [Fact]
    public void SingleParameterSet_DoesNotReceiveTheConditionalDomainParameterReference()
    {
        using SyntheticChip chip = SyntheticDocument.Build().AdvertisingPace().CreateChip();
        chip.Connect();

        InspectionOutcome outcome = new InspectionSession(new TrustStore([chip.Document.Csca]))
            .Inspect(chip, chip.Document.MrzKey);

        // If the reference were sent, the chip would reject MSE:Set AT and PACE would fail.
        Assert.Equal(
            CheckStatus.Passed,
            outcome.Report.Checks.Single(c => c.Id == CheckIds.AccessControlPace).Status);
    }

    [Fact]
    public void ASingleAdvertisedVariantIsNotAmbiguous()
    {
        SecurityInfos infos = SecurityInfos.Parse(
            SyntheticDocument.BuildEfCardAccess(parameterId: 13));

        Assert.False(infos.DomainParametersAreAmbiguous);
    }

    /// <summary>
    /// Regression guard for a bug that reached real hardware: the inspection selected the
    /// eMRTD application before attempting PACE, and the chip answered 6985. Doc 9303
    /// Part 11 places the PACE security context in the Master File and orders the flow
    /// EF.CardAccess, PACE, select application, BAC.
    /// </summary>
    [Fact]
    public void PaceRunsBeforeTheApplicationIsSelected()
    {
        using SyntheticChip chip = SyntheticDocument.Build().AdvertisingPace().CreateChip();
        chip.Connect();

        // The chip refuses PACE once the application is selected, so a session that
        // completes proves the terminal ran the steps in the specified order.
        InspectionOutcome outcome = new InspectionSession(new TrustStore([chip.Document.Csca]))
            .Inspect(chip, chip.Document.MrzKey);

        Assert.Equal(
            CheckStatus.Passed,
            outcome.Report.Checks.Single(c => c.Id == CheckIds.AccessControlPace).Status);

        // And the document is still fully read afterwards, over the PACE channel.
        Assert.False(outcome.Report.HasFailure);
        Assert.Equal(2, outcome.DataGroupsRead.Count);
    }
}
