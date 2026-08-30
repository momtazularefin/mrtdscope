using MRTDScope.Core.Inspection;
using MRTDScope.Core.Lds;
using MRTDScope.Core.Mrz;
using MRTDScope.Core.Transport;
using MRTDScope.Core.Verification;
using MRTDScope.Pcsc;
using Xunit.Abstractions;

namespace MRTDScope.Core.Tests.Hardware;

/// <summary>
/// The complete inspection chain against a physical document (AC1).
/// </summary>
/// <remarks>
/// Where <see cref="RealDocumentTests"/> proves BAC and the secure channel work, this
/// runs the whole thing: chunked reads of a real DG2 portrait, real end-of-file
/// behaviour, DG1 and DG2 parsing of an actual issuer's encoding, and Passive
/// Authentication. That read loop is where documents diverge from the specification most
/// often, and neither the published vectors nor the synthetic chip can expose it.
/// <para>
/// <b>Nothing personal is asserted, printed, or written.</b> The document's MRZ,
/// portrait, and identity never leave the process (NFR3). What this test reports is
/// structural: how many bytes each data group ran to, which checks were reached, and the
/// issuing authority's signer metadata — none of which describes the bearer.
/// </para>
/// </remarks>
[Trait("Category", "Hardware")]
[Collection(HardwareCollection.Name)]
public sealed class RealDocumentInspectionTests(ITestOutputHelper output)
{
    private const string DocumentNumberVariable = "MRTDSCOPE_TEST_DOC_NUMBER";
    private const string DateOfBirthVariable = "MRTDSCOPE_TEST_DOB";
    private const string DateOfExpiryVariable = "MRTDSCOPE_TEST_DOE";

    /// <summary>Optional directory of operator-supplied CSCA anchors.</summary>
    private const string TrustDirectoryVariable = "MRTDSCOPE_TRUST_DIR";

    [SkippableFact]
    public void FullInspection_ReadsEveryProtectedDataGroupAndVerifiesIt()
    {
        MrzKey key = ResolveKeyOrSkip();
        string reader = PcscReaderResolver.Resolve()
            ?? throw new SkipException("No PC/SC reader is available.");

        ApduTracer tracer = new();
        using PcscCardTransport transport = new(reader, tracer);
        transport.Connect();

        output.WriteLine($"Reader: {reader}");
        output.WriteLine($"ATS: {Convert.ToHexString(transport.AnswerToReset.Span)}");

        TrustStore trust = new();
        string? trustDirectory = Environment.GetEnvironmentVariable(TrustDirectoryVariable);

        if (!string.IsNullOrWhiteSpace(trustDirectory))
        {
            output.WriteLine($"Loaded {trust.LoadDirectory(trustDirectory)} trust anchor(s).");
        }

        InspectionOutcome outcome = new InspectionSession(trust).Inspect(transport, key);

        foreach (InspectionCheck check in outcome.Report.Checks)
        {
            output.WriteLine(
                $"{check.Status,-13} {check.Id}" +
                (check.ReasonCode is null ? string.Empty : $"  ({check.ReasonCode})"));
        }

        output.WriteLine($"Elapsed: {outcome.Report.ElapsedMilliseconds} ms, " +
            $"{tracer.Exchanges.Count} APDUs.");

        // Access control must have succeeded, or nothing below it ran.
        InspectionCheck bac = outcome.Report.Checks.Single(c => c.Id == CheckIds.AccessControlBac);
        Assert.Equal(CheckStatus.Passed, bac.Status);

        // The chunked read loop against real files: sizes only, never content.
        Assert.NotEmpty(outcome.DataGroupsRead);

        foreach ((int number, ReadOnlyMemory<byte> content) in outcome.DataGroupsRead.OrderBy(p => p.Key))
        {
            output.WriteLine($"DG{number}: {content.Length} bytes");

            // Every file must carry the BER tag Doc 9303 assigns it, which proves the
            // length header was read correctly and the file is complete.
            DataGroup group = DataGroup.FromNumber(number)!;
            Assert.Equal(group.Tag, content.Span[0]);
        }

        // DG1 and DG2 are mandatory on every eMRTD.
        Assert.Contains(1, outcome.DataGroupsRead.Keys);
        Assert.Contains(2, outcome.DataGroupsRead.Keys);

        // A real portrait is kilobytes, not a handful of bytes. This is the assertion
        // that would catch a read loop that silently stopped early.
        Assert.True(
            outcome.DataGroupsRead[2].Length > 1000,
            $"DG2 was only {outcome.DataGroupsRead[2].Length} bytes; the chunked read " +
            "cannot have completed.");

        // Both parsed, against a real issuer's encoding rather than my own fixtures.
        Assert.NotNull(outcome.Mrz);
        Assert.NotNull(outcome.Portrait);
        output.WriteLine(
            $"Portrait: {outcome.Portrait!.Encoding}, " +
            $"{outcome.Portrait.Width}x{outcome.Portrait.Height}, " +
            $"{outcome.Portrait.Data.Length} bytes");

        // The chip's own MRZ must regenerate the key derived from the printed one. A
        // mismatch would mean the document read is not the document in hand.
        Assert.Equal(
            Convert.ToHexString(key.ComputeSeed()),
            Convert.ToHexString(outcome.Mrz!.ToKey().ComputeSeed()));

        // Passive Authentication: the security object is the issuer's, so its signature
        // and the data-group hashes must verify. The chain is only answerable with an
        // anchor for this issuer, so it is asserted as "not a failure" rather than passed.
        InspectionCheck signature = outcome.Report.Checks
            .Single(c => c.Id == CheckIds.PassiveAuthSodSignature);
        InspectionCheck hashes = outcome.Report.Checks
            .Single(c => c.Id == CheckIds.PassiveAuthDataGroupHashes);
        InspectionCheck chain = outcome.Report.Checks
            .Single(c => c.Id == CheckIds.PassiveAuthDocumentSignerChain);

        Assert.Equal(CheckStatus.Passed, signature.Status);
        Assert.Equal(CheckStatus.Passed, hashes.Status);
        Assert.NotEqual(CheckStatus.Failed, chain.Status);

        // Secret hygiene on a real session (NFR7).
        Assert.Contains("withheld", tracer.ToText(), StringComparison.Ordinal);
    }

    private static MrzKey ResolveKeyOrSkip()
    {
        string? documentNumber = Environment.GetEnvironmentVariable(DocumentNumberVariable);
        string? dateOfBirth = Environment.GetEnvironmentVariable(DateOfBirthVariable);
        string? dateOfExpiry = Environment.GetEnvironmentVariable(DateOfExpiryVariable);

        Skip.If(
            string.IsNullOrWhiteSpace(documentNumber)
            || string.IsNullOrWhiteSpace(dateOfBirth)
            || string.IsNullOrWhiteSpace(dateOfExpiry),
            $"Set {DocumentNumberVariable}, {DateOfBirthVariable}, and {DateOfExpiryVariable} " +
            "to run against a physical document.");

        return MrzKey.Create(documentNumber!, dateOfBirth!, dateOfExpiry!);
    }
}
