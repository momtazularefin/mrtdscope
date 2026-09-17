using MRTDScope.Core.Inspection;
using MRTDScope.Core.Lds;
using MRTDScope.Core.Verification;
using MRTDScope.Synthetic;

namespace MRTDScope.Core.Tests.Inspection;

/// <summary>
/// How a report reaches a person, and how it reaches a file.
/// </summary>
/// <remarks>
/// The rendering is shared by the CLI, the desktop application and the Android head, so a
/// defect here misleads an operator on every surface at once. That makes it worth tests
/// of its own rather than leaving it to whichever surface happened to be looked at.
/// </remarks>
public sealed class ReportFormatterTests
{
    private static InspectionOutcome Inspect(DocumentFault fault = DocumentFault.None)
    {
        using SyntheticChip chip = SyntheticDocument.Build().WithFault(fault).CreateChip();
        chip.Connect();

        return new InspectionSession(new TrustStore([chip.Document.Csca]))
            .Inspect(chip, chip.Document.MrzKey);
    }

    [Fact]
    public void EveryCheckAppearsWithItsStatusAndDetail()
    {
        InspectionReport report = Inspect().Report;

        string text = ReportFormatter.ToText(report);

        foreach (InspectionCheck check in report.Checks)
        {
            Assert.Contains(check.Id, text, StringComparison.Ordinal);
            Assert.Contains(check.Detail, text, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void AFailingCheckCarriesItsReasonCodeAndEvidence()
    {
        InspectionReport report = Inspect(DocumentFault.TamperedDataGroup).Report;

        string text = ReportFormatter.ToText(report);

        Assert.Contains($"FAIL     {CheckIds.PassiveAuthDataGroupHashes}", text, StringComparison.Ordinal);
        Assert.Contains(ReasonCodes.HashMismatch, text, StringComparison.Ordinal);
        Assert.Contains("DG2: MISMATCH", text, StringComparison.Ordinal);
    }

    [Fact]
    public void EvidenceCanBeSuppressedWithoutLosingTheOutcomes()
    {
        InspectionReport report = Inspect(DocumentFault.TamperedDataGroup).Report;

        string terse = ReportFormatter.ToText(report, includeEvidence: false);

        Assert.DoesNotContain("DG2: MISMATCH", terse, StringComparison.Ordinal);
        Assert.Contains(CheckIds.PassiveAuthDataGroupHashes, terse, StringComparison.Ordinal);
    }

    /// <summary>
    /// Every status has a badge of its own, and they all line up.
    /// </summary>
    /// <remarks>
    /// Five statuses exist so that "this document does not offer it" and "this tool cannot
    /// do it" are never confused. A shared badge confuses them on every surface at once;
    /// the first real read on a phone showed exactly that.
    /// </remarks>
    [Fact]
    public void EveryStatusHasADistinctFixedWidthBadge()
    {
        CheckStatus[] statuses = Enum.GetValues<CheckStatus>();
        string[] badges = [.. statuses.Select(ReportFormatter.Badge)];

        Assert.Equal(statuses.Length, badges.Distinct(StringComparer.Ordinal).Count());
        Assert.Single(badges.Select(badge => badge.Length).Distinct());
    }

    [Fact]
    public void TheSummaryCountsStatusesAndReadsAsEnglish()
    {
        InspectionReport report = Inspect(DocumentFault.TamperedDataGroup).Report;

        string summary = ReportFormatter.Summarize(report);

        Assert.Contains($"{report.Checks.Count} checks", summary, StringComparison.Ordinal);
        Assert.Contains("1 failed", summary, StringComparison.Ordinal);
        Assert.Contains("not applicable", summary, StringComparison.Ordinal);
        Assert.DoesNotContain("notapplicable", summary, StringComparison.Ordinal);
    }

    /// <summary>
    /// The report closes with counts, never with an overall verdict.
    /// </summary>
    /// <remarks>
    /// A single accept/reject line is exactly what the five-status vocabulary exists to
    /// prevent (D003), and it is the easiest thing in the world to add later "for
    /// convenience" — so it is asserted against rather than merely documented. The
    /// assertion is on the closing summary line specifically: individual checks describe
    /// what they did, and a detail reading "mutual authentication completed" is a
    /// statement about one protocol, not a verdict about the document.
    /// </remarks>
    [Theory]
    [InlineData(DocumentFault.None)]
    [InlineData(DocumentFault.TamperedDataGroup)]
    [InlineData(DocumentFault.CorruptedSodSignature)]
    public void TheReportClosesWithCountsAndNeverAVerdict(DocumentFault fault)
    {
        InspectionReport report = Inspect(fault).Report;

        string summary = ReportFormatter.Summarize(report);

        foreach (string verdict in new[] { "genuine", "authentic", "rejected", "accepted", "forged", "valid" })
        {
            Assert.DoesNotMatch($@"\b{verdict}\b", summary.ToLowerInvariant());
        }

        // The summary is the last thing printed, so it is what an operator reads last.
        string[] lines = ReportFormatter.ToText(report)
            .Split('\n', StringSplitOptions.RemoveEmptyEntries);

        Assert.Equal(summary, lines[^1].TrimEnd('\r'));
    }
}

public sealed class ReportExportTests : IDisposable
{
    private readonly DirectoryInfo _directory = Directory.CreateTempSubdirectory("mrtdscope-export");

    public void Dispose() => _directory.Delete(recursive: true);

    private string Path(string name) => System.IO.Path.Combine(_directory.FullName, name);

    private static InspectionOutcome Inspect()
    {
        using SyntheticChip chip = SyntheticDocument.Build().CreateChip();
        chip.Connect();

        return new InspectionSession(new TrustStore([chip.Document.Csca]))
            .Inspect(chip, chip.Document.MrzKey);
    }

    [Fact]
    public void NothingIsWrittenUnlessAPathWasGiven()
    {
        IReadOnlyList<string> written = ReportExport.Write(Inspect(), new ExportTargets());

        Assert.Empty(written);
        Assert.Empty(_directory.GetFiles());
    }

    [Fact]
    public void TheExportedJsonIsTheDeterministicReport()
    {
        InspectionOutcome outcome = Inspect();
        string path = Path("report.json");

        ReportExport.Write(outcome, new ExportTargets(Json: path));

        Assert.Equal(outcome.Report.ToDeterministicJson(), File.ReadAllText(path));
    }

    [Fact]
    public void MissingDirectoriesAreCreatedRatherThanFailing()
    {
        string path = Path(System.IO.Path.Combine("nested", "deeper", "report.txt"));

        ReportExport.Write(Inspect(), new ExportTargets(Text: path));

        Assert.True(File.Exists(path));
    }

    /// <summary>
    /// A JPEG 2000 portrait must not be written under a <c>.jpg</c> name.
    /// </summary>
    /// <remarks>
    /// Many issuers store JPEG 2000 in DG2, and an operator typing "portrait.jpg" is
    /// guessing. Honouring the guess produces a file most viewers refuse to open, and
    /// misreports what the document actually contains.
    /// </remarks>
    [Theory]
    [InlineData(FaceImageEncoding.Jpeg2000, "portrait.jpg", "portrait.jp2")]
    [InlineData(FaceImageEncoding.Jpeg, "portrait.jp2", "portrait.jpg")]
    [InlineData(FaceImageEncoding.Jpeg, "portrait", "portrait.jpg")]
    [InlineData(FaceImageEncoding.Jpeg, "portrait.jpg", "portrait.jpg")]
    public void ThePortraitExtensionFollowsTheEncodingNotTheRequest(
        FaceImageEncoding encoding, string requested, string expected)
    {
        FaceImage image = new(encoding, 240, 320, new byte[] { 1, 2, 3 });

        Assert.Equal(expected, ReportExport.PortraitPathFor(requested, image));
    }

    [Fact]
    public void AskingForAPortraitThatWasNeverReadWritesNothing()
    {
        InspectionOutcome outcome = Inspect() with { Portrait = null };

        IReadOnlyList<string> written = ReportExport.Write(
            outcome, new ExportTargets(Portrait: Path("portrait.jpg")));

        Assert.Empty(written);
    }

    [Fact]
    public void EachRequestedArtifactIsWrittenExactlyOnce()
    {
        IReadOnlyList<string> written = ReportExport.Write(
            Inspect(),
            new ExportTargets(Json: Path("r.json"), Text: Path("r.txt"), Portrait: Path("p.jpg")));

        Assert.Equal(3, written.Count);
        Assert.Equal(written.Count, written.Distinct(StringComparer.Ordinal).Count());
        Assert.All(written, path => Assert.True(File.Exists(path)));
    }
}
