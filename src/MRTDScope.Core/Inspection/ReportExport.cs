using MRTDScope.Core.Lds;
using MRTDScope.Core.Transport;

namespace MRTDScope.Core.Inspection;

/// <summary>
/// Where an inspection's artifacts should be written. A null entry is not written.
/// </summary>
/// <param name="Json">The deterministic machine-readable report.</param>
/// <param name="Text">The same report rendered for a person.</param>
/// <param name="Trace">The APDU trace, with key-bearing payloads redacted.</param>
/// <param name="Portrait">The DG2 portrait, in whatever encoding the chip stored.</param>
public sealed record ExportTargets(
    string? Json = null,
    string? Text = null,
    string? Trace = null,
    string? Portrait = null)
{
    /// <summary>Whether anything at all was requested.</summary>
    public bool Any => Json is not null || Text is not null || Trace is not null || Portrait is not null;
}

/// <summary>
/// Writes an inspection's artifacts to disk.
/// </summary>
/// <remarks>
/// Shared by the CLI and the desktop application so that an exported report is the same
/// file whichever surface produced it.
/// <para>
/// Nothing here writes unless a path was explicitly given. An inspection of a real
/// document produces the holder's portrait, MRZ, and nationality; a tool that dropped
/// those into a default location would eventually leave them somewhere the operator did
/// not intend, and in this repository's case, somewhere a blind <c>git add</c> could
/// reach.
/// </para>
/// </remarks>
public static class ReportExport
{
    /// <summary>
    /// Writes every requested artifact and returns the paths actually written, in order.
    /// </summary>
    /// <param name="outcome">The completed inspection.</param>
    /// <param name="targets">Which artifacts to write, and where.</param>
    /// <param name="tracer">The session's trace, when one was captured.</param>
    public static IReadOnlyList<string> Write(
        InspectionOutcome outcome,
        ExportTargets targets,
        ApduTracer? tracer = null)
    {
        ArgumentNullException.ThrowIfNull(outcome);
        ArgumentNullException.ThrowIfNull(targets);

        List<string> written = [];

        if (targets.Json is { } json)
        {
            written.Add(WriteText(json, outcome.Report.ToDeterministicJson()));
        }

        if (targets.Text is { } text)
        {
            written.Add(WriteText(text, ReportFormatter.ToText(outcome.Report)));
        }

        if (targets.Trace is { } trace && tracer is not null)
        {
            written.Add(WriteText(trace, tracer.ToText()));
        }

        if (targets.Portrait is { } portrait && outcome.Portrait is { } face)
        {
            string path = PortraitPathFor(portrait, face);
            EnsureDirectory(path);
            File.WriteAllBytes(path, face.Data.ToArray());
            written.Add(path);
        }

        return written;
    }

    /// <summary>
    /// Corrects a requested portrait path to the encoding the chip actually stored.
    /// </summary>
    /// <remarks>
    /// DG2 commonly holds JPEG 2000 rather than JPEG, and an operator asking for
    /// <c>portrait.jpg</c> is usually guessing. Honouring the guess would write JPEG 2000
    /// bytes under a <c>.jpg</c> name, which most viewers refuse to open and which
    /// misreports what the document contains. The extension follows the data.
    /// </remarks>
    public static string PortraitPathFor(string requested, FaceImage image)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(requested);
        ArgumentNullException.ThrowIfNull(image);

        string extension = Path.GetExtension(requested);

        return extension.Equals(image.FileExtension, StringComparison.OrdinalIgnoreCase)
            ? requested
            : Path.ChangeExtension(requested, image.FileExtension);
    }

    private static string WriteText(string path, string content)
    {
        EnsureDirectory(path);
        File.WriteAllText(path, content);
        return path;
    }

    private static void EnsureDirectory(string path)
    {
        if (Path.GetDirectoryName(Path.GetFullPath(path)) is { Length: > 0 } directory)
        {
            Directory.CreateDirectory(directory);
        }
    }
}
