using Avalonia.Media;
using MRTDScope.Core.Inspection;

namespace MRTDScope.Desktop;

/// <summary>
/// One check as the list displays it.
/// </summary>
/// <remarks>
/// Colour is assigned here, and deliberately not reduced to green and red. The five
/// statuses exist because "cannot verify" is not "verification failed" (D003), and a
/// palette that paints an inconclusive certificate chain the same amber as a hash
/// mismatch would put the distinction back where the report worked to remove it.
/// <para>
/// Each colour is the dark end of its hue rather than the vivid mid tone the palette
/// starts from, because this brush paints the badge word as well as the rule beside it.
/// The mid tones were measured on a capture at 2.15:1 for PASS, 1.39:1 for INCONCL and
/// 2.59:1 for N/A against the card, so the one word that carries the verdict was the
/// least readable text on screen. Colour is redundant here in any case: the word says
/// the same thing, which is what makes it safe to darken the hue rather than keep it
/// bright.
/// </para>
/// </remarks>
public sealed class CheckRow
{
    public CheckRow(InspectionCheck check)
    {
        ArgumentNullException.ThrowIfNull(check);

        Id = check.Id;
        // The label comes from Core, as it does on the CLI and the Android head. This window
        // kept a private copy of the mapping after M7 moved it there, which is how both
        // surfaces could go on calling Unavailable "N/A" unnoticed.
        Badge = ReportFormatter.Badge(check.Status).TrimEnd();

        Accent = new SolidColorBrush(AccentFor(check.Status));

        Detail = check.Detail;
        Reason = check.ReasonCode ?? string.Empty;
        HasReason = check.ReasonCode is not null;

        Evidence = string.Join(
            Environment.NewLine,
            check.Evidence.Select(item => $"{item.Label}: {item.Value}"));

        HasEvidence = check.Evidence.Count > 0;
    }

    /// <summary>
    /// The colour a status is drawn in, exposed so its contrast can be asserted.
    /// </summary>
    public static Color AccentFor(CheckStatus status) => status switch
    {
        CheckStatus.Passed => Color.FromRgb(0x1B, 0x5E, 0x20),
        CheckStatus.Failed => Color.FromRgb(0xB7, 0x1C, 0x1C),
        CheckStatus.Inconclusive => Color.FromRgb(0x6D, 0x4C, 0x00),
        _ => Color.FromRgb(0x45, 0x5A, 0x64),
    };

    public string Id { get; }

    public string Badge { get; }

    public IBrush Accent { get; }

    public string Detail { get; }

    public string Reason { get; }

    public bool HasReason { get; }

    public string Evidence { get; }

    public bool HasEvidence { get; }
}
