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
/// </remarks>
public sealed class CheckRow
{
    public CheckRow(InspectionCheck check)
    {
        ArgumentNullException.ThrowIfNull(check);

        Id = check.Id;
        Badge = check.Status switch
        {
            CheckStatus.Passed => "PASS",
            CheckStatus.Failed => "FAIL",
            CheckStatus.Inconclusive => "UNKNOWN",
            CheckStatus.NotApplicable => "N/A",
            _ => "N/A",
        };

        Accent = check.Status switch
        {
            CheckStatus.Passed => new SolidColorBrush(Color.FromRgb(0x4C, 0xAF, 0x50)),
            CheckStatus.Failed => new SolidColorBrush(Color.FromRgb(0xE5, 0x39, 0x35)),
            CheckStatus.Inconclusive => new SolidColorBrush(Color.FromRgb(0xFF, 0xB3, 0x00)),
            _ => new SolidColorBrush(Color.FromRgb(0x78, 0x90, 0x9C)),
        };

        Detail = check.Detail;
        Reason = check.ReasonCode ?? string.Empty;
        HasReason = check.ReasonCode is not null;

        Evidence = string.Join(
            Environment.NewLine,
            check.Evidence.Select(item => $"{item.Label}: {item.Value}"));

        HasEvidence = check.Evidence.Count > 0;
    }

    public string Id { get; }

    public string Badge { get; }

    public IBrush Accent { get; }

    public string Detail { get; }

    public string Reason { get; }

    public bool HasReason { get; }

    public string Evidence { get; }

    public bool HasEvidence { get; }
}
