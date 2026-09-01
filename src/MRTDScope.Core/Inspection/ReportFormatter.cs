using System.Globalization;
using System.Text;

namespace MRTDScope.Core.Inspection;

/// <summary>
/// Renders an inspection report for people rather than machines.
/// </summary>
/// <remarks>
/// Shared by the CLI, the desktop application and the Android head, so all three present
/// the same thing. That matters more than saving duplication: three surfaces that
/// summarise the same report differently would eventually disagree about what a document
/// said, and the one an operator happened to be looking at would decide the outcome.
/// <para>
/// There is deliberately no overall verdict line. The summary counts statuses and stops
/// there — "passport valid" is not a claim this or any reader can make, and offering one
/// would undo the separation the whole check vocabulary exists to preserve.
/// </para>
/// </remarks>
public static class ReportFormatter
{
    /// <summary>Renders the report as plain text.</summary>
    /// <param name="report">The report to render.</param>
    /// <param name="includeEvidence">Whether to list each check's supporting observations.</param>
    public static string ToText(InspectionReport report, bool includeEvidence = true)
    {
        ArgumentNullException.ThrowIfNull(report);

        StringBuilder text = new();

        foreach (InspectionCheck check in report.Checks)
        {
            text.Append(CultureInfo.InvariantCulture, $"{Badge(check.Status)}  {check.Id}");

            if (check.ReasonCode is not null)
            {
                text.Append(CultureInfo.InvariantCulture, $"  ({check.ReasonCode})");
            }

            text.AppendLine();
            text.Append("        ").AppendLine(check.Detail);

            if (includeEvidence)
            {
                foreach (Evidence evidence in check.Evidence)
                {
                    text.Append(CultureInfo.InvariantCulture,
                        $"          {evidence.Label}: {evidence.Value}");
                    text.AppendLine();
                }
            }

            text.AppendLine();
        }

        text.AppendLine(Summarize(report));

        return text.ToString();
    }

    /// <summary>
    /// A one-line count of outcomes.
    /// </summary>
    /// <remarks>
    /// Counts, never a verdict. An operator reading "3 failed" knows to look; an operator
    /// reading "REJECTED" has been told a conclusion the tool is not entitled to reach.
    /// </remarks>
    public static string Summarize(InspectionReport report)
    {
        ArgumentNullException.ThrowIfNull(report);

        IEnumerable<string> parts = report.Summary
            .OrderBy(pair => pair.Key, StringComparer.Ordinal)
            .Select(pair => $"{pair.Value} {Describe(pair.Key)}");

        return $"{report.Checks.Count} checks: {string.Join(", ", parts)}.";
    }

    /// <summary>The status name as it should read in a sentence.</summary>
    private static string Describe(string status) => status switch
    {
        nameof(CheckStatus.NotApplicable) => "not applicable",
        _ => status.ToLowerInvariant(),
    };

    /// <summary>A fixed-width status badge, so the check ids line up when scanned.</summary>
    public static string Badge(CheckStatus status) => status switch
    {
        CheckStatus.Passed => "PASS   ",
        CheckStatus.Failed => "FAIL   ",
        CheckStatus.Inconclusive => "UNKNOWN",
        CheckStatus.NotApplicable => "N/A    ",
        CheckStatus.Unavailable => "N/A    ",
        _ => "?      ",
    };
}
