using System.Collections.ObjectModel;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace MRTDScope.Core.Inspection;

/// <summary>
/// The complete result of one inspection: every check that was considered, in a stable
/// order, with the evidence behind each outcome.
/// </summary>
/// <remarks>
/// The report deliberately has no single overall boolean. An operator asking "is this
/// passport genuine?" is asking a question the chip cannot answer on its own, and
/// flattening the checks into one verdict is how a tool stops being auditable. What the
/// report offers instead is <see cref="Summary"/>: a count per status, so a consumer can
/// apply its own policy.
/// </remarks>
public sealed class InspectionReport
{
    /// <summary>The report contract version. Consumers match on check ids and reason codes.</summary>
    public const string CurrentSchemaVersion = "1.0";

    private InspectionReport(
        string schemaVersion,
        IReadOnlyList<InspectionCheck> checks,
        long elapsedMilliseconds)
    {
        SchemaVersion = schemaVersion;
        Checks = checks;
        ElapsedMilliseconds = elapsedMilliseconds;
    }

    /// <summary>The report contract version.</summary>
    [JsonPropertyOrder(0)]
    public string SchemaVersion { get; }

    /// <summary>Every check considered, in the order the inspection performed them.</summary>
    [JsonPropertyOrder(1)]
    public IReadOnlyList<InspectionCheck> Checks { get; }

    /// <summary>
    /// Counts by status. Present so consumers can apply their own acceptance policy
    /// without the report pretending to have one.
    /// </summary>
    [JsonPropertyOrder(2)]
    public IReadOnlyDictionary<string, int> Summary =>
        Checks
            .GroupBy(check => check.Status)
            .OrderBy(group => group.Key)
            .ToDictionary(group => group.Key.ToString(), group => group.Count());

    /// <summary>
    /// Wall-clock duration of the inspection.
    /// </summary>
    /// <remarks>
    /// This is the one field exempt from the determinism requirement (NFR4), and it is
    /// excluded from <see cref="ToDeterministicJson"/> for exactly that reason.
    /// </remarks>
    [JsonPropertyOrder(3)]
    public long ElapsedMilliseconds { get; }

    /// <summary>
    /// Creates a report from the checks an inspection produced.
    /// </summary>
    public static InspectionReport Create(
        IEnumerable<InspectionCheck> checks,
        long elapsedMilliseconds = 0)
    {
        ArgumentNullException.ThrowIfNull(checks);
        ArgumentOutOfRangeException.ThrowIfNegative(elapsedMilliseconds);

        return new InspectionReport(
            CurrentSchemaVersion,
            new ReadOnlyCollection<InspectionCheck>([.. checks]),
            elapsedMilliseconds);
    }

    /// <summary>
    /// Whether any check actively found the document wanting. Distinct from "not all
    /// checks passed", because an inconclusive or unavailable check is not a rejection.
    /// </summary>
    public bool HasFailure => Checks.Any(check => check.Status == CheckStatus.Failed);

    /// <summary>
    /// Serializes the report to JSON, omitting the timing field so that two inspections
    /// of the same document under the same configuration produce byte-identical output
    /// (NFR4). This is the form the fault corpus asserts against.
    /// </summary>
    public string ToDeterministicJson() =>
        JsonSerializer.Serialize(
            new DeterministicView(SchemaVersion, Checks, Summary),
            DeterministicOptions);

    private static readonly JsonSerializerOptions DeterministicOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private sealed record DeterministicView(
        [property: JsonPropertyOrder(0)] string SchemaVersion,
        [property: JsonPropertyOrder(1)] IReadOnlyList<InspectionCheck> Checks,
        [property: JsonPropertyOrder(2)] IReadOnlyDictionary<string, int> Summary);
}
