using System.Collections.ObjectModel;
using System.Text.Json.Serialization;

namespace MRTDScope.Core.Inspection;

/// <summary>
/// One named security check and its outcome.
/// </summary>
/// <remarks>
/// This type is the enforcement point for the project's binding correctness rule
/// (NFR1, D003): <b>no check may report success without having performed it.</b>
/// <para>
/// The constructor is private and the only route to <see cref="CheckStatus.Passed"/> is
/// <see cref="Passed"/>, which rejects an empty evidence list. A stub cannot report
/// success, because a stub has nothing to report. The rule is therefore a property of
/// the type rather than a convention reviewers must remember — which matters, because
/// the code this project harvests from contained exactly that defect: two protocol
/// implementations that were comment blocks returning <c>true</c>.
/// </para>
/// </remarks>
public sealed class InspectionCheck
{
    private static readonly ReadOnlyCollection<Evidence> NoEvidence =
        new([]);

    private InspectionCheck(
        string id,
        CheckStatus status,
        string? reasonCode,
        string detail,
        IReadOnlyList<Evidence> evidence)
    {
        Id = id;
        Status = status;
        ReasonCode = reasonCode;
        Detail = detail;
        Evidence = evidence;
    }

    /// <summary>The stable check identifier. See <see cref="CheckIds"/>.</summary>
    [JsonPropertyOrder(0)]
    public string Id { get; }

    /// <summary>The outcome.</summary>
    [JsonPropertyOrder(1)]
    [JsonConverter(typeof(JsonStringEnumConverter<CheckStatus>))]
    public CheckStatus Status { get; }

    /// <summary>
    /// Why the check did not pass. See <see cref="ReasonCodes"/>. Always <c>null</c>
    /// for a passing check and never <c>null</c> otherwise.
    /// </summary>
    [JsonPropertyOrder(2)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ReasonCode { get; }

    /// <summary>Human-readable explanation of the outcome.</summary>
    [JsonPropertyOrder(3)]
    public string Detail { get; }

    /// <summary>Supporting observations. Never empty for a passing check.</summary>
    [JsonPropertyOrder(4)]
    public IReadOnlyList<Evidence> Evidence { get; }

    /// <summary>
    /// Records a check that ran and succeeded.
    /// </summary>
    /// <param name="id">The check identifier, from <see cref="CheckIds"/>.</param>
    /// <param name="detail">What succeeded, in operator-readable terms.</param>
    /// <param name="evidence">
    /// What was actually observed. At least one item is required: this is what makes a
    /// silent success unrepresentable.
    /// </param>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="evidence"/> is empty, which would mean claiming
    /// success without having observed anything.
    /// </exception>
    public static InspectionCheck Passed(string id, string detail, params Evidence[] evidence)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        ArgumentException.ThrowIfNullOrWhiteSpace(detail);
        ArgumentNullException.ThrowIfNull(evidence);

        if (evidence.Length == 0)
        {
            throw new ArgumentException(
                $"Check '{id}' cannot report Passed without evidence. A check that " +
                "observed nothing has not verified anything (NFR1).",
                nameof(evidence));
        }

        return new InspectionCheck(
            id,
            CheckStatus.Passed,
            reasonCode: null,
            detail,
            new ReadOnlyCollection<Evidence>([.. evidence]));
    }

    /// <summary>
    /// Records a check that ran and found the document wanting.
    /// </summary>
    public static InspectionCheck Failed(
        string id,
        string reasonCode,
        string detail,
        params Evidence[] evidence) =>
        Create(id, CheckStatus.Failed, reasonCode, detail, evidence);

    /// <summary>
    /// Records a check that could not reach a verdict, typically for want of a trust
    /// anchor. This is never a statement about the document (D005).
    /// </summary>
    public static InspectionCheck Inconclusive(
        string id,
        string reasonCode,
        string detail,
        params Evidence[] evidence) =>
        Create(id, CheckStatus.Inconclusive, reasonCode, detail, evidence);

    /// <summary>
    /// Records a check that does not apply to this document.
    /// </summary>
    public static InspectionCheck NotApplicable(string id, string reasonCode, string detail) =>
        Create(id, CheckStatus.NotApplicable, reasonCode, detail, []);

    /// <summary>
    /// Records a check this build cannot perform. Extended Access Control reports this
    /// because MRTDScope holds no Inspection System certificate chain (D008).
    /// </summary>
    public static InspectionCheck Unavailable(string id, string reasonCode, string detail) =>
        Create(id, CheckStatus.Unavailable, reasonCode, detail, []);

    private static InspectionCheck Create(
        string id,
        CheckStatus status,
        string reasonCode,
        string detail,
        Evidence[] evidence)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        ArgumentException.ThrowIfNullOrWhiteSpace(reasonCode);
        ArgumentException.ThrowIfNullOrWhiteSpace(detail);
        ArgumentNullException.ThrowIfNull(evidence);

        return new InspectionCheck(
            id,
            status,
            reasonCode,
            detail,
            evidence.Length == 0
                ? NoEvidence
                : new ReadOnlyCollection<Evidence>([.. evidence]));
    }
}
