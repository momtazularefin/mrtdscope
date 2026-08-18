using System.Text.Json.Serialization;

namespace MRTDScope.Core.Inspection;

/// <summary>
/// A single piece of supporting material for a check's outcome.
/// </summary>
/// <remarks>
/// Evidence is what separates an instrument reading from an assertion. A passing check
/// must say what it actually observed — the signing algorithm it verified under, the
/// subject of the anchor it chained to, the digest it compared.
/// <para>
/// Evidence is rendered to operators and written to reports, so it must never carry key
/// material, a password, a CAN, or an MRZ (NFR7). Record identifiers and digests, not
/// secrets.
/// </para>
/// </remarks>
/// <param name="Label">A short, stable name for what was observed.</param>
/// <param name="Value">The observation itself, already safe to display.</param>
public sealed record Evidence(
    [property: JsonPropertyOrder(0)] string Label,
    [property: JsonPropertyOrder(1)] string Value)
{
    /// <summary>
    /// Creates evidence, rejecting an empty label or value so that a check cannot
    /// satisfy its evidence requirement with a placeholder.
    /// </summary>
    public static Evidence Of(string label, string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(label);
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return new Evidence(label, value);
    }
}
