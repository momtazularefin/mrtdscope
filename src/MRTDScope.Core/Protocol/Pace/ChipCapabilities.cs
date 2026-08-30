using MRTDScope.Core.Errors;
using MRTDScope.Core.Lds;
using MRTDScope.Core.Transport;

namespace MRTDScope.Core.Protocol.Pace;

/// <summary>What a chip says it supports, read before any access control is attempted.</summary>
/// <param name="CardAccessPresent">Whether EF.CardAccess could be read.</param>
/// <param name="SecurityInfos">Its parsed contents, when present.</param>
/// <param name="Detail">Operator-readable explanation.</param>
public sealed record ChipCapabilities(
    bool CardAccessPresent,
    SecurityInfos? SecurityInfos,
    string Detail)
{
    /// <summary>
    /// Whether PACE is advertised. A chip without EF.CardAccess is BAC-only.
    /// </summary>
    public bool SupportsPace => SecurityInfos?.SupportsPace ?? false;
}

/// <summary>
/// Probes a chip for the protocols it offers.
/// </summary>
/// <remarks>
/// EF.CardAccess is deliberately readable with **no access control at all** — that is its
/// entire purpose, since a terminal must know which protocols exist before it can choose
/// one. That makes this the cheapest and most definitive way to answer "does this
/// document support PACE?", needing no MRZ, no key, and no cryptography.
/// <para>
/// Its absence is a meaningful answer rather than a failure: a chip with no EF.CardAccess
/// predates Supplemental Access Control and is BAC-only.
/// </para>
/// </remarks>
public static class ChipCapabilityProbe
{
    /// <summary>
    /// Reads EF.CardAccess and reports what the chip advertises.
    /// </summary>
    /// <remarks>
    /// Call after selecting the eMRTD application and before attempting access control.
    /// </remarks>
    public static ChipCapabilities Probe(ICardTransport transport)
    {
        ArgumentNullException.ThrowIfNull(transport);

        LdsReader reader = new(transport);
        LdsReader.ReadResult result = reader.ReadFile(DataGroup.CardAccess);

        if (!result.Success)
        {
            // EF.CardAccess lives under the Master File. If the eMRTD application is
            // already selected, the file is not visible under the current DF, so climb
            // back to the MF and look again before concluding it is absent.
            MrtdApplication.SelectMasterFile(transport);
            result = reader.ReadFile(DataGroup.CardAccess);
        }

        if (!result.Success)
        {
            return new ChipCapabilities(
                false,
                null,
                $"EF.CardAccess could not be read ({result.StatusWord}). The chip predates " +
                "Supplemental Access Control, so BAC is the only way in.");
        }

        try
        {
            SecurityInfos infos = SecurityInfos.Parse(result.Content.Span);

            return new ChipCapabilities(
                true,
                infos,
                infos.SupportsPace
                    ? $"EF.CardAccess advertises {infos.PaceInfos.Count} PACE variant(s)."
                    : "EF.CardAccess is present but advertises no PACE variant.");
        }
        catch (MrtdEncodingException exception)
        {
            return new ChipCapabilities(
                true,
                null,
                $"EF.CardAccess was read but could not be parsed: {exception.Message}");
        }
    }
}
