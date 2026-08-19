using MRTDScope.Core.Apdu;
using MRTDScope.Core.Transport;

namespace MRTDScope.Core.Protocol;

/// <summary>
/// Selection of the eMRTD application on the chip.
/// </summary>
public static class MrtdApplication
{
    /// <summary>
    /// The LDS1 eMRTD application identifier, ICAO Doc 9303 Part 10.
    /// </summary>
    public static ReadOnlySpan<byte> Lds1ApplicationId =>
        [0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01];

    private const byte ClaPlain = 0x00;
    private const byte InsSelect = 0xA4;

    /// <summary>
    /// Selects the LDS1 eMRTD application by AID.
    /// </summary>
    /// <remarks>
    /// P2 is 0x0C — "no response data" — because a chip that returns file control
    /// information here forces the terminal to parse an FCI template it does not need,
    /// and some chips answer 6A87 when asked for one.
    /// </remarks>
    public static ResponseApdu Select(ICardTransport transport)
    {
        ArgumentNullException.ThrowIfNull(transport);

        return transport.Transmit(new CommandApdu(
            ClaPlain,
            InsSelect,
            p1: 0x04,
            p2: 0x0C,
            Lds1ApplicationId.ToArray()));
    }
}
