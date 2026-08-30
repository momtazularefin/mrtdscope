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

    /// <summary>The Master File identifier.</summary>
    private static ReadOnlySpan<byte> MasterFileId => [0x3F, 0x00];

    /// <summary>
    /// Selects the Master File, the root of the card's file system.
    /// </summary>
    /// <remarks>
    /// EF.CardAccess sits under the MF rather than under the LDS1 application, so a
    /// terminal that has already selected the eMRTD AID must come back up here to read
    /// it. Chips differ on whether they accept selection by identifier or require the
    /// dedicated "select MF" form with an empty data field, so both are attempted.
    /// </remarks>
    public static ResponseApdu SelectMasterFile(ICardTransport transport)
    {
        ArgumentNullException.ThrowIfNull(transport);

        ResponseApdu byIdentifier = transport.Transmit(new CommandApdu(
            ClaPlain, InsSelect, p1: 0x00, p2: 0x0C, MasterFileId.ToArray()));

        return byIdentifier.IsSuccess
            ? byIdentifier
            : transport.Transmit(new CommandApdu(ClaPlain, InsSelect, p1: 0x00, p2: 0x0C));
    }

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
