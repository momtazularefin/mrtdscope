using MRTDScope.Core.Apdu;

namespace MRTDScope.Core.Transport;

/// <summary>
/// The single boundary between MRTDScope's protocol code and whatever is carrying APDUs.
/// </summary>
/// <remarks>
/// Everything above this interface is transport-agnostic (FR1). PC/SC on desktop,
/// Android NFC IsoDep, the secure-messaging decorator, and the synthetic chip that
/// arrives in M3 are all peers behind it.
/// <para>
/// That last one is the point. Because the synthetic chip implements this interface
/// rather than being injected further up, the fault corpus exercises the real BAC,
/// PACE, and Passive Authentication code paths byte for byte — the same code that talks
/// to a physical passport. A test double placed any higher would prove only that the
/// test double works.
/// </para>
/// </remarks>
public interface ICardTransport : IDisposable
{
    /// <summary>A human-readable identifier for the reader or emulated chip.</summary>
    string Name { get; }

    /// <summary>Whether a card is currently connected and able to exchange APDUs.</summary>
    bool IsConnected { get; }

    /// <summary>
    /// The Answer To Reset or Answer To Select, when the transport exposes one. Empty
    /// where the platform does not surface it.
    /// </summary>
    ReadOnlyMemory<byte> AnswerToReset { get; }

    /// <summary>Establishes the card connection.</summary>
    void Connect();

    /// <summary>Sends one command APDU and returns the card's response.</summary>
    /// <exception cref="Errors.CardTransportException">
    /// The exchange could not complete. A card that answers with a non-success status
    /// word has completed the exchange and does not throw.
    /// </exception>
    ResponseApdu Transmit(CommandApdu command);

    /// <summary>Releases the card connection, leaving the transport reusable.</summary>
    void Disconnect();
}
