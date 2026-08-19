using MRTDScope.Core.Apdu;
using MRTDScope.Core.Transport;

namespace MRTDScope.Core.Protocol.SecureMessaging;

/// <summary>
/// Wraps a transport so that every command is protected and every response verified.
/// </summary>
/// <remarks>
/// Modelling the secure channel as a decorator over <see cref="ICardTransport"/> rather
/// than as a mode inside the reader means the LDS reading code is written once, against
/// a plain transport, and works identically whether the channel is unprotected, BAC's
/// 3DES, or PACE's AES. It also means the M3 fault corpus can corrupt a MAC by wrapping
/// a tampering transport at exactly the layer a real attacker would sit at.
/// </remarks>
public sealed class SecureMessagingTransport : ICardTransport
{
    private readonly ICardTransport _inner;
    private readonly ISecureMessaging _secureMessaging;
    private readonly bool _ownsInner;

    /// <param name="inner">The underlying transport carrying the protected APDUs.</param>
    /// <param name="secureMessaging">The established channel.</param>
    /// <param name="ownsInner">
    /// Whether disposing this transport should dispose the inner one. False by default,
    /// because the caller normally still owns the reader connection.
    /// </param>
    public SecureMessagingTransport(
        ICardTransport inner,
        ISecureMessaging secureMessaging,
        bool ownsInner = false)
    {
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentNullException.ThrowIfNull(secureMessaging);

        _inner = inner;
        _secureMessaging = secureMessaging;
        _ownsInner = ownsInner;
    }

    public string Name => $"{_inner.Name} [{_secureMessaging.Algorithm}]";

    public bool IsConnected => _inner.IsConnected;

    public ReadOnlyMemory<byte> AnswerToReset => _inner.AnswerToReset;

    public void Connect() => _inner.Connect();

    public ResponseApdu Transmit(CommandApdu command)
    {
        ArgumentNullException.ThrowIfNull(command);

        CommandApdu protectedCommand = _secureMessaging.Protect(command);
        ResponseApdu protectedResponse = _inner.Transmit(protectedCommand);
        return _secureMessaging.Unprotect(protectedResponse);
    }

    public void Disconnect() => _inner.Disconnect();

    public void Dispose()
    {
        if (_ownsInner)
        {
            _inner.Dispose();
        }
    }
}
