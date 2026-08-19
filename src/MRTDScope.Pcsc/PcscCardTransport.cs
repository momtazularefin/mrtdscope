using System.Diagnostics;
using MRTDScope.Core.Apdu;
using MRTDScope.Core.Errors;
using MRTDScope.Core.Transport;
using PCSC;
using PCSC.Exceptions;

namespace MRTDScope.Pcsc;

/// <summary>
/// Carries APDUs over a PC/SC contactless reader on Windows and Linux.
/// </summary>
public sealed class PcscCardTransport : ICardTransport
{
    /// <summary>
    /// Receive buffer size. Sized for an extended-length response plus its status word,
    /// rather than the 256 bytes the harvested code used, which would truncate any
    /// extended read.
    /// </summary>
    private const int ReceiveBufferSize = 65538;

    private readonly string _readerName;
    private readonly IApduTracer _tracer;

    private ISCardContext? _context;
    private ICardReader? _reader;
    private byte[] _answerToReset = [];
    private int _sequence;

    public PcscCardTransport(string readerName, IApduTracer? tracer = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(readerName);

        _readerName = readerName;
        _tracer = tracer ?? NullApduTracer.Instance;
    }

    public string Name => _readerName;

    public bool IsConnected => _reader is not null;

    public ReadOnlyMemory<byte> AnswerToReset => _answerToReset;

    public void Connect()
    {
        if (IsConnected)
        {
            return;
        }

        try
        {
            _context = ContextFactory.Instance.Establish(SCardScope.System);
            _reader = _context.ConnectReader(_readerName, SCardShareMode.Shared, SCardProtocol.Any);
            _answerToReset = _reader.GetStatus()?.GetAtr() ?? [];
        }
        catch (PCSCException exception)
        {
            Disconnect();
            throw new CardTransportException(
                $"Could not connect to reader '{_readerName}'. Check that a card is " +
                "present and the reader is not in use by another application.",
                exception);
        }
    }

    public ResponseApdu Transmit(CommandApdu command)
    {
        ArgumentNullException.ThrowIfNull(command);

        if (_reader is null)
        {
            throw new CardTransportException(
                "Transmit was called before Connect; there is no card connection.");
        }

        byte[] request = command.ToBytes();
        byte[] buffer = new byte[ReceiveBufferSize];

        long startedAt = Stopwatch.GetTimestamp();

        int received;
        try
        {
            received = _reader.Transmit(request, buffer);
        }
        catch (PCSCException exception)
        {
            throw new CardTransportException(
                "The card exchange failed. The document may have been removed from the reader.",
                exception);
        }

        TimeSpan elapsed = Stopwatch.GetElapsedTime(startedAt);

        if (received < 2)
        {
            throw new CardTransportException(
                $"The reader returned {received} bytes; a response APDU is at least 2.");
        }

        byte[] response = buffer[..received];
        _tracer.Record(new ApduExchange(++_sequence, request, response, elapsed));

        return ResponseApdu.Parse(response);
    }

    public void Disconnect()
    {
        _reader?.Dispose();
        _reader = null;

        _context?.Dispose();
        _context = null;

        _answerToReset = [];
    }

    public void Dispose() => Disconnect();
}
