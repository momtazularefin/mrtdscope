using Android.Nfc;
using Android.Nfc.Tech;
using MRTDScope.Core.Apdu;
using MRTDScope.Core.Errors;
using MRTDScope.Core.Transport;
using IOException = Java.IO.IOException;

namespace MRTDScope.Droid;

/// <summary>
/// Carries APDUs over Android NFC using ISO-DEP (ISO/IEC 14443-4).
/// </summary>
/// <remarks>
/// Deliberately thin. Everything that could plausibly be wrong — retry policy, tag-loss
/// recovery, chunk sizing, the protocols themselves — lives in
/// <c>MRTDScope.Core</c>, where 209 tests exercise it on every commit. This class only
/// translates between <see cref="ICardTransport"/> and the platform API, because it is the
/// one piece that cannot run in CI.
/// <para>
/// Wrap it in <see cref="ResilientTransport"/> with
/// <see cref="TransportResilience.Handheld"/>: a phone is held against the document by
/// hand, and an 18 KB DG2 read takes a hundred-odd exchanges over several seconds, so
/// brief tag loss is ordinary rather than exceptional.
/// </para>
/// </remarks>
public sealed class IsoDepTransport : ICardTransport
{
    /// <summary>
    /// Transceive timeout in milliseconds.
    /// </summary>
    /// <remarks>
    /// Android's default is around 300 ms on many devices, which is too short: a chip
    /// performing PACE key agreement or signing an Active Authentication challenge can
    /// take noticeably longer, and the resulting timeout looks exactly like tag loss.
    /// </remarks>
    public const int DefaultTimeoutMilliseconds = 10_000;

    private readonly Tag _tag;
    private readonly IApduTracer _tracer;
    private readonly int _timeout;

    private IsoDep? _isoDep;
    private int _sequence;

    public IsoDepTransport(
        Tag tag,
        IApduTracer? tracer = null,
        int timeoutMilliseconds = DefaultTimeoutMilliseconds)
    {
        ArgumentNullException.ThrowIfNull(tag);

        _tag = tag;
        _tracer = tracer ?? NullApduTracer.Instance;
        _timeout = timeoutMilliseconds;
    }

    /// <summary>Whether a discovered tag speaks ISO-DEP at all.</summary>
    public static bool IsSupported(Tag tag) => IsoDep.Get(tag) is not null;

    public string Name => "android-nfc";

    public bool IsConnected => _isoDep?.IsConnected ?? false;

    public ReadOnlyMemory<byte> AnswerToReset =>
        _isoDep?.GetHiLayerResponse() ?? _isoDep?.GetHistoricalBytes() ?? [];

    public void Connect()
    {
        if (IsConnected)
        {
            return;
        }

        _isoDep = IsoDep.Get(_tag)
            ?? throw new CardTransportException(
                "This tag does not support ISO-DEP, so it is not an eMRTD chip.");

        try
        {
            _isoDep.Timeout = _timeout;
            _isoDep.Connect();
        }
        catch (IOException exception)
        {
            throw new CardTransportException(
                "Could not connect to the document. Hold the phone still against the " +
                "datapage — the antenna is usually near the centre of the back.",
                exception);
        }
    }

    public ResponseApdu Transmit(CommandApdu command)
    {
        ArgumentNullException.ThrowIfNull(command);

        if (_isoDep is null || !_isoDep.IsConnected)
        {
            throw new CardTransportException(
                "Transmit was called with no connected tag.");
        }

        byte[] request = command.ToBytes();
        long startedAt = System.Diagnostics.Stopwatch.GetTimestamp();

        byte[]? response;
        try
        {
            response = _isoDep.Transceive(request);
        }
        catch (TagLostException exception)
        {
            // Surfaced as a transport failure so ResilientTransport can reconnect and
            // retry, which is the ordinary case on a handheld reader.
            throw new CardTransportException(
                "The document moved out of range mid-exchange.", exception);
        }
        catch (IOException exception)
        {
            throw new CardTransportException(
                "The NFC exchange failed.", exception);
        }

        if (response is null || response.Length < 2)
        {
            throw new CardTransportException(
                $"The chip returned {response?.Length ?? 0} bytes; a response APDU is at least 2.");
        }

        _tracer.Record(new ApduExchange(
            ++_sequence,
            request,
            response,
            System.Diagnostics.Stopwatch.GetElapsedTime(startedAt)));

        return ResponseApdu.Parse(response);
    }

    public void Disconnect()
    {
        try
        {
            _isoDep?.Close();
        }
        catch (IOException)
        {
            // The tag is already gone; closing a dead handle is not worth reporting.
        }

        _isoDep = null;
    }

    public void Dispose()
    {
        Disconnect();
        _isoDep?.Dispose();
    }
}
