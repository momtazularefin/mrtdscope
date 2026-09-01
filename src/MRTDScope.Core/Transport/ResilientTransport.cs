using MRTDScope.Core.Apdu;
using MRTDScope.Core.Errors;

namespace MRTDScope.Core.Transport;

/// <summary>How a transport should behave when an exchange fails.</summary>
/// <param name="MaxAttempts">Total attempts per command, including the first.</param>
/// <param name="RetryDelay">Pause between attempts, giving a re-presented tag time to settle.</param>
public sealed record TransportResilience(int MaxAttempts = 3, TimeSpan? RetryDelay = null)
{
    /// <summary>Contactless readers on a desk: failures are rare and usually fatal.</summary>
    public static TransportResilience Wired { get; } = new(MaxAttempts: 1);

    /// <summary>
    /// A phone held against a document by hand, where brief tag loss is routine.
    /// </summary>
    public static TransportResilience Handheld { get; } =
        new(MaxAttempts: 4, RetryDelay: TimeSpan.FromMilliseconds(120));
}

/// <summary>
/// Retries transient transport failures without letting a retry corrupt a secure session.
/// </summary>
/// <remarks>
/// On a phone the document is held against the back of the handset by hand, so it moves.
/// A read of an 18 KB DG2 takes a hundred-odd exchanges and several seconds, and losing
/// the tag part-way through is ordinary rather than exceptional. Failing the whole
/// inspection because the holder's grip shifted would make the tool unusable in the field.
/// <para>
/// <b>This decorator must sit below secure messaging, never above it.</b> Every protected
/// command advances the send sequence counter, so re-sending an already-transmitted
/// protected APDU desynchronises the channel and every subsequent command fails its
/// checksum — a far worse outcome than the original error. Placed below the secure
/// channel, a retry re-sends bytes the chip never successfully processed, which is exactly
/// what recovery should mean.
/// </para>
/// </remarks>
public sealed class ResilientTransport : ICardTransport
{
    private readonly ICardTransport _inner;
    private readonly TransportResilience _policy;
    private readonly Action<TimeSpan> _wait;

    public ResilientTransport(
        ICardTransport inner,
        TransportResilience? policy = null,
        Action<TimeSpan>? wait = null)
    {
        ArgumentNullException.ThrowIfNull(inner);

        _inner = inner;
        _policy = policy ?? TransportResilience.Handheld;

        // Injectable so tests exercise the retry policy without actually sleeping.
        _wait = wait ?? (delay => Thread.Sleep(delay));
    }

    /// <summary>How many exchanges had to be retried, for reporting.</summary>
    public int RetriedExchanges { get; private set; }

    public string Name => _inner.Name;

    public bool IsConnected => _inner.IsConnected;

    public ReadOnlyMemory<byte> AnswerToReset => _inner.AnswerToReset;

    public void Connect() => _inner.Connect();

    public ResponseApdu Transmit(CommandApdu command)
    {
        ArgumentNullException.ThrowIfNull(command);

        CardTransportException? last = null;

        for (int attempt = 1; attempt <= _policy.MaxAttempts; attempt++)
        {
            try
            {
                ResponseApdu response = _inner.Transmit(command);

                if (attempt > 1)
                {
                    RetriedExchanges++;
                }

                return response;
            }
            catch (CardTransportException exception)
            {
                last = exception;

                if (attempt < _policy.MaxAttempts && _policy.RetryDelay is { } delay)
                {
                    // Reconnecting is what actually recovers a lost tag; without it the
                    // retry hits the same dead handle.
                    TryReconnect();
                    _wait(delay);
                }
            }
        }

        throw new CardTransportException(
            $"The exchange failed after {_policy.MaxAttempts} attempt(s). On a handheld " +
            "reader this usually means the document moved away from the antenna.",
            last!);
    }

    private void TryReconnect()
    {
        try
        {
            _inner.Disconnect();
            _inner.Connect();
        }
        catch (CardTransportException)
        {
            // The tag is still gone. The next attempt will fail and be counted; there is
            // nothing useful to report from a failed recovery attempt itself.
        }
    }

    public void Disconnect() => _inner.Disconnect();

    public void Dispose() => _inner.Dispose();
}
