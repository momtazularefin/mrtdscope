namespace MRTDScope.Core.Protocol.SecureMessaging;

/// <summary>
/// The send sequence counter, incremented once before each protected command and once
/// before each protected response.
/// </summary>
/// <remarks>
/// The SSC is what makes replay detectable: a captured protected APDU replayed later
/// carries a MAC computed over a counter value that has moved on. Keeping it in its own
/// type, with mutation only through <see cref="Increment"/>, prevents the classic bug of
/// incrementing on the command path but forgetting the response path — which desynchronises
/// the channel and produces MAC failures that look like a damaged chip.
/// </remarks>
public sealed class SendSequenceCounter
{
    private readonly byte[] _value;

    public SendSequenceCounter(ReadOnlySpan<byte> initialValue)
    {
        if (initialValue.Length is not (8 or 16))
        {
            throw new ArgumentException(
                $"The send sequence counter is 8 bytes for 3DES or 16 for AES; got {initialValue.Length}.",
                nameof(initialValue));
        }

        _value = initialValue.ToArray();
    }

    /// <summary>The counter's current value.</summary>
    public ReadOnlySpan<byte> Value => _value;

    public int Length => _value.Length;

    /// <summary>Increments the counter as a big-endian integer, wrapping on overflow.</summary>
    public void Increment()
    {
        for (int i = _value.Length - 1; i >= 0; i--)
        {
            if (++_value[i] != 0)
            {
                return;
            }
        }
    }

    public override string ToString() => Convert.ToHexString(_value);
}
