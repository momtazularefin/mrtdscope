using System.Security.Cryptography;

namespace MRTDScope.Core.Tests.Support;

/// <summary>
/// Returns a scripted byte sequence instead of real randomness, so that a published
/// worked example with fixed nonces can be reproduced exactly.
/// </summary>
/// <remarks>
/// Test-only by construction: it lives in the test assembly, so no production code path
/// can reach it. The protocol accepts an injected generator purely to make the ICAO
/// vectors reproducible.
/// </remarks>
public sealed class FixedRandom : RandomNumberGenerator
{
    private readonly Queue<byte[]> _values;

    public FixedRandom(params byte[][] values)
    {
        ArgumentNullException.ThrowIfNull(values);
        _values = new Queue<byte[]>(values);
    }

    public override void GetBytes(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);

        if (_values.Count == 0)
        {
            throw new InvalidOperationException("FixedRandom ran out of scripted values.");
        }

        byte[] next = _values.Dequeue();

        if (next.Length != data.Length)
        {
            throw new InvalidOperationException(
                $"FixedRandom was asked for {data.Length} bytes but the next scripted " +
                $"value is {next.Length}.");
        }

        next.CopyTo(data, 0);
    }
}
