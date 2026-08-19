using MRTDScope.Core.Apdu;
using MRTDScope.Core.Transport;

namespace MRTDScope.Core.Tests.Support;

/// <summary>
/// A transport that answers from a fixed script and records what it was asked.
/// </summary>
/// <remarks>
/// This is a test double for pinning exact wire bytes against published test vectors,
/// not a chip model. The real emulated chip arrives in M3; this one only replays a
/// recorded exchange and asserts the command matched.
/// </remarks>
public sealed class ScriptedTransport : ICardTransport
{
    private readonly Queue<Exchange> _script;

    public ScriptedTransport(params Exchange[] script)
    {
        ArgumentNullException.ThrowIfNull(script);
        _script = new Queue<Exchange>(script);
    }

    /// <param name="ExpectedCommand">The command bytes the caller must send, as hex.</param>
    /// <param name="Response">The response bytes to answer with, as hex.</param>
    public readonly record struct Exchange(string ExpectedCommand, string Response);

    public List<byte[]> SentCommands { get; } = [];

    public string Name => "scripted";

    public bool IsConnected { get; private set; }

    public ReadOnlyMemory<byte> AnswerToReset => default;

    public void Connect() => IsConnected = true;

    public ResponseApdu Transmit(CommandApdu command)
    {
        ArgumentNullException.ThrowIfNull(command);

        byte[] sent = command.ToBytes();
        SentCommands.Add(sent);

        if (_script.Count == 0)
        {
            throw new InvalidOperationException(
                $"Unexpected command {Convert.ToHexString(sent)}; the script is exhausted.");
        }

        Exchange next = _script.Dequeue();
        string actual = Convert.ToHexString(sent);
        string expected = next.ExpectedCommand.Replace(" ", string.Empty, StringComparison.Ordinal);

        if (!string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"Command mismatch.{Environment.NewLine}" +
                $"  expected: {expected}{Environment.NewLine}" +
                $"  actual:   {actual}");
        }

        return ResponseApdu.Parse(
            Convert.FromHexString(next.Response.Replace(" ", string.Empty, StringComparison.Ordinal)));
    }

    public void Disconnect() => IsConnected = false;

    public void Dispose() => Disconnect();

    /// <summary>Whether every scripted exchange was consumed.</summary>
    public bool IsExhausted => _script.Count == 0;
}
