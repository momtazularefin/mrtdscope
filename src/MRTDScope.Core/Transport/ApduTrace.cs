using System.Collections.ObjectModel;
using System.Globalization;
using MRTDScope.Core.Apdu;

namespace MRTDScope.Core.Transport;

/// <summary>One recorded command/response exchange.</summary>
/// <param name="Sequence">Position in the session, starting at 1.</param>
/// <param name="Command">The command bytes as transmitted.</param>
/// <param name="Response">The response bytes as received.</param>
/// <param name="Elapsed">How long the exchange took.</param>
public sealed record ApduExchange(
    int Sequence,
    ReadOnlyMemory<byte> Command,
    ReadOnlyMemory<byte> Response,
    TimeSpan Elapsed)
{
    /// <summary>The status word the card returned.</summary>
    public StatusWord StatusWord => Response.Length >= 2
        ? new StatusWord((ushort)((Response.Span[^2] << 8) | Response.Span[^1]))
        : default;
}

/// <summary>Receives APDU exchanges as they happen.</summary>
public interface IApduTracer
{
    void Record(ApduExchange exchange);
}

/// <summary>Discards everything. The default when no trace was requested.</summary>
public sealed class NullApduTracer : IApduTracer
{
    public static NullApduTracer Instance { get; } = new();

    private NullApduTracer()
    {
    }

    public void Record(ApduExchange exchange)
    {
    }
}

/// <summary>
/// Collects the session's exchanges in memory for reporting and debugging.
/// </summary>
/// <remarks>
/// Traces are shown to operators and written into reports, so <see cref="ToText"/>
/// redacts the payloads that carry key material (NFR7). The redaction is applied at
/// render time rather than at capture time so that a MAC mismatch can still be
/// diagnosed in a debugger from the retained bytes, while nothing sensitive reaches a
/// file or a screen.
/// </remarks>
public sealed class ApduTracer : IApduTracer
{
    private readonly List<ApduExchange> _exchanges = [];

    /// <summary>ISO/IEC 7816-4 INS byte for GET CHALLENGE.</summary>
    private const byte InsGetChallenge = 0x84;

    /// <summary>ISO/IEC 7816-4 INS byte for EXTERNAL AUTHENTICATE.</summary>
    private const byte InsExternalAuthenticate = 0x82;

    /// <summary>ISO/IEC 7816-4 INS byte for GENERAL AUTHENTICATE, used by PACE.</summary>
    private const byte InsGeneralAuthenticate = 0x86;

    /// <summary>ISO/IEC 7816-4 INS byte for INTERNAL AUTHENTICATE, used by Active Authentication.</summary>
    private const byte InsInternalAuthenticate = 0x88;

    public IReadOnlyList<ApduExchange> Exchanges => new ReadOnlyCollection<ApduExchange>(_exchanges);

    public void Record(ApduExchange exchange)
    {
        ArgumentNullException.ThrowIfNull(exchange);
        _exchanges.Add(exchange);
    }

    /// <summary>
    /// Renders the trace with key-bearing payloads replaced by a length marker.
    /// </summary>
    public string ToText()
    {
        System.Text.StringBuilder builder = new();

        foreach (ApduExchange exchange in _exchanges)
        {
            bool sensitive = CarriesKeyMaterial(exchange.Command.Span);

            builder.Append(CultureInfo.InvariantCulture, $"[{exchange.Sequence:D3}] >> ");
            builder.AppendLine(Render(exchange.Command.Span, sensitive, headerBytes: 4));

            builder.Append(CultureInfo.InvariantCulture, $"[{exchange.Sequence:D3}] << ");
            builder.AppendLine(Render(exchange.Response.Span, sensitive, headerBytes: 0));
        }

        return builder.ToString();
    }

    /// <summary>
    /// Whether a command's payload derives from, or reveals, session key material.
    /// </summary>
    /// <remarks>
    /// The authentication commands carry the nonces and encrypted key seeds that
    /// establish the session. Anyone holding a full trace of those plus the MRZ can
    /// reconstruct the session keys and decrypt the rest of the trace, so the payloads
    /// are withheld while the headers, which are what actually aid debugging, are kept.
    /// </remarks>
    private static bool CarriesKeyMaterial(ReadOnlySpan<byte> command)
    {
        if (command.Length < 2)
        {
            return false;
        }

        return command[1] is InsGetChallenge
            or InsExternalAuthenticate
            or InsGeneralAuthenticate
            or InsInternalAuthenticate;
    }

    private static string Render(ReadOnlySpan<byte> bytes, bool sensitive, int headerBytes)
    {
        if (!sensitive)
        {
            return Convert.ToHexString(bytes);
        }

        if (bytes.Length <= headerBytes + 2)
        {
            return Convert.ToHexString(bytes);
        }

        string header = headerBytes > 0 ? Convert.ToHexString(bytes[..headerBytes]) + " " : string.Empty;
        int withheld = bytes.Length - headerBytes - (headerBytes > 0 ? 0 : 2);
        string trailer = headerBytes > 0 ? string.Empty : " " + Convert.ToHexString(bytes[^2..]);

        return $"{header}<{withheld} bytes withheld: key material>{trailer}";
    }
}
