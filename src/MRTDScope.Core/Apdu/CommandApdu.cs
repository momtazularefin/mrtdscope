using MRTDScope.Core.Errors;

namespace MRTDScope.Core.Apdu;

/// <summary>
/// An ISO/IEC 7816-4 command APDU, covering all four cases in both short and extended
/// length encodings.
/// </summary>
/// <remarks>
/// <see cref="ExpectedLength"/> is nullable rather than a sentinel integer, because
/// "no Le field at all" (Case 1 and Case 3) and "Le = 0, meaning 256" are genuinely
/// different commands on the wire and conflating them is a classic source of 6700
/// responses.
/// </remarks>
public sealed class CommandApdu
{
    /// <summary>The Le value meaning "up to 256 bytes", encoded as a single 0x00 byte.</summary>
    public const int MaxShortLength = 256;

    /// <summary>The Le value meaning "up to 65536 bytes", encoded as extended length.</summary>
    public const int MaxExtendedLength = 65536;

    public CommandApdu(
        byte cla,
        byte ins,
        byte p1,
        byte p2,
        ReadOnlyMemory<byte> data = default,
        int? expectedLength = null,
        bool forceExtended = false)
    {
        if (expectedLength is { } le && (le < 0 || le > MaxExtendedLength))
        {
            throw new ArgumentOutOfRangeException(
                nameof(expectedLength),
                le,
                $"Le must be between 0 and {MaxExtendedLength}, or null when absent.");
        }

        if (data.Length > MaxExtendedLength - 1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(data),
                data.Length,
                "Command data exceeds the extended-length maximum.");
        }

        Cla = cla;
        Ins = ins;
        P1 = p1;
        P2 = p2;
        Data = data;
        ExpectedLength = expectedLength;
        IsExtended = forceExtended
            || data.Length > 255
            || expectedLength > MaxShortLength;
    }

    public byte Cla { get; }

    public byte Ins { get; }

    public byte P1 { get; }

    public byte P2 { get; }

    /// <summary>The command data field. Empty for Case 1 and Case 2.</summary>
    public ReadOnlyMemory<byte> Data { get; }

    /// <summary>
    /// The maximum response length, or <c>null</c> when the command carries no Le field.
    /// </summary>
    public int? ExpectedLength { get; }

    /// <summary>Whether this APDU serializes with extended length fields.</summary>
    public bool IsExtended { get; }

    /// <summary>Whether secure messaging has been applied, indicated by bits b4/b3 of CLA.</summary>
    public bool IsSecureMessaging => (Cla & 0x0C) != 0;

    /// <summary>
    /// Returns a copy of this command with a different class byte, used to set the
    /// secure-messaging bits without rebuilding the command by hand.
    /// </summary>
    public CommandApdu WithCla(byte cla) =>
        new(cla, Ins, P1, P2, Data, ExpectedLength, IsExtended);

    /// <summary>Serializes the command to its wire encoding.</summary>
    public byte[] ToBytes()
    {
        int dataLength = Data.Length;
        bool hasData = dataLength > 0;
        bool hasLe = ExpectedLength.HasValue;

        int size = 4;
        if (hasData)
        {
            size += IsExtended ? 3 : 1;
            size += dataLength;
        }

        if (hasLe)
        {
            // Extended Le is three bytes on its own, but only two when Lc already
            // supplied the leading 0x00 marker.
            size += IsExtended ? (hasData ? 2 : 3) : 1;
        }

        byte[] buffer = new byte[size];
        buffer[0] = Cla;
        buffer[1] = Ins;
        buffer[2] = P1;
        buffer[3] = P2;

        int offset = 4;

        if (hasData)
        {
            if (IsExtended)
            {
                buffer[offset++] = 0x00;
                buffer[offset++] = (byte)(dataLength >> 8);
                buffer[offset++] = (byte)dataLength;
            }
            else
            {
                buffer[offset++] = (byte)dataLength;
            }

            Data.Span.CopyTo(buffer.AsSpan(offset));
            offset += dataLength;
        }

        if (hasLe)
        {
            int le = ExpectedLength!.Value;
            if (IsExtended)
            {
                if (!hasData)
                {
                    buffer[offset++] = 0x00;
                }

                // 65536 encodes as 0x0000, mirroring 256 encoding as 0x00.
                int encoded = le == MaxExtendedLength ? 0 : le;
                buffer[offset++] = (byte)(encoded >> 8);
                buffer[offset] = (byte)encoded;
            }
            else
            {
                // 256 encodes as 0x00.
                buffer[offset] = (byte)(le == MaxShortLength ? 0 : le);
            }
        }

        return buffer;
    }

    /// <summary>
    /// Parses a command APDU from its wire encoding. Used by the synthetic chip in M3,
    /// which must decode exactly what a real chip would receive.
    /// </summary>
    public static CommandApdu Parse(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length < 4)
        {
            throw new MrtdEncodingException(
                $"A command APDU is at least 4 bytes; got {bytes.Length}.");
        }

        byte cla = bytes[0];
        byte ins = bytes[1];
        byte p1 = bytes[2];
        byte p2 = bytes[3];

        if (bytes.Length == 4)
        {
            return new CommandApdu(cla, ins, p1, p2);
        }

        ReadOnlySpan<byte> body = bytes[4..];

        // Case 2S: a lone Le byte.
        if (body.Length == 1)
        {
            return new CommandApdu(
                cla, ins, p1, p2,
                expectedLength: body[0] == 0 ? MaxShortLength : body[0]);
        }

        bool extended = body[0] == 0x00 && body.Length >= 3;

        if (extended)
        {
            // Case 2E: 00 Le1 Le2 with nothing else.
            if (body.Length == 3)
            {
                int le = (body[1] << 8) | body[2];
                return new CommandApdu(
                    cla, ins, p1, p2,
                    expectedLength: le == 0 ? MaxExtendedLength : le,
                    forceExtended: true);
            }

            int lc = (body[1] << 8) | body[2];
            if (body.Length < 3 + lc)
            {
                throw new MrtdEncodingException(
                    $"Extended Lc claims {lc} data bytes but only {body.Length - 3} remain.");
            }

            ReadOnlyMemory<byte> data = body.Slice(3, lc).ToArray();
            int remaining = body.Length - 3 - lc;

            return remaining switch
            {
                0 => new CommandApdu(cla, ins, p1, p2, data, forceExtended: true),
                2 => new CommandApdu(
                    cla, ins, p1, p2, data,
                    expectedLength: ((body[3 + lc] << 8) | body[4 + lc]) is var le && le == 0
                        ? MaxExtendedLength
                        : le,
                    forceExtended: true),
                _ => throw new MrtdEncodingException(
                    $"Extended APDU has {remaining} trailing bytes; expected 0 or 2."),
            };
        }

        int shortLc = body[0];
        if (body.Length < 1 + shortLc)
        {
            throw new MrtdEncodingException(
                $"Lc claims {shortLc} data bytes but only {body.Length - 1} remain.");
        }

        ReadOnlyMemory<byte> shortData = body.Slice(1, shortLc).ToArray();
        int trailing = body.Length - 1 - shortLc;

        return trailing switch
        {
            0 => new CommandApdu(cla, ins, p1, p2, shortData),
            1 => new CommandApdu(
                cla, ins, p1, p2, shortData,
                expectedLength: body[1 + shortLc] == 0 ? MaxShortLength : body[1 + shortLc]),
            _ => throw new MrtdEncodingException(
                $"Short APDU has {trailing} trailing bytes; expected 0 or 1."),
        };
    }
}
