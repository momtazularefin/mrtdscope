using MRTDScope.Core.Errors;

namespace MRTDScope.Core.Apdu;

/// <summary>
/// An ISO/IEC 7816-4 response APDU: an optional data field followed by a status word.
/// </summary>
public sealed class ResponseApdu
{
    public ResponseApdu(ReadOnlyMemory<byte> data, StatusWord statusWord)
    {
        Data = data;
        StatusWord = statusWord;
    }

    /// <summary>The response data field, empty when the card returned only a status word.</summary>
    public ReadOnlyMemory<byte> Data { get; }

    public StatusWord StatusWord { get; }

    public bool IsSuccess => StatusWord.IsSuccess;

    /// <summary>Parses a raw response, which is always at least the two status bytes.</summary>
    public static ResponseApdu Parse(ReadOnlySpan<byte> raw)
    {
        if (raw.Length < 2)
        {
            throw new MrtdEncodingException(
                $"A response APDU carries at least a 2-byte status word; got {raw.Length}.");
        }

        int dataLength = raw.Length - 2;
        ushort sw = (ushort)((raw[dataLength] << 8) | raw[dataLength + 1]);
        return new ResponseApdu(raw[..dataLength].ToArray(), new StatusWord(sw));
    }

    /// <summary>Serializes back to the wire encoding.</summary>
    public byte[] ToBytes()
    {
        byte[] buffer = new byte[Data.Length + 2];
        Data.Span.CopyTo(buffer);
        buffer[^2] = StatusWord.Sw1;
        buffer[^1] = StatusWord.Sw2;
        return buffer;
    }

    /// <summary>
    /// Returns the data, or throws when the card did not report success. Used where a
    /// protocol step genuinely cannot continue, never to signal a verification verdict.
    /// </summary>
    public ReadOnlyMemory<byte> RequireSuccess(string operation)
    {
        if (!IsSuccess)
        {
            throw new CardTransportException(
                $"{operation} failed with status word {StatusWord}.");
        }

        return Data;
    }
}
