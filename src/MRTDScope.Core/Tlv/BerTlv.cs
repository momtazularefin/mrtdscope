using MRTDScope.Core.Errors;

namespace MRTDScope.Core.Tlv;

/// <summary>
/// One BER-TLV element, retaining its exact source encoding.
/// </summary>
/// <remarks>
/// <see cref="RawBytes"/> matters more than it looks. Secure messaging computes its MAC
/// over the encoded data objects exactly as they appeared on the wire, so a parser that
/// only preserved tag and value would force the verifier to re-encode and hope the
/// length form matched. Re-encoding a length as 0x81 0x0A when the card sent 0x0A
/// produces a MAC mismatch on a perfectly good document, which is precisely the kind of
/// false rejection this project treats as a defect.
/// </remarks>
public sealed class BerTlv
{
    internal BerTlv(int tag, ReadOnlyMemory<byte> value, ReadOnlyMemory<byte> rawBytes)
    {
        Tag = tag;
        Value = value;
        RawBytes = rawBytes;
    }

    /// <summary>The tag, packed big-endian for multi-byte tags (for example 0x5F1F).</summary>
    public int Tag { get; }

    /// <summary>The value field.</summary>
    public ReadOnlyMemory<byte> Value { get; }

    /// <summary>The complete element as it appeared in the source, tag and length included.</summary>
    public ReadOnlyMemory<byte> RawBytes { get; }

    /// <summary>Whether this element is constructed, meaning its value holds further elements.</summary>
    public bool IsConstructed => (FirstTagByte & 0x20) != 0;

    private byte FirstTagByte
    {
        get
        {
            int tag = Tag;
            while (tag > 0xFF)
            {
                tag >>= 8;
            }

            return (byte)tag;
        }
    }

    /// <summary>Parses the children of a constructed element.</summary>
    public IReadOnlyList<BerTlv> Children() => Parse(Value.Span);

    /// <summary>Parses a flat sequence of BER-TLV elements.</summary>
    public static IReadOnlyList<BerTlv> Parse(ReadOnlySpan<byte> source)
    {
        List<BerTlv> elements = [];
        int offset = 0;

        while (offset < source.Length)
        {
            // Skip 0x00 and 0xFF filler between elements, which real chips do emit.
            if (source[offset] is 0x00 or 0xFF)
            {
                offset++;
                continue;
            }

            int start = offset;
            int tag = ReadTag(source, ref offset);
            int length = ReadLength(source, ref offset);

            if (offset + length > source.Length)
            {
                throw new MrtdEncodingException(
                    $"TLV element {tag:X} claims {length} value bytes but only " +
                    $"{source.Length - offset} remain.");
            }

            ReadOnlyMemory<byte> value = source.Slice(offset, length).ToArray();
            offset += length;
            ReadOnlyMemory<byte> raw = source[start..offset].ToArray();

            elements.Add(new BerTlv(tag, value, raw));
        }

        return elements;
    }

    /// <summary>Finds the first element with the given tag, or <c>null</c>.</summary>
    public static BerTlv? Find(IEnumerable<BerTlv> elements, int tag) =>
        elements.FirstOrDefault(element => element.Tag == tag);

    /// <summary>Encodes a tag and value using the shortest valid definite length form.</summary>
    public static byte[] Encode(int tag, ReadOnlySpan<byte> value)
    {
        byte[] tagBytes = EncodeTag(tag);
        byte[] lengthBytes = EncodeLength(value.Length);

        byte[] buffer = new byte[tagBytes.Length + lengthBytes.Length + value.Length];
        tagBytes.CopyTo(buffer, 0);
        lengthBytes.CopyTo(buffer, tagBytes.Length);
        value.CopyTo(buffer.AsSpan(tagBytes.Length + lengthBytes.Length));
        return buffer;
    }

    private static byte[] EncodeTag(int tag)
    {
        if (tag <= 0xFF)
        {
            return [(byte)tag];
        }

        if (tag <= 0xFFFF)
        {
            return [(byte)(tag >> 8), (byte)tag];
        }

        return [(byte)(tag >> 16), (byte)(tag >> 8), (byte)tag];
    }

    private static byte[] EncodeLength(int length)
    {
        if (length < 0x80)
        {
            return [(byte)length];
        }

        if (length <= 0xFF)
        {
            return [0x81, (byte)length];
        }

        if (length <= 0xFFFF)
        {
            return [0x82, (byte)(length >> 8), (byte)length];
        }

        return [0x83, (byte)(length >> 16), (byte)(length >> 8), (byte)length];
    }

    private static int ReadTag(ReadOnlySpan<byte> source, ref int offset)
    {
        byte first = source[offset++];
        int tag = first;

        // Bits b5-b1 all set means the tag number continues in subsequent bytes.
        if ((first & 0x1F) == 0x1F)
        {
            byte next;
            do
            {
                if (offset >= source.Length)
                {
                    throw new MrtdEncodingException("Truncated multi-byte TLV tag.");
                }

                next = source[offset++];
                tag = (tag << 8) | next;
            }
            while ((next & 0x80) != 0);
        }

        return tag;
    }

    private static int ReadLength(ReadOnlySpan<byte> source, ref int offset)
    {
        if (offset >= source.Length)
        {
            throw new MrtdEncodingException("Truncated TLV length.");
        }

        byte first = source[offset++];

        if ((first & 0x80) == 0)
        {
            return first;
        }

        int count = first & 0x7F;

        if (count == 0)
        {
            throw new MrtdEncodingException(
                "Indefinite TLV length is not permitted in eMRTD encodings.");
        }

        if (count > 4 || offset + count > source.Length)
        {
            throw new MrtdEncodingException($"Unsupported or truncated TLV length form 0x{first:X2}.");
        }

        int length = 0;
        for (int i = 0; i < count; i++)
        {
            length = (length << 8) | source[offset++];
        }

        if (length < 0)
        {
            throw new MrtdEncodingException("TLV length overflowed.");
        }

        return length;
    }
}
