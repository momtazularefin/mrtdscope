using MRTDScope.Core.Apdu;
using MRTDScope.Core.Errors;
using MRTDScope.Core.Tlv;
using MRTDScope.Core.Transport;

namespace MRTDScope.Core.Lds;

/// <summary>
/// Reads elementary files off the chip with SELECT followed by chunked READ BINARY.
/// </summary>
public sealed class LdsReader
{
    private const byte ClaPlain = 0x00;
    private const byte InsSelect = 0xA4;
    private const byte InsReadBinary = 0xB0;

    /// <summary>
    /// Bytes requested per READ BINARY.
    /// </summary>
    /// <remarks>
    /// Deliberately below the 256-byte theoretical maximum. Under secure messaging each
    /// response also carries DO'87' overhead, its padding, DO'99' and DO'8E'; asking for a
    /// full 256 makes the protected response exceed what some chips will return and
    /// produces 6700 on documents that are otherwise fine.
    /// </remarks>
    private const int DefaultChunkSize = 224;

    private readonly ICardTransport _transport;
    private readonly int _chunkSize;

    public LdsReader(ICardTransport transport, int chunkSize = DefaultChunkSize)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentOutOfRangeException.ThrowIfLessThan(chunkSize, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(chunkSize, 256);

        _transport = transport;
        _chunkSize = chunkSize;
    }

    /// <summary>The outcome of reading one file.</summary>
    /// <param name="Success">Whether the complete file was read.</param>
    /// <param name="Content">The raw file content, tag and length included.</param>
    /// <param name="StatusWord">The status word that ended the read.</param>
    /// <param name="Detail">Operator-readable explanation when unsuccessful.</param>
    public sealed record ReadResult(
        bool Success,
        ReadOnlyMemory<byte> Content,
        StatusWord StatusWord,
        string Detail);

    /// <summary>
    /// Selects and reads a file in full.
    /// </summary>
    /// <remarks>
    /// A file the chip refuses is a reported result, not an exception: DG3 answering
    /// 6982 because Extended Access Control was never performed is expected behaviour,
    /// and the inspection records it as unavailable rather than aborting.
    /// </remarks>
    public ReadResult ReadFile(DataGroup dataGroup)
    {
        ArgumentNullException.ThrowIfNull(dataGroup);

        byte[] fileId = [(byte)(dataGroup.FileId >> 8), (byte)dataGroup.FileId];

        ResponseApdu selected = _transport.Transmit(
            new CommandApdu(ClaPlain, InsSelect, p1: 0x02, p2: 0x0C, fileId));

        if (!selected.IsSuccess)
        {
            return new ReadResult(
                false,
                default,
                selected.StatusWord,
                $"SELECT {dataGroup.Name} returned {selected.StatusWord}.");
        }

        // Read the first chunk, then learn the real length from the file's own BER header.
        ResponseApdu head = ReadBinary(offset: 0, length: Math.Min(_chunkSize, 8));

        if (!head.IsSuccess)
        {
            return new ReadResult(
                false,
                default,
                head.StatusWord,
                $"READ BINARY on {dataGroup.Name} returned {head.StatusWord}.");
        }

        if (head.Data.Length == 0)
        {
            return new ReadResult(
                false,
                default,
                head.StatusWord,
                $"{dataGroup.Name} is present but empty.");
        }

        int totalLength;
        try
        {
            totalLength = DetermineFileLength(head.Data.Span);
        }
        catch (MrtdEncodingException exception)
        {
            return new ReadResult(
                false,
                default,
                head.StatusWord,
                $"{dataGroup.Name} does not begin with a readable BER-TLV header: {exception.Message}");
        }

        List<byte> content = [.. head.Data.Span];

        while (content.Count < totalLength)
        {
            int remaining = totalLength - content.Count;
            int request = Math.Min(_chunkSize, remaining);

            ResponseApdu chunk = ReadBinary(content.Count, request);

            if (!chunk.IsSuccess)
            {
                return new ReadResult(
                    false,
                    content.ToArray(),
                    chunk.StatusWord,
                    $"READ BINARY on {dataGroup.Name} failed at offset {content.Count} " +
                    $"with {chunk.StatusWord}. {content.Count} of {totalLength} bytes were read.");
            }

            if (chunk.Data.Length == 0)
            {
                return new ReadResult(
                    false,
                    content.ToArray(),
                    chunk.StatusWord,
                    $"{dataGroup.Name} returned no data at offset {content.Count} " +
                    $"despite {remaining} bytes remaining.");
            }

            content.AddRange(chunk.Data.Span);
        }

        return new ReadResult(
            true,
            content.ToArray()[..totalLength],
            head.StatusWord,
            $"Read {totalLength} bytes.");
    }

    private ResponseApdu ReadBinary(int offset, int length)
    {
        // P1-P2 carry a 15-bit offset; bit 8 of P1 must stay clear for plain READ BINARY.
        if (offset > 0x7FFF)
        {
            throw new MrtdEncodingException(
                $"Offset {offset} exceeds the 32767-byte limit of plain READ BINARY. " +
                "Files this large need the odd-INS form (ISO/IEC 7816-4 §7.2.3), which " +
                "this build does not implement.");
        }

        return _transport.Transmit(new CommandApdu(
            ClaPlain,
            InsReadBinary,
            p1: (byte)(offset >> 8),
            p2: (byte)offset,
            expectedLength: length));
    }

    /// <summary>
    /// Works out a file's total length from the BER tag and length at its start.
    /// </summary>
    internal static int DetermineFileLength(ReadOnlySpan<byte> header)
    {
        int offset = 0;

        if (header.Length < 2)
        {
            throw new MrtdEncodingException("Fewer than 2 bytes of file header were read.");
        }

        // Skip the tag, which may be multi-byte.
        byte first = header[offset++];
        if ((first & 0x1F) == 0x1F)
        {
            byte next;
            do
            {
                if (offset >= header.Length)
                {
                    throw new MrtdEncodingException("The file's tag is truncated.");
                }

                next = header[offset++];
            }
            while ((next & 0x80) != 0);
        }

        if (offset >= header.Length)
        {
            throw new MrtdEncodingException("The file's length field is missing.");
        }

        byte lengthByte = header[offset++];

        if ((lengthByte & 0x80) == 0)
        {
            return offset + lengthByte;
        }

        int lengthBytes = lengthByte & 0x7F;

        if (lengthBytes is 0 or > 4)
        {
            throw new MrtdEncodingException(
                $"Unsupported BER length form 0x{lengthByte:X2} at the start of the file.");
        }

        if (offset + lengthBytes > header.Length)
        {
            throw new MrtdEncodingException("The file's length field is truncated.");
        }

        int value = 0;
        for (int i = 0; i < lengthBytes; i++)
        {
            value = (value << 8) | header[offset++];
        }

        if (value < 0)
        {
            throw new MrtdEncodingException("The file's declared length overflowed.");
        }

        return offset + value;
    }
}
