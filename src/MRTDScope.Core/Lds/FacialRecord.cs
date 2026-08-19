using System.Buffers.Binary;
using MRTDScope.Core.Errors;
using MRTDScope.Core.Tlv;

namespace MRTDScope.Core.Lds;

/// <summary>How the portrait bytes are encoded.</summary>
public enum FaceImageEncoding
{
    /// <summary>ISO/IEC 10918-1 JPEG. Image Data Type 0.</summary>
    Jpeg,

    /// <summary>ISO/IEC 15444-1 JPEG 2000. Image Data Type 1.</summary>
    Jpeg2000,

    /// <summary>A reserved or unrecognized Image Data Type.</summary>
    Unknown,
}

/// <summary>One facial image and the properties recorded alongside it.</summary>
public sealed record FaceImage(
    FaceImageEncoding Encoding,
    int Width,
    int Height,
    ReadOnlyMemory<byte> Data)
{
    /// <summary>A conventional file extension for the encoding.</summary>
    public string FileExtension => Encoding switch
    {
        FaceImageEncoding.Jpeg => ".jpg",
        FaceImageEncoding.Jpeg2000 => ".jp2",
        _ => ".bin",
    };
}

/// <summary>
/// DG2 — the encoded face, parsed through its CBEFF wrapper into an ISO/IEC 19794-5
/// facial record.
/// </summary>
/// <remarks>
/// Two layers, and both matter. Doc 9303 Part 10 defines the CBEFF nesting
/// (0x75 → 0x7F61 → 0x7F60 → 0xA1 header and 0x5F2E biometric data block), while the
/// content of that data block is ISO/IEC 19794-5: a 14-byte Facial Record Header
/// beginning "FAC\0", then per image a 20-byte Facial Information block, zero or more
/// 8-byte Feature Point blocks, a 12-byte Image Information block, and the image bytes.
/// <para>
/// The record has no separators or tags — §5.3 states fields are parsed by byte count —
/// so a single wrong offset silently yields plausible-looking garbage. Every length here
/// is bounds-checked against the buffer rather than trusted.
/// </para>
/// </remarks>
public sealed class FacialRecord
{
    private const int TagBiometricGroup = 0x7F61;
    private const int TagBiometricTemplate = 0x7F60;
    private const int TagBiometricData19794 = 0x5F2E;
    private const int TagBiometricData39794 = 0x7F2E;

    private const int RecordHeaderLength = 14;
    private const int FacialInformationLength = 20;
    private const int FeaturePointLength = 8;
    private const int ImageInformationLength = 12;

    /// <summary>"FAC\0" — the ISO/IEC 19794-5 format identifier.</summary>
    private static ReadOnlySpan<byte> FormatIdentifier => [0x46, 0x41, 0x43, 0x00];

    private FacialRecord(IReadOnlyList<FaceImage> images) => Images = images;

    /// <summary>Every facial image the record carries, usually exactly one.</summary>
    public IReadOnlyList<FaceImage> Images { get; }

    /// <summary>The primary portrait, or <c>null</c> when the record holds none.</summary>
    public FaceImage? Primary => Images.Count > 0 ? Images[0] : null;

    /// <summary>Parses the raw DG2 file content, tag 0x75 included.</summary>
    public static FacialRecord Parse(ReadOnlySpan<byte> fileContent)
    {
        IReadOnlyList<BerTlv> outer = BerTlv.Parse(fileContent);
        BerTlv root = BerTlv.Find(outer, DataGroup.Dg2.Tag)
            ?? throw new MrtdEncodingException(
                $"DG2 must be wrapped in tag 0x{DataGroup.Dg2.Tag:X2}.");

        BerTlv group = BerTlv.Find(root.Children(), TagBiometricGroup)
            ?? throw new MrtdEncodingException(
                "DG2 carries no biometric information group template (tag 0x7F61).");

        List<FaceImage> images = [];

        foreach (BerTlv template in group.Children().Where(child => child.Tag == TagBiometricTemplate))
        {
            IReadOnlyList<BerTlv> parts = template.Children();

            BerTlv? block = BerTlv.Find(parts, TagBiometricData19794);

            if (block is null && BerTlv.Find(parts, TagBiometricData39794) is not null)
            {
                throw new MrtdEncodingException(
                    "This DG2 stores its biometric data under tag 0x7F2E, meaning the " +
                    "ISO/IEC 39794 encoding. This build parses the ISO/IEC 19794 encoding " +
                    "(tag 0x5F2E) only.");
            }

            if (block is null)
            {
                continue;
            }

            images.AddRange(ParseBiometricDataBlock(block.Value.Span));
        }

        return new FacialRecord(images);
    }

    private static IReadOnlyList<FaceImage> ParseBiometricDataBlock(ReadOnlySpan<byte> block)
    {
        if (block.Length < RecordHeaderLength)
        {
            throw new MrtdEncodingException(
                $"A facial record header is {RecordHeaderLength} bytes; the block holds " +
                $"only {block.Length}.");
        }

        if (!block[..4].SequenceEqual(FormatIdentifier))
        {
            throw new MrtdEncodingException(
                "The biometric data block does not begin with the ISO/IEC 19794-5 format " +
                $"identifier \"FAC\\0\"; found {Convert.ToHexString(block[..4])}.");
        }

        int faceCount = BinaryPrimitives.ReadUInt16BigEndian(block[12..14]);

        List<FaceImage> images = [];
        int offset = RecordHeaderLength;

        for (int index = 0; index < faceCount; index++)
        {
            if (offset + FacialInformationLength > block.Length)
            {
                throw new MrtdEncodingException(
                    $"Facial record data for image {index + 1} runs past the end of the block.");
            }

            // The Facial Information block opens with the length of this image's whole
            // record data, which is what lets us skip to the next image.
            int recordDataLength = (int)BinaryPrimitives.ReadUInt32BigEndian(
                block.Slice(offset, 4));
            int featurePoints = BinaryPrimitives.ReadUInt16BigEndian(
                block.Slice(offset + 4, 2));

            int imageInfoOffset = offset
                + FacialInformationLength
                + (featurePoints * FeaturePointLength);

            if (imageInfoOffset + ImageInformationLength > block.Length)
            {
                throw new MrtdEncodingException(
                    $"Image information for image {index + 1} runs past the end of the " +
                    $"block; the record claims {featurePoints} feature points.");
            }

            ReadOnlySpan<byte> imageInfo = block.Slice(imageInfoOffset, ImageInformationLength);

            FaceImageEncoding encoding = imageInfo[1] switch
            {
                0 => FaceImageEncoding.Jpeg,
                1 => FaceImageEncoding.Jpeg2000,
                _ => FaceImageEncoding.Unknown,
            };

            int width = BinaryPrimitives.ReadUInt16BigEndian(imageInfo[2..4]);
            int height = BinaryPrimitives.ReadUInt16BigEndian(imageInfo[4..6]);

            int imageOffset = imageInfoOffset + ImageInformationLength;

            // Prefer the declared record length, but fall back to the rest of the block
            // when it is absent or inconsistent — some issuers get this field wrong, and
            // refusing to show a portrait over a bad length field helps nobody.
            int imageLength = recordDataLength > 0
                ? recordDataLength - (imageOffset - offset)
                : block.Length - imageOffset;

            if (imageLength <= 0 || imageOffset + imageLength > block.Length)
            {
                imageLength = block.Length - imageOffset;
            }

            if (imageLength <= 0)
            {
                throw new MrtdEncodingException(
                    $"Image {index + 1} carries no data.");
            }

            images.Add(new FaceImage(
                encoding,
                width,
                height,
                block.Slice(imageOffset, imageLength).ToArray()));

            offset = recordDataLength > 0 ? offset + recordDataLength : block.Length;

            if (offset >= block.Length)
            {
                break;
            }
        }

        return images;
    }
}
