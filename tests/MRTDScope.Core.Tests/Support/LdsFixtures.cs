using System.Buffers.Binary;
using System.Text;
using MRTDScope.Core.Lds;
using MRTDScope.Core.Tlv;

namespace MRTDScope.Core.Tests.Support;

/// <summary>
/// Builds well-formed LDS files byte by byte, so parsers are tested against structures
/// built from the specification rather than against their own output.
/// </summary>
public static class LdsFixtures
{
    /// <summary>A TD3 passport MRZ matching the Doc 9303 worked-example document.</summary>
    public const string Td3Mrz =
        "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<" +
        "L898902C<3UTO6908061F9406236ZE184226B<<<<<14";

    /// <summary>Builds EF.COM listing the given data groups.</summary>
    public static byte[] EfCom(params DataGroup[] dataGroups)
    {
        byte[] version = BerTlv.Encode(0x5F01, Encoding.ASCII.GetBytes("0107"));
        byte[] unicode = BerTlv.Encode(0x5F36, Encoding.ASCII.GetBytes("040000"));
        byte[] list = BerTlv.Encode(0x5C, [.. dataGroups.Select(group => (byte)group.Tag)]);

        return BerTlv.Encode(DataGroup.Com.Tag, [.. version, .. unicode, .. list]);
    }

    /// <summary>Builds DG1 around an MRZ string.</summary>
    public static byte[] Dg1(string mrz = Td3Mrz) =>
        BerTlv.Encode(DataGroup.Dg1.Tag, BerTlv.Encode(0x5F1F, Encoding.ASCII.GetBytes(mrz)));

    /// <summary>
    /// Builds DG2 with its CBEFF wrapper around an ISO/IEC 19794-5 facial record.
    /// </summary>
    /// <param name="imageBytes">Stand-in image payload; content is irrelevant to parsing.</param>
    /// <param name="featurePoints">How many 8-byte feature point blocks to include.</param>
    public static byte[] Dg2(byte[]? imageBytes = null, int featurePoints = 0, byte imageDataType = 0)
    {
        imageBytes ??= [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46];

        // Facial Information block: 20 bytes, opening with the record data length.
        int recordDataLength = 20 + (featurePoints * 8) + 12 + imageBytes.Length;

        byte[] facialInformation = new byte[20];
        BinaryPrimitives.WriteUInt32BigEndian(facialInformation.AsSpan(0, 4), (uint)recordDataLength);
        BinaryPrimitives.WriteUInt16BigEndian(facialInformation.AsSpan(4, 2), (ushort)featurePoints);

        byte[] featurePointBlocks = new byte[featurePoints * 8];
        for (int i = 0; i < featurePoints; i++)
        {
            featurePointBlocks[i * 8] = 0x01;
            featurePointBlocks[(i * 8) + 1] = 0x37;
        }

        // Image Information block: 12 bytes.
        byte[] imageInformation = new byte[12];
        imageInformation[0] = 0x01;            // Face Image Type: basic
        imageInformation[1] = imageDataType;   // 0 = JPEG, 1 = JPEG 2000
        BinaryPrimitives.WriteUInt16BigEndian(imageInformation.AsSpan(2, 2), 420);
        BinaryPrimitives.WriteUInt16BigEndian(imageInformation.AsSpan(4, 2), 540);

        // Facial Record Header: 14 bytes.
        byte[] header = new byte[14];
        "FAC\0"u8.CopyTo(header);
        "010\0"u8.CopyTo(header.AsSpan(4));
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(8, 4), (uint)(14 + recordDataLength));
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(12, 2), 1);

        byte[] biometricData =
        [
            .. header,
            .. facialInformation,
            .. featurePointBlocks,
            .. imageInformation,
            .. imageBytes,
        ];

        byte[] biometricHeader = BerTlv.Encode(0xA1, [0x81, 0x01, 0x02]);
        byte[] dataBlock = BerTlv.Encode(0x5F2E, biometricData);
        byte[] template = BerTlv.Encode(0x7F60, [.. biometricHeader, .. dataBlock]);
        byte[] instanceCount = BerTlv.Encode(0x02, [0x01]);
        byte[] group = BerTlv.Encode(0x7F61, [.. instanceCount, .. template]);

        return BerTlv.Encode(DataGroup.Dg2.Tag, group);
    }

    /// <summary>A minimal well-formed data group for tests that only need bytes.</summary>
    public static byte[] Filler(DataGroup dataGroup, byte seed = 0x00)
    {
        byte[] payload = new byte[16];
        Array.Fill(payload, seed);
        return BerTlv.Encode(dataGroup.Tag, payload);
    }

    /// <summary>Returns a copy with one byte of the value flipped.</summary>
    public static byte[] Tamper(byte[] file)
    {
        ArgumentNullException.ThrowIfNull(file);

        byte[] copy = [.. file];
        copy[^1] ^= 0xFF;
        return copy;
    }
}
