using MRTDScope.Core.Errors;
using MRTDScope.Core.Lds;
using MRTDScope.Core.Tests.Support;
using MRTDScope.Core.Tlv;

namespace MRTDScope.Core.Tests.Lds;

public sealed class EfComTests
{
    [Fact]
    public void ListsTheAdvertisedDataGroups()
    {
        EfCom com = EfCom.Parse(LdsFixtures.EfCom(DataGroup.Dg1, DataGroup.Dg2, DataGroup.Dg15));

        Assert.Equal([DataGroup.Dg1, DataGroup.Dg2, DataGroup.Dg15], com.DataGroups);
        Assert.Equal("0107", com.LdsVersion);
        Assert.Equal("040000", com.UnicodeVersion);
    }

    [Fact]
    public void UnknownTagsAreCollectedRatherThanDiscarded()
    {
        byte[] list = BerTlv.Encode(0x5C, [(byte)DataGroup.Dg1.Tag, 0x99]);
        byte[] file = BerTlv.Encode(DataGroup.Com.Tag, list);

        EfCom com = EfCom.Parse(file);

        Assert.Equal([DataGroup.Dg1], com.DataGroups);
        Assert.Equal([0x99], com.UnknownTags);
    }

    [Fact]
    public void WrongOuterTagIsRejected()
    {
        Assert.Throws<MrtdEncodingException>(() => EfCom.Parse(BerTlv.Encode(0x61, [0x00])));
    }
}

public sealed class MrzInfoTests
{
    [Fact]
    public void ParsesTd3PassportFields()
    {
        MrzInfo mrz = MrzInfo.Parse(LdsFixtures.Dg1());

        Assert.Equal(MrzFormat.Td3, mrz.Format);
        Assert.Equal(2, mrz.Lines.Count);
        Assert.Equal("UTO", mrz.IssuingState);
        Assert.Equal("L898902C<", mrz.DocumentNumber);
        Assert.Equal("690806", mrz.DateOfBirth);
        Assert.Equal("940623", mrz.DateOfExpiry);
    }

    /// <summary>
    /// The MRZ on the chip should regenerate the same BAC key an operator types from the
    /// printed page. This is what makes DG1 usable as a cross-check.
    /// </summary>
    [Fact]
    public void RegeneratesTheSameBacKeyAsTheTypedMrz()
    {
        MrzInfo mrz = MrzInfo.Parse(LdsFixtures.Dg1());

        Assert.Equal(
            Convert.ToHexString(
                MRTDScope.Core.Mrz.MrzKey.Create("L898902C<", "690806", "940623").ComputeSeed()),
            Convert.ToHexString(mrz.ToKey().ComputeSeed()));
    }

    [Fact]
    public void ParsesTd1IdentityCardFields()
    {
        // TD1 is three lines of 30. The document number sits on line 1, not line 2.
        string td1 =
            "I<UTOD23145890<7349<<<<<<<<<<<" +
            "7408122F1204159UTO<<<<<<<<<<<6" +
            "ERIKSSON<<ANNA<MARIA<<<<<<<<<<";

        MrzInfo mrz = MrzInfo.Parse(LdsFixtures.Dg1(td1));

        Assert.Equal(MrzFormat.Td1, mrz.Format);
        Assert.Equal(3, mrz.Lines.Count);
        Assert.Equal("UTO", mrz.IssuingState);
        Assert.Equal("D23145890", mrz.DocumentNumber);
        Assert.Equal("740812", mrz.DateOfBirth);
        Assert.Equal("120415", mrz.DateOfExpiry);
    }

    [Fact]
    public void ParsesTheHolderIdentityFromTd3()
    {
        MrzInfo mrz = MrzInfo.Parse(LdsFixtures.Dg1());

        Assert.Equal("ERIKSSON", mrz.PrimaryIdentifier);
        Assert.Equal("ANNA MARIA", mrz.SecondaryIdentifier);
        Assert.Equal("ANNA MARIA ERIKSSON", mrz.HolderName);
        Assert.Equal("UTO", mrz.Nationality);
        Assert.Equal('F', mrz.Sex);
    }

    [Fact]
    public void ParsesTheHolderIdentityFromTd1()
    {
        string td1 =
            "I<UTOD23145890<7349<<<<<<<<<<<" +
            "7408122F1204159UTO<<<<<<<<<<<6" +
            "ERIKSSON<<ANNA<MARIA<<<<<<<<<<";

        MrzInfo mrz = MrzInfo.Parse(LdsFixtures.Dg1(td1));

        Assert.Equal("ERIKSSON", mrz.PrimaryIdentifier);
        Assert.Equal("ANNA MARIA", mrz.SecondaryIdentifier);
        Assert.Equal("UTO", mrz.Nationality);
        Assert.Equal('F', mrz.Sex);
    }

    /// <summary>
    /// A name too long for the field is truncated by the issuer, which can remove the
    /// double filler that separates the identifiers. That is a legitimate MRZ, so the
    /// whole field becomes the primary identifier rather than failing to parse.
    /// </summary>
    [Fact]
    public void ATruncatedNameWithNoSeparatorIsStillParsed()
    {
        string line1 = "P<UTO" + new string('A', 39);
        string line2 = "L898902C<3UTO6908061F9406236ZE184226B<<<<<14";

        MrzInfo mrz = MrzInfo.Parse(LdsFixtures.Dg1(line1 + line2));

        Assert.Equal(new string('A', 39), mrz.PrimaryIdentifier);
        Assert.Equal(string.Empty, mrz.SecondaryIdentifier);
        Assert.Equal(new string('A', 39), mrz.HolderName);
    }

    /// <summary>
    /// A holder with no secondary identifier is normal in many naming conventions, and
    /// must not leave a stray separator in the displayed name.
    /// </summary>
    [Fact]
    public void AHolderWithOnlyAPrimaryIdentifierHasNoTrailingSeparator()
    {
        string line1 = "P<UTOSUHARTO" + new string('<', 32);
        string line2 = "L898902C<3UTO6908061M9406236ZE184226B<<<<<14";

        MrzInfo mrz = MrzInfo.Parse(LdsFixtures.Dg1(line1 + line2));

        Assert.Equal("SUHARTO", mrz.PrimaryIdentifier);
        Assert.Equal(string.Empty, mrz.SecondaryIdentifier);
        Assert.Equal("SUHARTO", mrz.HolderName);
        Assert.Equal('M', mrz.Sex);
    }

    [Fact]
    public void UnknownMrzLengthIsRejectedRatherThanGuessed()
    {
        MrtdEncodingException error = Assert.Throws<MrtdEncodingException>(
            () => MrzInfo.Parse(LdsFixtures.Dg1(new string('A', 50))));

        Assert.Contains("no known format", error.Message, StringComparison.Ordinal);
    }
}

public sealed class FacialRecordTests
{
    [Fact]
    public void ExtractsAJpegPortrait()
    {
        byte[] image = [0xFF, 0xD8, 0xFF, 0xE0, 0x11, 0x22, 0x33, 0x44];
        FacialRecord record = FacialRecord.Parse(LdsFixtures.Dg2(image));

        FaceImage? face = record.Primary;

        Assert.NotNull(face);
        Assert.Equal(FaceImageEncoding.Jpeg, face!.Encoding);
        Assert.Equal(420, face.Width);
        Assert.Equal(540, face.Height);
        Assert.Equal(Convert.ToHexString(image), Convert.ToHexString(face.Data.Span));
        Assert.Equal(".jpg", face.FileExtension);
    }

    [Fact]
    public void RecognizesJpeg2000()
    {
        FacialRecord record = FacialRecord.Parse(LdsFixtures.Dg2(imageDataType: 1));

        Assert.Equal(FaceImageEncoding.Jpeg2000, record.Primary!.Encoding);
        Assert.Equal(".jp2", record.Primary.FileExtension);
    }

    /// <summary>
    /// The 19794-5 record has no separators — fields are located by byte count — so
    /// feature point blocks shift the image offset. Getting this wrong yields plausible
    /// garbage rather than an error, which is why it is pinned.
    /// </summary>
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(9)]
    public void FeaturePointBlocksShiftTheImageOffsetCorrectly(int featurePoints)
    {
        byte[] image = [0xFF, 0xD8, 0xAB, 0xCD, 0xEF, 0x01, 0x02, 0x03];

        FacialRecord record = FacialRecord.Parse(
            LdsFixtures.Dg2(image, featurePoints: featurePoints));

        Assert.Equal(
            Convert.ToHexString(image),
            Convert.ToHexString(record.Primary!.Data.Span));
    }

    [Fact]
    public void RejectsABlockWithoutTheFacFormatIdentifier()
    {
        byte[] block = new byte[40];
        byte[] dg2 = BerTlv.Encode(
            DataGroup.Dg2.Tag,
            BerTlv.Encode(0x7F61, BerTlv.Encode(0x7F60, BerTlv.Encode(0x5F2E, block))));

        MrtdEncodingException error = Assert.Throws<MrtdEncodingException>(
            () => FacialRecord.Parse(dg2));

        Assert.Contains("FAC", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void RejectsATruncatedRecordRatherThanReadingPastTheEnd()
    {
        byte[] dg2 = LdsFixtures.Dg2();
        byte[] truncated = dg2[..(dg2.Length - 20)];

        // The outer TLV length no longer matches, so this must fail loudly.
        Assert.ThrowsAny<MrtdEncodingException>(() => FacialRecord.Parse(truncated));
    }

    /// <summary>
    /// ISO/IEC 39794 data sits under tag 0x7F2E. Reporting that plainly beats decoding it
    /// as though it were the 19794 layout and producing nonsense.
    /// </summary>
    [Fact]
    public void ReportsIso39794EncodingAsUnsupported()
    {
        byte[] dg2 = BerTlv.Encode(
            DataGroup.Dg2.Tag,
            BerTlv.Encode(0x7F61, BerTlv.Encode(0x7F60, BerTlv.Encode(0x7F2E, new byte[32]))));

        MrtdEncodingException error = Assert.Throws<MrtdEncodingException>(
            () => FacialRecord.Parse(dg2));

        Assert.Contains("39794", error.Message, StringComparison.Ordinal);
    }
}

public sealed class LdsReaderTests
{
    [Theory]
    // Short form: tag 0x60, length 0x10 -> 2 header bytes + 16.
    [InlineData("6010", 18)]
    // Long form 0x81: tag 0x75, length 0x81 0xC8 -> 3 header bytes + 200.
    [InlineData("7581C8", 203)]
    // Long form 0x82: tag 0x75, length 0x82 0x1A 0x2B -> 4 header bytes + 6699.
    [InlineData("75821A2B", 6703)]
    // Multi-byte tag 0x5F1F with short length.
    [InlineData("5F1F58", 91)]
    public void DeterminesTotalFileLengthFromTheBerHeader(string headerHex, int expected)
    {
        Assert.Equal(
            expected,
            LdsReader.DetermineFileLength(Convert.FromHexString(headerHex)));
    }

    [Fact]
    public void RejectsAnIndefiniteLengthHeader()
    {
        Assert.Throws<MrtdEncodingException>(
            () => LdsReader.DetermineFileLength(Convert.FromHexString("6080")));
    }

    [Fact]
    public void ReadsAFileAcrossMultipleChunks()
    {
        // A 20-byte file read 8 bytes at a time: SELECT, then a header read, then chunks.
        byte[] file = BerTlv.Encode(DataGroup.Dg1.Tag, new byte[18]);
        Assert.Equal(20, file.Length);

        string hex = Convert.ToHexString(file);

        ScriptedTransport transport = new(
            new ScriptedTransport.Exchange("00A4020C020101", "9000"),
            new ScriptedTransport.Exchange("00B0000008", hex[..16] + "9000"),
            new ScriptedTransport.Exchange("00B0000808", hex[16..32] + "9000"),
            // Only 4 bytes remain, and the reader asks for exactly 4. Requesting a full
            // chunk here would read past end-of-file and draw 6B00 from a real chip.
            new ScriptedTransport.Exchange("00B0001004", hex[32..40] + "9000"));

        LdsReader.ReadResult result = new LdsReader(transport, chunkSize: 8).ReadFile(DataGroup.Dg1);

        Assert.True(result.Success, result.Detail);
        Assert.Equal(hex, Convert.ToHexString(result.Content.Span));
        Assert.True(transport.IsExhausted);
    }

    /// <summary>
    /// DG3 answering 6982 without Extended Access Control is expected behaviour, not an
    /// error. The inspection records it and carries on (D008).
    /// </summary>
    [Fact]
    public void AccessDeniedIsReportedNotThrown()
    {
        ScriptedTransport transport = new(
            new ScriptedTransport.Exchange("00A4020C020103", "6982"));

        LdsReader.ReadResult result = new LdsReader(transport).ReadFile(DataGroup.Dg3);

        Assert.False(result.Success);
        Assert.Equal(0x6982, result.StatusWord.Value);
        Assert.Contains("EF.DG3", result.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void PartialReadReportsHowFarItGot()
    {
        byte[] file = BerTlv.Encode(DataGroup.Dg1.Tag, new byte[18]);
        string hex = Convert.ToHexString(file);

        ScriptedTransport transport = new(
            new ScriptedTransport.Exchange("00A4020C020101", "9000"),
            new ScriptedTransport.Exchange("00B0000008", hex[..16] + "9000"),
            new ScriptedTransport.Exchange("00B0000808", "6982"));

        LdsReader.ReadResult result = new LdsReader(transport, chunkSize: 8).ReadFile(DataGroup.Dg1);

        Assert.False(result.Success);
        Assert.Contains("8 of 20 bytes", result.Detail, StringComparison.Ordinal);
    }
}
