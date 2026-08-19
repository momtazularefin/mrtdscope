using MRTDScope.Core.Crypto;
using MRTDScope.Core.Errors;
using MRTDScope.Core.Mrz;
using MRTDScope.Core.Protocol.SecureMessaging;
using MRTDScope.Core.Tlv;
using MRTDScope.Core.Transport;

namespace MRTDScope.Core.Tests.Primitives;

public sealed class BerTlvTests
{
    [Fact]
    public void Parse_ReadsShortForm()
    {
        IReadOnlyList<BerTlv> elements = BerTlv.Parse(Convert.FromHexString("990290008E0801020304050607 08"
            .Replace(" ", string.Empty, StringComparison.Ordinal)));

        Assert.Equal(2, elements.Count);
        Assert.Equal(0x99, elements[0].Tag);
        Assert.Equal(0x8E, elements[1].Tag);
    }

    [Fact]
    public void Parse_ReadsMultiByteTags()
    {
        IReadOnlyList<BerTlv> elements = BerTlv.Parse(Convert.FromHexString("5F1F03ABCDEF"));

        Assert.Single(elements);
        Assert.Equal(0x5F1F, elements[0].Tag);
        Assert.Equal("ABCDEF", Convert.ToHexString(elements[0].Value.Span));
    }

    [Fact]
    public void Parse_ReadsLongFormLengths()
    {
        byte[] value = new byte[200];
        byte[] encoded = [0x87, 0x81, 200, .. value];

        IReadOnlyList<BerTlv> elements = BerTlv.Parse(encoded);

        Assert.Single(elements);
        Assert.Equal(200, elements[0].Value.Length);
    }

    /// <summary>
    /// The parser keeps the source bytes rather than re-encoding, because secure
    /// messaging MACs the data objects exactly as the chip sent them. Re-encoding a
    /// 0x81-form length as short form would break the MAC on a valid document.
    /// </summary>
    [Fact]
    public void RawBytes_PreserveTheSourceLengthForm()
    {
        byte[] nonMinimal = [0x87, 0x81, 0x02, 0xAA, 0xBB];

        IReadOnlyList<BerTlv> elements = BerTlv.Parse(nonMinimal);

        Assert.Equal("878102AABB", Convert.ToHexString(elements[0].RawBytes.Span));
        Assert.NotEqual(
            Convert.ToHexString(BerTlv.Encode(0x87, Convert.FromHexString("AABB"))),
            Convert.ToHexString(elements[0].RawBytes.Span));
    }

    [Fact]
    public void Parse_SkipsFillerBytes()
    {
        IReadOnlyList<BerTlv> elements = BerTlv.Parse(Convert.FromHexString("00FF990290000000"));

        Assert.Single(elements);
        Assert.Equal(0x99, elements[0].Tag);
    }

    [Fact]
    public void Parse_RejectsATruncatedValue()
    {
        Assert.Throws<MrtdEncodingException>(() => BerTlv.Parse(Convert.FromHexString("870AAABB")));
    }

    [Fact]
    public void Parse_RejectsIndefiniteLength()
    {
        Assert.Throws<MrtdEncodingException>(() => BerTlv.Parse(Convert.FromHexString("308000")));
    }

    [Fact]
    public void Encode_UsesShortestValidLengthForm()
    {
        Assert.Equal("87020102", Convert.ToHexString(BerTlv.Encode(0x87, Convert.FromHexString("0102"))));
        Assert.Equal("8781", Convert.ToHexString(BerTlv.Encode(0x87, new byte[200]))[..4]);
    }
}

public sealed class MrzKeyTests
{
    [Theory]
    // The check digits published alongside the Doc 9303 worked example.
    [InlineData("L898902C<", '3')]
    [InlineData("690806", '1')]
    [InlineData("940623", '6')]
    public void CheckDigit_MatchesTheSpecification(string field, char expected)
    {
        Assert.Equal(expected, MrzKey.ComputeCheckDigit(field));
    }

    [Fact]
    public void ShortDocumentNumbers_ArePaddedWithFiller()
    {
        MrzKey key = MrzKey.Create("AB1234", "800101", "300101");

        Assert.Equal("AB1234<<<", key.DocumentNumber);
        Assert.StartsWith("AB1234<<<", key.MrzInformation, StringComparison.Ordinal);
    }

    [Fact]
    public void Seed_IsSixteenBytes()
    {
        Assert.Equal(16, MrzKey.Create("AB1234", "800101", "300101").ComputeSeed().Length);
    }

    [Fact]
    public void MalformedDates_AreRejected()
    {
        Assert.Throws<MrtdEncodingException>(() => MrzKey.Create("AB1234", "8001", "300101"));
    }

    [Fact]
    public void InvalidMrzCharacters_AreRejected()
    {
        Assert.Throws<MrtdEncodingException>(() => MrzKey.Create("AB-1234", "800101", "300101"));
    }

    [Fact]
    public void OverlongDocumentNumbers_AreRejectedRatherThanTruncated()
    {
        // Silently truncating would produce a wrong key and an unexplainable 6300.
        Assert.Throws<MrtdEncodingException>(() => MrzKey.Create("ABCDEFGHIJ", "800101", "300101"));
    }
}

public sealed class PaddingAndCounterTests
{
    [Fact]
    public void Padding_AppendsAFullBlockWhenAlreadyAligned()
    {
        byte[] aligned = new byte[8];
        byte[] padded = Iso7816Padding.Add(aligned);

        Assert.Equal(16, padded.Length);
        Assert.Equal(0x80, padded[8]);
    }

    [Fact]
    public void Padding_RoundTrips()
    {
        byte[] data = Convert.FromHexString("011E");
        byte[]? recovered = Iso7816Padding.Remove(Iso7816Padding.Add(data));

        Assert.Equal(data, recovered);
    }

    [Fact]
    public void Padding_ReturnsNullForAnInvalidTrailer()
    {
        Assert.Null(Iso7816Padding.Remove(Convert.FromHexString("0102030405060708")));
    }

    [Fact]
    public void Counter_IncrementsBigEndian()
    {
        SendSequenceCounter counter = new(Convert.FromHexString("00000000000000FF"));
        counter.Increment();

        Assert.Equal("0000000000000100", counter.ToString());
    }

    [Fact]
    public void Counter_WrapsOnOverflow()
    {
        SendSequenceCounter counter = new(Convert.FromHexString("FFFFFFFFFFFFFFFF"));
        counter.Increment();

        Assert.Equal("0000000000000000", counter.ToString());
    }

    [Fact]
    public void Counter_RejectsAWrongLengthSeed()
    {
        Assert.Throws<ArgumentException>(() => new SendSequenceCounter(new byte[4]));
    }
}

public sealed class ApduTracerTests
{
    /// <summary>
    /// A full trace of the authentication commands, combined with the MRZ, is enough to
    /// reconstruct the session keys and decrypt everything that follows. The headers stay
    /// because they are what actually helps diagnose a reader problem (NFR7).
    /// </summary>
    [Fact]
    public void AuthenticationPayloads_AreWithheldFromRenderedTraces()
    {
        ApduTracer tracer = new();

        tracer.Record(new ApduExchange(
            1,
            Convert.FromHexString("0082000028" + new string('A', 80) + "28"),
            Convert.FromHexString("00112233445566778899AABBCCDDEEFF9000"),
            TimeSpan.Zero));

        string text = tracer.ToText();

        // The four header bytes survive; everything from Lc onward is withheld.
        Assert.Contains("00820000", text, StringComparison.Ordinal);
        Assert.Contains("withheld", text, StringComparison.Ordinal);
        Assert.DoesNotContain("AAAAAAAAAA", text, StringComparison.Ordinal);
        Assert.DoesNotContain("00112233445566778899AABBCCDDEEFF", text, StringComparison.Ordinal);
    }

    [Fact]
    public void OrdinaryExchanges_AreRenderedInFull()
    {
        ApduTracer tracer = new();

        tracer.Record(new ApduExchange(
            1,
            Convert.FromHexString("00A4020C02011E"),
            Convert.FromHexString("9000"),
            TimeSpan.Zero));

        string text = tracer.ToText();

        Assert.Contains("00A4020C02011E", text, StringComparison.Ordinal);
        Assert.DoesNotContain("withheld", text, StringComparison.Ordinal);
    }

    [Fact]
    public void StatusWord_IsExtractedFromTheResponse()
    {
        ApduExchange exchange = new(
            1,
            Convert.FromHexString("00A4020C02011E"),
            Convert.FromHexString("6A82"),
            TimeSpan.Zero);

        Assert.Equal(0x6A82, exchange.StatusWord.Value);
    }
}
