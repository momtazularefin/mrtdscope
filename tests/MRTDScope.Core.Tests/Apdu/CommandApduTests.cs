using MRTDScope.Core.Apdu;
using MRTDScope.Core.Errors;

namespace MRTDScope.Core.Tests.Apdu;

/// <summary>
/// APDU encoding across all four ISO/IEC 7816-4 cases, short and extended.
/// </summary>
/// <remarks>
/// Le is nullable rather than a sentinel because "no Le field" and "Le = 0 meaning 256"
/// are different commands on the wire. Conflating them is a standard source of 6700
/// responses from real chips, so both forms are pinned here.
/// </remarks>
public sealed class CommandApduTests
{
    [Fact]
    public void Case1_HeaderOnly()
    {
        Assert.Equal("00A40400", Hex(new CommandApdu(0x00, 0xA4, 0x04, 0x00)));
    }

    [Fact]
    public void Case2Short_LeOnly()
    {
        Assert.Equal("0084000008", Hex(new CommandApdu(0x00, 0x84, 0x00, 0x00, expectedLength: 8)));
    }

    [Fact]
    public void Case2Short_Le256_EncodesAsZero()
    {
        Assert.Equal(
            "00B0000000",
            Hex(new CommandApdu(0x00, 0xB0, 0x00, 0x00, expectedLength: CommandApdu.MaxShortLength)));
    }

    [Fact]
    public void Case3Short_DataWithoutLe()
    {
        Assert.Equal(
            "00A4020C02011E",
            Hex(new CommandApdu(0x00, 0xA4, 0x02, 0x0C, Convert.FromHexString("011E"))));
    }

    [Fact]
    public void Case4Short_DataAndLe()
    {
        Assert.Equal(
            "00A4020C02011E00",
            Hex(new CommandApdu(
                0x00, 0xA4, 0x02, 0x0C,
                Convert.FromHexString("011E"),
                expectedLength: CommandApdu.MaxShortLength)));
    }

    [Fact]
    public void Case2Extended_ThreeByteLe()
    {
        CommandApdu command = new(0x00, 0xB0, 0x00, 0x00, expectedLength: 4096);

        Assert.True(command.IsExtended);
        Assert.Equal("00B0000000" + "1000", Hex(command));
    }

    [Fact]
    public void Case3Extended_ThreeByteLc()
    {
        byte[] data = new byte[300];
        CommandApdu command = new(0x00, 0x2A, 0x00, 0x00, data);

        string encoded = Hex(command);

        Assert.True(command.IsExtended);
        Assert.StartsWith("002A0000" + "00012C", encoded, StringComparison.Ordinal);
        Assert.Equal(4 + 3 + 300, encoded.Length / 2);
    }

    [Theory]
    [InlineData("00A40400")]
    [InlineData("0084000008")]
    [InlineData("00A4020C02011E")]
    [InlineData("00A4020C02011E00")]
    [InlineData("00B0000000")]
    public void Parse_RoundTripsEveryCase(string hex)
    {
        CommandApdu parsed = CommandApdu.Parse(Convert.FromHexString(hex));
        Assert.Equal(hex, Hex(parsed));
    }

    [Fact]
    public void Parse_DistinguishesAbsentLeFromLe256()
    {
        CommandApdu withoutLe = CommandApdu.Parse(Convert.FromHexString("00A4020C02011E"));
        CommandApdu withLe = CommandApdu.Parse(Convert.FromHexString("00A4020C02011E00"));

        Assert.Null(withoutLe.ExpectedLength);
        Assert.Equal(CommandApdu.MaxShortLength, withLe.ExpectedLength);
    }

    [Fact]
    public void Parse_RejectsATruncatedHeader()
    {
        Assert.Throws<MrtdEncodingException>(() => CommandApdu.Parse(Convert.FromHexString("00A404")));
    }

    [Fact]
    public void Parse_RejectsAnLcThatOverrunsTheBuffer()
    {
        Assert.Throws<MrtdEncodingException>(() => CommandApdu.Parse(Convert.FromHexString("00A4020C0AFF")));
    }

    [Fact]
    public void SecureMessagingBits_AreDetected()
    {
        Assert.False(new CommandApdu(0x00, 0xA4, 0x02, 0x0C).IsSecureMessaging);
        Assert.True(new CommandApdu(0x0C, 0xA4, 0x02, 0x0C).IsSecureMessaging);
    }

    private static string Hex(CommandApdu command) => Convert.ToHexString(command.ToBytes());
}
