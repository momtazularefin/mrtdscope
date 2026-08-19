using System.Security.Cryptography;
using MRTDScope.Core.Apdu;
using MRTDScope.Core.Crypto;
using MRTDScope.Core.Mrz;
using MRTDScope.Core.Protocol.Bac;
using MRTDScope.Core.Protocol.SecureMessaging;
using MRTDScope.Core.Tests.Support;

namespace MRTDScope.Core.Tests.Protocol;

/// <summary>
/// The BAC implementation checked against the worked example published in ICAO Doc 9303
/// Part 11, Appendix D.
/// </summary>
/// <remarks>
/// These vectors are the strongest evidence available without hardware: they are
/// authored by the standards body, not by this project, so agreement means the
/// implementation matches the specification rather than matching its own assumptions.
/// Every intermediate value is asserted, so a failure localizes to one step instead of
/// reporting only that the session keys came out wrong.
/// </remarks>
public sealed class Doc9303AppendixDTests
{
    // Appendix D.2 — the MRZ of the example document.
    private const string DocumentNumber = "L898902C<";
    private const string DateOfBirth = "690806";
    private const string DateOfExpiry = "940623";

    private const string ExpectedMrzInformation = "L898902C<369080619406236";
    private const string ExpectedSeed = "239AB9CB282DAF66231DC5A4DF6BFBAE";
    private const string ExpectedKEnc = "AB94FDECF2674FDFB9B391F85D7F76F2";
    private const string ExpectedKMac = "7962D9ECE03D1ACD4C76089DCE131543";

    // Appendix D.3 — mutual authentication.
    private const string RndIc = "4608F91988702212";
    private const string RndIfd = "781723860C06C226";
    private const string KIfd = "0B795240CB7049B01C19B33E32804F0B";

    private const string ExpectedEIfd =
        "72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F2";
    private const string ExpectedMIfd = "5F1448EEA8AD90A7";

    private const string ResponseEIc =
        "46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F";
    private const string ResponseMIc = "2F2D235D074D7449";

    // Appendix D.4 — the resulting session state.
    private const string ExpectedSessionKEnc = "979EC13B1CBFE9DCD01AB0FED307EAE5";
    private const string ExpectedSessionKMac = "F1CB1F1FB5ADF208806B89DC579DC1F8";
    private const string ExpectedSsc = "887022120C06C226";

    private static MrzKey Key() => MrzKey.Create(DocumentNumber, DateOfBirth, DateOfExpiry);

    [Fact]
    public void MrzInformation_MatchesTheWorkedExample()
    {
        Assert.Equal(ExpectedMrzInformation, Key().MrzInformation);
    }

    [Fact]
    public void KeySeed_MatchesTheWorkedExample()
    {
        Assert.Equal(ExpectedSeed, Convert.ToHexString(Key().ComputeSeed()));
    }

    [Fact]
    public void DocumentKeys_MatchTheWorkedExample()
    {
        BacKeyDerivation.KeyPair keys = Key().DeriveDocumentKeys();

        Assert.Equal(ExpectedKEnc, Convert.ToHexString(keys.Encryption));
        Assert.Equal(ExpectedKMac, Convert.ToHexString(keys.Mac));
    }

    [Fact]
    public void TerminalAuthenticationData_MatchesTheWorkedExample()
    {
        BacKeyDerivation.KeyPair keys = Key().DeriveDocumentKeys();

        // S = RND.IFD || RND.IC || K.IFD
        byte[] s = Bytes(RndIfd + RndIc + KIfd);

        byte[] eIfd = TripleDes.EncryptCbc(keys.Encryption, s);
        byte[] mIfd = TripleDes.RetailMac(keys.Mac, eIfd);

        Assert.Equal(ExpectedEIfd, Convert.ToHexString(eIfd));
        Assert.Equal(ExpectedMIfd, Convert.ToHexString(mIfd));
    }

    [Fact]
    public void Authenticate_ReproducesTheWorkedExampleEndToEnd()
    {
        ScriptedTransport transport = new(
            new ScriptedTransport.Exchange(
                ExpectedCommand: "0084000008",
                Response: RndIc + "9000"),
            new ScriptedTransport.Exchange(
                ExpectedCommand: "0082000028" + ExpectedEIfd + ExpectedMIfd + "28",
                Response: ResponseEIc + ResponseMIc + "9000"));

        BacProtocol protocol = new(Key(), new FixedRandom(Bytes(RndIfd), Bytes(KIfd)));

        BacResult result = protocol.Authenticate(transport);

        Assert.True(result.Succeeded, result.Detail);
        Assert.Null(result.FailureReason);
        Assert.NotNull(result.SecureMessaging);
        Assert.True(transport.IsExhausted);
    }

    [Fact]
    public void SessionKeysAndCounter_MatchTheWorkedExample()
    {
        // K.IC is recovered from the chip's response, and the session seed is the XOR of
        // the two halves of key material.
        BacKeyDerivation.KeyPair documentKeys = Key().DeriveDocumentKeys();
        byte[] r = TripleDes.DecryptCbc(documentKeys.Encryption, Bytes(ResponseEIc));

        byte[] kIc = r[16..32];
        byte[] kIfd = Bytes(KIfd);

        byte[] sessionSeed = new byte[16];
        for (int i = 0; i < sessionSeed.Length; i++)
        {
            sessionSeed[i] = (byte)(kIfd[i] ^ kIc[i]);
        }

        BacKeyDerivation.KeyPair sessionKeys = BacKeyDerivation.Derive(sessionSeed);

        Assert.Equal(ExpectedSessionKEnc, Convert.ToHexString(sessionKeys.Encryption));
        Assert.Equal(ExpectedSessionKMac, Convert.ToHexString(sessionKeys.Mac));

        // SSC is the low four bytes of RND.IC followed by the low four of RND.IFD.
        byte[] ssc = [.. Bytes(RndIc)[4..], .. Bytes(RndIfd)[4..]];
        Assert.Equal(ExpectedSsc, Convert.ToHexString(ssc));
    }

    [Fact]
    public void ProtectedSelect_MatchesTheWorkedExample()
    {
        ISecureMessaging channel = SessionChannel();

        // Appendix D.4: SELECT EF.COM, unprotected 00 A4 02 0C 02 01 1E.
        CommandApdu select = new(0x00, 0xA4, 0x02, 0x0C, Bytes("011E"));
        CommandApdu protectedSelect = channel.Protect(select);

        Assert.Equal(
            "0CA4020C158709016375432908C044F68E08BF8B92D635FF24F800",
            Convert.ToHexString(protectedSelect.ToBytes()));
    }

    [Fact]
    public void ProtectedSelectResponse_VerifiesAndDecodes()
    {
        ISecureMessaging channel = SessionChannel();
        channel.Protect(new CommandApdu(0x00, 0xA4, 0x02, 0x0C, Bytes("011E")));

        ResponseApdu response = ResponseApdu.Parse(
            Bytes("990290008E08FA855A5D4C50A8ED9000"));

        ResponseApdu plain = channel.Unprotect(response);

        Assert.True(plain.IsSuccess);
        Assert.Equal(0, plain.Data.Length);
    }

    [Fact]
    public void ProtectedReadBinary_MatchesTheWorkedExample()
    {
        ISecureMessaging channel = SessionChannel();

        // Advance the counter past the SELECT exchange.
        channel.Protect(new CommandApdu(0x00, 0xA4, 0x02, 0x0C, Bytes("011E")));
        channel.Unprotect(ResponseApdu.Parse(Bytes("990290008E08FA855A5D4C50A8ED9000")));

        // Appendix D.4: READ BINARY of the first four bytes, unprotected 00 B0 00 00 04.
        CommandApdu read = new(0x00, 0xB0, 0x00, 0x00, expectedLength: 4);
        CommandApdu protectedRead = channel.Protect(read);

        Assert.Equal(
            "0CB000000D9701048E08ED6705417E96BA5500",
            Convert.ToHexString(protectedRead.ToBytes()));

        ResponseApdu response = ResponseApdu.Parse(
            Bytes("8709019FF0EC34F9922651990290008E08AD55CC17140B2DED9000"));

        ResponseApdu plain = channel.Unprotect(response);

        Assert.True(plain.IsSuccess);
        Assert.Equal("60145F01", Convert.ToHexString(plain.Data.Span));
    }

    private static ISecureMessaging SessionChannel() =>
        new TripleDesSecureMessaging(
            Bytes(ExpectedSessionKEnc),
            Bytes(ExpectedSessionKMac),
            new SendSequenceCounter(Bytes(ExpectedSsc)));

    private static byte[] Bytes(string hex) => Convert.FromHexString(hex);
}
