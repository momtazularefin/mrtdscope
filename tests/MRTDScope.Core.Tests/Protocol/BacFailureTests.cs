using MRTDScope.Core.Apdu;
using MRTDScope.Core.Errors;
using MRTDScope.Core.Inspection;
using MRTDScope.Core.Mrz;
using MRTDScope.Core.Protocol.Bac;
using MRTDScope.Core.Protocol.SecureMessaging;
using MRTDScope.Core.Tests.Support;

namespace MRTDScope.Core.Tests.Protocol;

/// <summary>
/// How BAC behaves when things go wrong.
/// </summary>
/// <remarks>
/// These matter as much as the success path. A reader that only proves it can succeed
/// has demonstrated nothing about the case that counts, and each failure must be
/// reported as its own distinguishable reason rather than a single "authentication
/// failed" (NFR5, D003).
/// </remarks>
public sealed class BacFailureTests
{
    private const string RndIc = "4608F91988702212";
    private const string RndIfd = "781723860C06C226";
    private const string KIfd = "0B795240CB7049B01C19B33E32804F0B";

    private const string EIfd =
        "72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F2";
    private const string MIfd = "5F1448EEA8AD90A7";
    private const string EIc =
        "46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F";
    private const string MIc = "2F2D235D074D7449";

    [Fact]
    public void WrongMrz_IsReportedAsAccessDenied_NotThrown()
    {
        // 6300 is what a chip answers when the terminal's key does not match.
        ScriptedTransport transport = new(
            new ScriptedTransport.Exchange("0084000008", RndIc + "9000"),
            new ScriptedTransport.Exchange("0082000028" + EIfd + MIfd + "28", "6300"));

        BacResult result = Protocol().Authenticate(transport);

        Assert.False(result.Succeeded);
        Assert.Equal(ReasonCodes.AccessDenied, result.FailureReason);
        Assert.Null(result.SecureMessaging);
        Assert.Contains("6300", result.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void TamperedChipResponse_IsCaughtByTheChecksum()
    {
        // Flip the last byte of the chip's MAC.
        string tamperedMac = MIc[..14] + "4A";

        ScriptedTransport transport = new(
            new ScriptedTransport.Exchange("0084000008", RndIc + "9000"),
            new ScriptedTransport.Exchange("0082000028" + EIfd + MIfd + "28", EIc + tamperedMac + "9000"));

        BacResult result = Protocol().Authenticate(transport);

        Assert.False(result.Succeeded);
        Assert.Equal(ReasonCodes.SecureMessagingIntegrity, result.FailureReason);
    }

    [Fact]
    public void ChipEchoingTheWrongNonce_FailsTheChallengeBinding()
    {
        // A response replayed from an earlier session carries a MAC that verifies
        // perfectly — it was genuine once. What it cannot do is echo the nonce this
        // terminal generated a moment ago. Build exactly that: a well-formed, correctly
        // MAC'd response whose embedded RND.IFD belongs to some other session.
        MRTDScope.Core.Crypto.BacKeyDerivation.KeyPair documentKeys = Key().DeriveDocumentKeys();

        byte[] staleRndIfd = Convert.FromHexString("0102030405060708");
        byte[] forged =
        [
            .. Convert.FromHexString(RndIc),
            .. staleRndIfd,
            .. Convert.FromHexString(KIfd),
        ];

        byte[] forgedEIc = MRTDScope.Core.Crypto.TripleDes.EncryptCbc(documentKeys.Encryption, forged);
        byte[] forgedMIc = MRTDScope.Core.Crypto.TripleDes.RetailMac(documentKeys.Mac, forgedEIc);

        ScriptedTransport transport = new(
            new ScriptedTransport.Exchange("0084000008", RndIc + "9000"),
            new ScriptedTransport.Exchange(
                "0082000028" + EIfd + MIfd + "28",
                Convert.ToHexString(forgedEIc) + Convert.ToHexString(forgedMIc) + "9000"));

        BacResult result = Protocol().Authenticate(transport);

        Assert.False(result.Succeeded);

        // The checksum passed, so this must be caught by the nonce binding specifically
        // and reported as such — not lumped in with an integrity failure.
        Assert.Equal(ReasonCodes.ChallengeMismatch, result.FailureReason);
        Assert.Null(result.SecureMessaging);
    }

    [Fact]
    public void ChallengeOfWrongLength_IsRejectedAsMalformed()
    {
        ScriptedTransport transport = new(
            new ScriptedTransport.Exchange("0084000008", "460891889000"));

        Assert.Throws<MrtdEncodingException>(() => Protocol().Authenticate(transport));
    }

    [Fact]
    public void GetChallengeFailure_IsReportedNotThrown()
    {
        ScriptedTransport transport = new(
            new ScriptedTransport.Exchange("0084000008", "6A82"));

        BacResult result = Protocol().Authenticate(transport);

        Assert.False(result.Succeeded);
        Assert.Equal(ReasonCodes.AccessDenied, result.FailureReason);
    }

    [Fact]
    public void CorruptedResponseMac_BreaksTheSecureChannel()
    {
        ISecureMessaging channel = new TripleDesSecureMessaging(
            Convert.FromHexString("979EC13B1CBFE9DCD01AB0FED307EAE5"),
            Convert.FromHexString("F1CB1F1FB5ADF208806B89DC579DC1F8"),
            new SendSequenceCounter(Convert.FromHexString("887022120C06C226")));

        channel.Protect(new CommandApdu(0x00, 0xA4, 0x02, 0x0C, Convert.FromHexString("011E")));

        // Same valid response as the worked example, with one MAC byte flipped.
        ResponseApdu tampered = ResponseApdu.Parse(
            Convert.FromHexString("990290008E08FA855A5D4C50A8EE9000"));

        SecureMessagingException error =
            Assert.Throws<SecureMessagingException>(() => channel.Unprotect(tampered));

        Assert.Contains("checksum", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ResponseMissingItsChecksum_IsRejected()
    {
        ISecureMessaging channel = new TripleDesSecureMessaging(
            Convert.FromHexString("979EC13B1CBFE9DCD01AB0FED307EAE5"),
            Convert.FromHexString("F1CB1F1FB5ADF208806B89DC579DC1F8"),
            new SendSequenceCounter(Convert.FromHexString("887022120C06C226")));

        channel.Protect(new CommandApdu(0x00, 0xA4, 0x02, 0x0C, Convert.FromHexString("011E")));

        ResponseApdu noMac = ResponseApdu.Parse(Convert.FromHexString("990290009000"));

        Assert.Throws<SecureMessagingException>(() => channel.Unprotect(noMac));
    }

    private static MrzKey Key() => MrzKey.Create("L898902C<", "690806", "940623");

    private static BacProtocol Protocol() => new(
        Key(),
        new FixedRandom(Convert.FromHexString(RndIfd), Convert.FromHexString(KIfd)));
}
