using System.Security.Cryptography;
using MRTDScope.Core.Apdu;
using MRTDScope.Core.Crypto;
using MRTDScope.Core.Errors;
using MRTDScope.Core.Mrz;
using MRTDScope.Core.Protocol.SecureMessaging;
using MRTDScope.Core.Transport;

namespace MRTDScope.Core.Protocol.Bac;

/// <summary>
/// The outcome of a BAC attempt. Failure is a value, not an exception (NFR5).
/// </summary>
/// <param name="Succeeded">Whether mutual authentication completed.</param>
/// <param name="SecureMessaging">The established channel, or <c>null</c> on failure.</param>
/// <param name="FailureReason">A reason code from <see cref="Inspection.ReasonCodes"/>, or <c>null</c>.</param>
/// <param name="Detail">Operator-readable explanation.</param>
public sealed record BacResult(
    bool Succeeded,
    ISecureMessaging? SecureMessaging,
    string? FailureReason,
    string Detail);

/// <summary>
/// Basic Access Control: the MRZ-derived challenge-response that unlocks the chip and
/// establishes a 3DES secure channel (ICAO Doc 9303 Part 11, section 4.3).
/// </summary>
public sealed class BacProtocol
{
    private const byte ClaPlain = 0x00;
    private const byte InsGetChallenge = 0x84;
    private const byte InsExternalAuthenticate = 0x82;

    private const int NonceLength = 8;
    private const int KeyMaterialLength = 16;

    private readonly MrzKey _mrzKey;
    private readonly RandomNumberGenerator _random;

    /// <param name="mrzKey">The document key derived from the MRZ.</param>
    /// <param name="random">
    /// Randomness source. Overridable so the Doc 9303 Appendix D worked example can be
    /// reproduced exactly; production always uses the cryptographic default.
    /// </param>
    public BacProtocol(MrzKey mrzKey, RandomNumberGenerator? random = null)
    {
        ArgumentNullException.ThrowIfNull(mrzKey);

        _mrzKey = mrzKey;
        _random = random ?? RandomNumberGenerator.Create();
    }

    /// <summary>
    /// Runs mutual authentication and, on success, returns the established channel.
    /// </summary>
    /// <remarks>
    /// A wrong MRZ is the ordinary failure here and is reported, not thrown: the chip
    /// answers 6300 or 6988 and the caller records a failed access-control check. Only a
    /// transport breakdown or a malformed response raises.
    /// </remarks>
    public BacResult Authenticate(ICardTransport transport)
    {
        ArgumentNullException.ThrowIfNull(transport);

        BacKeyDerivation.KeyPair documentKeys = _mrzKey.DeriveDocumentKeys();

        ResponseApdu challengeResponse = transport.Transmit(
            new CommandApdu(ClaPlain, InsGetChallenge, 0x00, 0x00, expectedLength: NonceLength));

        if (!challengeResponse.IsSuccess)
        {
            return new BacResult(
                false,
                null,
                Inspection.ReasonCodes.AccessDenied,
                $"GET CHALLENGE returned {challengeResponse.StatusWord}.");
        }

        if (challengeResponse.Data.Length != NonceLength)
        {
            throw new MrtdEncodingException(
                $"GET CHALLENGE returned {challengeResponse.Data.Length} bytes; expected {NonceLength}.");
        }

        byte[] rndIc = challengeResponse.Data.ToArray();

        byte[] rndIfd = new byte[NonceLength];
        byte[] kIfd = new byte[KeyMaterialLength];
        _random.GetBytes(rndIfd);
        _random.GetBytes(kIfd);

        // S = RND.IFD || RND.IC || K.IFD
        byte[] s = new byte[NonceLength + NonceLength + KeyMaterialLength];
        rndIfd.CopyTo(s, 0);
        rndIc.CopyTo(s, NonceLength);
        kIfd.CopyTo(s, NonceLength * 2);

        byte[] eIfd = TripleDes.EncryptCbc(documentKeys.Encryption, s);
        byte[] mIfd = TripleDes.RetailMac(documentKeys.Mac, eIfd);

        byte[] authenticationData = new byte[eIfd.Length + mIfd.Length];
        eIfd.CopyTo(authenticationData, 0);
        mIfd.CopyTo(authenticationData, eIfd.Length);

        ResponseApdu authenticateResponse = transport.Transmit(
            new CommandApdu(
                ClaPlain,
                InsExternalAuthenticate,
                0x00,
                0x00,
                authenticationData,
                expectedLength: 40));

        if (!authenticateResponse.IsSuccess)
        {
            return new BacResult(
                false,
                null,
                Inspection.ReasonCodes.AccessDenied,
                $"EXTERNAL AUTHENTICATE returned {authenticateResponse.StatusWord}. " +
                "The MRZ key is most likely wrong for this document.");
        }

        if (authenticateResponse.Data.Length != 40)
        {
            throw new MrtdEncodingException(
                $"EXTERNAL AUTHENTICATE returned {authenticateResponse.Data.Length} bytes; expected 40.");
        }

        ReadOnlySpan<byte> responseData = authenticateResponse.Data.Span;
        ReadOnlySpan<byte> eIc = responseData[..32];
        ReadOnlySpan<byte> mIc = responseData[32..];

        byte[] expectedMac = TripleDes.RetailMac(documentKeys.Mac, eIc);

        if (!CryptographicOperations.FixedTimeEquals(expectedMac, mIc))
        {
            return new BacResult(
                false,
                null,
                Inspection.ReasonCodes.SecureMessagingIntegrity,
                "The chip's authentication response failed its checksum.");
        }

        byte[] r = TripleDes.DecryptCbc(documentKeys.Encryption, eIc);

        // R = RND.IC || RND.IFD || K.IC — the echoed RND.IFD is what proves the chip
        // answered this challenge rather than replaying a recorded one.
        ReadOnlySpan<byte> echoedRndIfd = r.AsSpan(NonceLength, NonceLength);

        if (!CryptographicOperations.FixedTimeEquals(echoedRndIfd, rndIfd))
        {
            return new BacResult(
                false,
                null,
                Inspection.ReasonCodes.ChallengeMismatch,
                "The chip did not echo the terminal nonce, so its response does not bind " +
                "to this session.");
        }

        ReadOnlySpan<byte> kIc = r.AsSpan(NonceLength * 2, KeyMaterialLength);

        byte[] sessionSeed = new byte[KeyMaterialLength];
        for (int i = 0; i < KeyMaterialLength; i++)
        {
            sessionSeed[i] = (byte)(kIfd[i] ^ kIc[i]);
        }

        BacKeyDerivation.KeyPair sessionKeys = BacKeyDerivation.Derive(sessionSeed);

        // SSC starts as the low four bytes of each nonce, in chip-then-terminal order.
        byte[] ssc = new byte[NonceLength];
        rndIc.AsSpan(4, 4).CopyTo(ssc);
        rndIfd.AsSpan(4, 4).CopyTo(ssc.AsSpan(4));

        TripleDesSecureMessaging channel = new(
            sessionKeys.Encryption,
            sessionKeys.Mac,
            new SendSequenceCounter(ssc));

        CryptographicOperations.ZeroMemory(kIfd);
        CryptographicOperations.ZeroMemory(sessionSeed);
        CryptographicOperations.ZeroMemory(r);

        return new BacResult(
            true,
            channel,
            null,
            "Mutual authentication completed and a 3DES secure channel is established.");
    }
}
