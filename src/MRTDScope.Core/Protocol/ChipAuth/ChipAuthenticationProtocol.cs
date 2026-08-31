using System.Security.Cryptography;
using MRTDScope.Core.Apdu;
using MRTDScope.Core.Crypto;
using MRTDScope.Core.Errors;
using MRTDScope.Core.Inspection;
using MRTDScope.Core.Lds;
using MRTDScope.Core.Protocol.Pace;
using MRTDScope.Core.Protocol.SecureMessaging;
using MRTDScope.Core.Tlv;
using MRTDScope.Core.Transport;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;

namespace MRTDScope.Core.Protocol.ChipAuth;

/// <summary>What DG14 says about Chip Authentication.</summary>
/// <param name="ProtocolOid">The id-CA variant.</param>
/// <param name="Cipher">The secure-messaging suite it establishes.</param>
/// <param name="PublicKey">The chip's static Diffie-Hellman public key.</param>
/// <param name="KeyId">The key identifier, when the chip holds more than one.</param>
public sealed record ChipAuthenticationParameters(
    string ProtocolOid,
    PaceCipher Cipher,
    ECPublicKeyParameters PublicKey,
    int? KeyId);

/// <summary>The outcome of a Chip Authentication attempt.</summary>
public sealed record ChipAuthenticationResult(
    bool Succeeded,
    ISecureMessaging? SecureMessaging,
    string? FailureReason,
    string Detail);

/// <summary>
/// Chip Authentication: an ephemeral-static Diffie-Hellman agreement against the chip's
/// signed static key (ICAO Doc 9303 Part 11 §6.2).
/// </summary>
/// <remarks>
/// Like Active Authentication, this detects a cloned chip — but it does so without the
/// challenge-semantics problem. An Active Authentication transcript is a signature over a
/// value the terminal chose, so a coerced reader could obtain a signature over meaningful
/// data and use it as transferable proof the holder presented their document. Chip
/// Authentication's transcript proves nothing to a third party, because either party
/// could have produced it.
/// <para>
/// It also yields something Active Authentication does not: fresh, strong session keys.
/// Success restarts secure messaging on them, so every subsequent read is protected by a
/// channel that only the genuine chip could have established.
/// </para>
/// <para>
/// The static public key comes from DG14, which the Document Security Object covers — so
/// Passive Authentication is what makes this key trustworthy, and the two checks are
/// worth nothing apart.
/// </para>
/// </remarks>
public sealed class ChipAuthenticationProtocol
{
    private const byte ClaPlain = 0x00;
    private const byte InsManageSecurityEnvironment = 0x22;
    private const byte InsGeneralAuthenticate = 0x86;

    private const int TagDynamicAuthenticationData = 0x7C;
    private const int TagEphemeralPublicKey = 0x80;

    /// <summary>id-PK-ECDH: the chip's static Chip Authentication public key.</summary>
    public const string PublicKeyEcdhOid = "0.4.0.127.0.7.2.2.1.2";

    /// <summary>id-CA-ECDH: the Chip Authentication protocol family.</summary>
    public const string ProtocolEcdhOid = "0.4.0.127.0.7.2.2.3.2";

    private readonly ChipAuthenticationParameters _parameters;
    private readonly SecureRandom _random;

    public ChipAuthenticationProtocol(
        ChipAuthenticationParameters parameters,
        SecureRandom? random = null)
    {
        ArgumentNullException.ThrowIfNull(parameters);

        _parameters = parameters;
        _random = random ?? new SecureRandom();
    }

    /// <summary>
    /// Extracts the Chip Authentication parameters from DG14, or <c>null</c> when the
    /// document does not support it.
    /// </summary>
    public static ChipAuthenticationParameters? FromDg14(ReadOnlySpan<byte> dg14Content)
    {
        IReadOnlyList<BerTlv> outer = BerTlv.Parse(dg14Content);
        BerTlv? root = BerTlv.Find(outer, DataGroup.Dg14.Tag);

        if (root is null)
        {
            return null;
        }

        SecurityInfos infos = SecurityInfos.Parse(root.Value.Span);

        SecurityInfo? protocolInfo = infos.Entries.FirstOrDefault(
            entry => entry.Protocol.StartsWith(ProtocolEcdhOid + ".", StringComparison.Ordinal));

        SecurityInfo? keyInfo = infos.Entries.FirstOrDefault(
            entry => entry.Protocol == PublicKeyEcdhOid);

        if (protocolInfo is null || keyInfo is null)
        {
            return null;
        }

        // The cipher is the last arc of the protocol OID, using the same numbering PACE
        // uses: 1 is 3DES, 2 to 4 are AES-128, 192 and 256.
        PaceCipher? cipher = protocolInfo.Protocol[(ProtocolEcdhOid.Length + 1)..] switch
        {
            "1" => PaceCipher.TripleDes,
            "2" => PaceCipher.Aes128,
            "3" => PaceCipher.Aes192,
            "4" => PaceCipher.Aes256,
            _ => null,
        };

        if (cipher is not { } selected || selected == PaceCipher.TripleDes)
        {
            return null;
        }

        ECPublicKeyParameters publicKey;
        try
        {
            publicKey = (ECPublicKeyParameters)PublicKeyFactory.CreateKey(
                SubjectPublicKeyInfo.GetInstance(keyInfo.RequiredData));
        }
        catch (Exception exception) when (exception is ArgumentException
            or InvalidCastException or SecurityUtilityException or IOException)
        {
            throw new MrtdEncodingException(
                "DG14 carries a Chip Authentication public key this build cannot read.",
                exception);
        }

        int? keyId = keyInfo.OptionalData is DerInteger identifier
            ? identifier.IntValueExact
            : null;

        return new ChipAuthenticationParameters(
            protocolInfo.Protocol, selected, publicKey, keyId);
    }

    /// <summary>
    /// Runs Chip Authentication and, on success, returns the restarted secure channel.
    /// </summary>
    /// <remarks>
    /// Unlike PACE, this is performed inside the eMRTD application, which is already
    /// selected by the time access control has completed.
    /// </remarks>
    public ChipAuthenticationResult Establish(ICardTransport transport)
    {
        ArgumentNullException.ThrowIfNull(transport);

        ECDomainParameters domain = _parameters.PublicKey.Parameters;

        // Step 0: announce the protocol.
        ResponseApdu mse = transport.Transmit(BuildManageSecurityEnvironment());

        if (!mse.IsSuccess)
        {
            return new ChipAuthenticationResult(
                false,
                null,
                ReasonCodes.AccessDenied,
                $"MSE:Set AT for Chip Authentication returned {mse.StatusWord}.");
        }

        // Step 1: an ephemeral key pair over the chip's own domain parameters.
        BigInteger ephemeralPrivate = NewScalar(domain.N);
        ECPoint ephemeralPublic = domain.G.Multiply(ephemeralPrivate).Normalize();

        ResponseApdu authenticate = transport.Transmit(new CommandApdu(
            ClaPlain,
            InsGeneralAuthenticate,
            p1: 0x00,
            p2: 0x00,
            BerTlv.Encode(
                TagDynamicAuthenticationData,
                BerTlv.Encode(
                    TagEphemeralPublicKey,
                    ephemeralPublic.GetEncoded(compressed: false))),
            expectedLength: CommandApdu.MaxShortLength));

        if (!authenticate.IsSuccess)
        {
            return new ChipAuthenticationResult(
                false,
                null,
                ReasonCodes.AccessDenied,
                $"Chip Authentication key agreement returned {authenticate.StatusWord}.");
        }

        // Step 2: agree the shared secret against the chip's signed static key. There is
        // no token exchange — the proof is that the chip can continue the conversation on
        // the derived keys, which it can only do with the matching private key.
        ECPoint shared = _parameters.PublicKey.Q.Multiply(ephemeralPrivate).Normalize();

        if (shared.IsInfinity)
        {
            return new ChipAuthenticationResult(
                false,
                null,
                ReasonCodes.ChallengeMismatch,
                "Chip Authentication key agreement produced the point at infinity.");
        }

        byte[] sharedSecret = BigIntegers.AsUnsignedByteArray(
            (domain.Curve.FieldSize + 7) / 8,
            shared.AffineXCoord.ToBigInteger());

        byte[] encryptionKey = PaceKeyDerivation.DeriveEncryptionKey(sharedSecret, _parameters.Cipher);
        byte[] macKey = PaceKeyDerivation.DeriveMacKey(sharedSecret, _parameters.Cipher);

        CryptographicOperations.ZeroMemory(sharedSecret);

        AesSecureMessaging channel = new(
            encryptionKey, macKey, new SendSequenceCounter(new byte[16]));

        return new ChipAuthenticationResult(
            true,
            channel,
            null,
            $"Chip Authentication agreed a shared secret against the signed DG14 key and " +
            $"restarted secure messaging on fresh {_parameters.Cipher} session keys.");
    }

    private CommandApdu BuildManageSecurityEnvironment()
    {
        byte[] oid = BerTlv.Encode(
            0x80, new DerObjectIdentifier(_parameters.ProtocolOid).GetEncoded()[2..]);

        // Tag 0x84 is conditional: required only when the chip holds more than one
        // Chip Authentication private key. Sending it otherwise is the same mistake that
        // broke PACE against a single-parameter chip.
        byte[] data = _parameters.KeyId is { } keyId
            ? [.. oid, .. BerTlv.Encode(0x84, [(byte)keyId])]
            : oid;

        return new CommandApdu(
            ClaPlain, InsManageSecurityEnvironment, p1: 0x41, p2: 0xA4, data);
    }

    private BigInteger NewScalar(BigInteger order)
    {
        BigInteger value;

        do
        {
            value = new BigInteger(order.BitLength, _random);
        }
        while (value.CompareTo(BigInteger.One) < 0 || value.CompareTo(order) >= 0);

        return value;
    }
}
