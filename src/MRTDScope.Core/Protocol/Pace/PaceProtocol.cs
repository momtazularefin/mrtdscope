using System.Security.Cryptography;
using MRTDScope.Core.Apdu;
using MRTDScope.Core.Crypto;
using MRTDScope.Core.Errors;
using MRTDScope.Core.Inspection;
using MRTDScope.Core.Mrz;
using MRTDScope.Core.Protocol.SecureMessaging;
using MRTDScope.Core.Tlv;
using MRTDScope.Core.Transport;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace MRTDScope.Core.Protocol.Pace;

/// <summary>Which shared secret authenticates the PACE session.</summary>
public enum PacePasswordKind
{
    /// <summary>The MRZ, as printed. Password reference 1.</summary>
    Mrz = 1,

    /// <summary>The six-digit Card Access Number printed on the datapage. Password reference 2.</summary>
    Can = 2,
}

/// <summary>The outcome of a PACE attempt. Failure is a value, not an exception (NFR5).</summary>
public sealed record PaceResult(
    bool Succeeded,
    ISecureMessaging? SecureMessaging,
    string? FailureReason,
    string Detail);

/// <summary>
/// PACE with Generic Mapping over elliptic curves
/// (ICAO Doc 9303 Part 11 §4.4).
/// </summary>
/// <remarks>
/// PACE replaces BAC's weakness: the BAC key is derived entirely from MRZ data whose
/// entropy is low enough to brute-force offline from a recorded session. PACE instead
/// uses the password only to encrypt a chip-chosen nonce, then performs a Diffie-Hellman
/// agreement whose generator is remapped by that nonce — so a passive eavesdropper
/// recovers nothing offline, and an active attacker gets one guess per session.
/// <para>
/// Generic Mapping is four <c>GENERAL AUTHENTICATE</c> exchanges: fetch and decrypt the
/// nonce, map it to a fresh generator, agree a key over that generator, then exchange
/// authentication tokens. The first three are sent with command chaining (CLA 0x10); only
/// the last completes the chain.
/// </para>
/// </remarks>
public sealed class PaceProtocol
{
    private const byte ClaPlain = 0x00;
    private const byte ClaChaining = 0x10;
    private const byte InsManageSecurityEnvironment = 0x22;
    private const byte InsGeneralAuthenticate = 0x86;

    private const int TagDynamicAuthenticationData = 0x7C;
    private const int TagEncryptedNonce = 0x80;
    private const int TagMappingDataTerminal = 0x81;
    private const int TagMappingDataChip = 0x82;
    private const int TagKeyAgreementTerminal = 0x83;
    private const int TagKeyAgreementChip = 0x84;
    private const int TagTokenTerminal = 0x85;
    private const int TagTokenChip = 0x86;

    /// <summary>Public key template used when computing authentication tokens.</summary>
    private const int TagPublicKeyTemplate = 0x7F49;
    private const int TagOid = 0x06;
    private const int TagPoint = 0x86;

    private readonly PaceInfo _paceInfo;
    private readonly byte[] _password;
    private readonly PacePasswordKind _passwordKind;
    private readonly SecureRandom _random;
    private readonly bool _domainParametersAreAmbiguous;

    /// <param name="paceInfo">The variant the chip advertised in EF.CardAccess.</param>
    /// <param name="password">The derived password value.</param>
    /// <param name="passwordKind">Which password this is, for the MSE:Set AT reference.</param>
    /// <param name="random">Overridable so a worked example can be reproduced.</param>
    /// <param name="domainParametersAreAmbiguous">
    /// Whether the chip offers more than one set of domain parameters. Controls whether
    /// MSE:Set AT carries the conditional domain-parameter reference.
    /// </param>
    public PaceProtocol(
        PaceInfo paceInfo,
        ReadOnlySpan<byte> password,
        PacePasswordKind passwordKind = PacePasswordKind.Mrz,
        SecureRandom? random = null,
        bool domainParametersAreAmbiguous = false)
    {
        ArgumentNullException.ThrowIfNull(paceInfo);

        _paceInfo = paceInfo;
        _password = password.ToArray();
        _passwordKind = passwordKind;
        _random = random ?? new SecureRandom();
        _domainParametersAreAmbiguous = domainParametersAreAmbiguous;
    }

    /// <summary>Builds a protocol instance from an MRZ.</summary>
    public static PaceProtocol FromMrz(
        PaceInfo paceInfo,
        MrzKey mrzKey,
        SecureRandom? random = null,
        bool domainParametersAreAmbiguous = false)
    {
        ArgumentNullException.ThrowIfNull(mrzKey);

        return new PaceProtocol(
            paceInfo,
            PaceKeyDerivation.MrzPassword(mrzKey),
            PacePasswordKind.Mrz,
            random,
            domainParametersAreAmbiguous);
    }

    /// <summary>Builds a protocol instance from a Card Access Number.</summary>
    public static PaceProtocol FromCan(PaceInfo paceInfo, string can, SecureRandom? random = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(can);

        return new PaceProtocol(
            paceInfo,
            System.Text.Encoding.ASCII.GetBytes(can.Trim()),
            PacePasswordKind.Can,
            random);
    }

    /// <summary>Runs PACE and, on success, returns the established AES channel.</summary>
    public PaceResult Establish(ICardTransport transport)
    {
        ArgumentNullException.ThrowIfNull(transport);

        if (!_paceInfo.Algorithm.IsSupported)
        {
            return new PaceResult(
                false,
                null,
                ReasonCodes.NotImplemented,
                $"This build does not execute {_paceInfo.Algorithm}.");
        }

        if (_paceInfo.ParameterId is not { } parameterId
            || PaceDomainParameters.CurveFor(parameterId) is not { } curveName)
        {
            return new PaceResult(
                false,
                null,
                ReasonCodes.NotImplemented,
                "The chip did not name standardized domain parameters this build recognizes. " +
                "Explicit domain parameters are deliberately not accepted: Doc 9303 warns " +
                "that using chip-supplied parameters can leak the password.");
        }

        X9ECParameters curve = ECNamedCurveTable.GetByName(curveName)
            ?? throw new MrtdEncodingException($"Curve '{curveName}' is unavailable.");

        ECDomainParameters domain = new(curve.Curve, curve.G, curve.N, curve.H);
        PaceCipher cipher = _paceInfo.Algorithm.Cipher;

        // Step 0: tell the chip which protocol and which password we intend to use.
        ResponseApdu mse = transport.Transmit(BuildManageSecurityEnvironment());

        if (!mse.IsSuccess)
        {
            return Failure(
                ReasonCodes.AccessDenied,
                $"MSE:Set AT for PACE returned {mse.StatusWord}.");
        }

        // Step 1: the chip encrypts a fresh nonce under a key derived from the password.
        ResponseApdu nonceResponse = transport.Transmit(GeneralAuthenticate(
            chaining: true, BerTlv.Encode(TagDynamicAuthenticationData, [])));

        if (!nonceResponse.IsSuccess)
        {
            return Failure(
                ReasonCodes.AccessDenied,
                $"The chip refused to issue a PACE nonce ({nonceResponse.StatusWord}).");
        }

        byte[] encryptedNonce = ExtractInner(nonceResponse, TagEncryptedNonce, "encrypted nonce");
        byte[] nonce = DecryptNonce(encryptedNonce, cipher);

        // Step 2: map the nonce onto a fresh generator.
        ECPrivateKeyParameters mappingPrivate = GenerateKey(domain, out ECPoint mappingPublic);

        ResponseApdu mappingResponse = transport.Transmit(GeneralAuthenticate(
            chaining: true,
            Wrap(TagMappingDataTerminal, mappingPublic.GetEncoded(compressed: false))));

        if (!mappingResponse.IsSuccess)
        {
            return Failure(
                ReasonCodes.AccessDenied,
                $"PACE nonce mapping returned {mappingResponse.StatusWord}.");
        }

        ECPoint chipMappingPublic = DecodePoint(
            domain, ExtractInner(mappingResponse, TagMappingDataChip, "chip mapping data"));

        // Generic Mapping: G' = s.G + (x . Y), where s is the decrypted nonce.
        ECPoint sharedH = chipMappingPublic.Multiply(mappingPrivate.D).Normalize();
        ECPoint mappedGenerator = domain.G
            .Multiply(new BigInteger(1, nonce))
            .Add(sharedH)
            .Normalize();

        if (mappedGenerator.IsInfinity)
        {
            return Failure(
                ReasonCodes.ChallengeMismatch,
                "Nonce mapping produced the point at infinity, so the mapped generator is " +
                "unusable. The password is almost certainly wrong.");
        }

        ECDomainParameters mappedDomain = new(
            curve.Curve, mappedGenerator, domain.N, domain.H);

        // Step 3: agree a key over the mapped generator.
        ECPrivateKeyParameters agreementPrivate = GenerateKey(mappedDomain, out ECPoint agreementPublic);

        ResponseApdu agreementResponse = transport.Transmit(GeneralAuthenticate(
            chaining: true,
            Wrap(TagKeyAgreementTerminal, agreementPublic.GetEncoded(compressed: false))));

        if (!agreementResponse.IsSuccess)
        {
            return Failure(
                ReasonCodes.AccessDenied,
                $"PACE key agreement returned {agreementResponse.StatusWord}.");
        }

        byte[] chipAgreementEncoded = ExtractInner(
            agreementResponse, TagKeyAgreementChip, "chip key-agreement data");
        ECPoint chipAgreementPublic = DecodePoint(mappedDomain, chipAgreementEncoded);

        ECPoint sharedPoint = chipAgreementPublic.Multiply(agreementPrivate.D).Normalize();

        if (sharedPoint.IsInfinity)
        {
            return Failure(
                ReasonCodes.ChallengeMismatch,
                "PACE key agreement produced the point at infinity.");
        }

        // Only the x-coordinate is the shared secret; the KDF uses the first coordinate.
        byte[] sharedSecret = BigIntegers.AsUnsignedByteArray(
            (curve.Curve.FieldSize + 7) / 8,
            sharedPoint.AffineXCoord.ToBigInteger());

        byte[] encryptionKey = PaceKeyDerivation.DeriveEncryptionKey(sharedSecret, cipher);
        byte[] macKey = PaceKeyDerivation.DeriveMacKey(sharedSecret, cipher);

        // Step 4: each side proves it derived the same keys by MAC-ing the other's
        // ephemeral public key, which is what binds the session to this exchange.
        byte[] terminalToken = ComputeToken(macKey, chipAgreementEncoded);

        ResponseApdu tokenResponse = transport.Transmit(GeneralAuthenticate(
            chaining: false, Wrap(TagTokenTerminal, terminalToken)));

        if (!tokenResponse.IsSuccess)
        {
            return Failure(
                ReasonCodes.AccessDenied,
                $"The chip rejected the terminal's PACE token ({tokenResponse.StatusWord}). " +
                "The password is most likely wrong for this document.");
        }

        byte[] chipToken = ExtractInner(tokenResponse, TagTokenChip, "chip authentication token");
        byte[] expectedChipToken = ComputeToken(
            macKey, agreementPublic.GetEncoded(compressed: false));

        if (!CryptographicOperations.FixedTimeEquals(chipToken, expectedChipToken))
        {
            return Failure(
                ReasonCodes.SecureMessagingIntegrity,
                "The chip's PACE authentication token did not verify.");
        }

        // After PACE the send sequence counter starts at zero, unlike BAC where it is
        // derived from the two nonces.
        AesSecureMessaging channel = new(
            encryptionKey,
            macKey,
            new SendSequenceCounter(new byte[16]));

        CryptographicOperations.ZeroMemory(sharedSecret);
        CryptographicOperations.ZeroMemory(nonce);

        return new PaceResult(
            true,
            channel,
            null,
            $"PACE completed with {_paceInfo.Algorithm} on {curveName}, establishing an " +
            "AES secure channel.");
    }

    private static PaceResult Failure(string reason, string detail) =>
        new(false, null, reason, detail);

    /// <summary>MSE:Set AT — announces the protocol OID and which password will be used.</summary>
    private CommandApdu BuildManageSecurityEnvironment()
    {
        byte[] oid = BerTlv.Encode(
            0x80, new DerObjectIdentifier(_paceInfo.Algorithm.Oid).GetEncoded()[2..]);
        byte[] passwordReference = BerTlv.Encode(0x83, [(byte)_passwordKind]);

        // Tag 0x84 is CONDITIONAL (Doc 9303 Part 11 §4.4.4.1): it identifies which domain
        // parameters to use, and is required only when the chip offers more than one set.
        // Sending it unconditionally asks a single-parameter chip to resolve a reference
        // it has no table for, which it answers with 6A88.
        byte[] data = _domainParametersAreAmbiguous && _paceInfo.ParameterId is { } parameterId
            ? [.. oid, .. passwordReference, .. BerTlv.Encode(0x84, [(byte)parameterId])]
            : [.. oid, .. passwordReference];

        return new CommandApdu(
            ClaPlain, InsManageSecurityEnvironment, p1: 0xC1, p2: 0xA4, data);
    }

    private static CommandApdu GeneralAuthenticate(bool chaining, byte[] data) =>
        new(
            chaining ? ClaChaining : ClaPlain,
            InsGeneralAuthenticate,
            p1: 0x00,
            p2: 0x00,
            data,
            expectedLength: CommandApdu.MaxShortLength);

    private static byte[] Wrap(int innerTag, byte[] value) =>
        BerTlv.Encode(TagDynamicAuthenticationData, BerTlv.Encode(innerTag, value));

    private static byte[] ExtractInner(ResponseApdu response, int tag, string what)
    {
        IReadOnlyList<BerTlv> outer = BerTlv.Parse(response.Data.Span);

        BerTlv container = BerTlv.Find(outer, TagDynamicAuthenticationData)
            ?? throw new MrtdEncodingException(
                $"The chip's response carried no dynamic authentication data while " +
                $"expecting the {what}.");

        BerTlv inner = BerTlv.Find(container.Children(), tag)
            ?? throw new MrtdEncodingException(
                $"The chip's response carried no 0x{tag:X2} object for the {what}.");

        return inner.Value.ToArray();
    }

    private byte[] DecryptNonce(byte[] encryptedNonce, PaceCipher cipher)
    {
        byte[] passwordKey = PaceKeyDerivation.DerivePasswordKey(_password, cipher);

        using Aes aes = Aes.Create();
        aes.Key = passwordKey;
        aes.Mode = System.Security.Cryptography.CipherMode.CBC;
        aes.Padding = PaddingMode.None;

        // The nonce is encrypted under an all-zero IV; it is a single block of random
        // data, so no chaining context is needed.
        return aes.DecryptCbc(encryptedNonce, new byte[16], PaddingMode.None);
    }

    private ECPrivateKeyParameters GenerateKey(ECDomainParameters domain, out ECPoint publicPoint)
    {
        BigInteger order = domain.N;
        BigInteger d;

        do
        {
            d = new BigInteger(order.BitLength, _random);
        }
        while (d.CompareTo(BigInteger.One) < 0 || d.CompareTo(order) >= 0);

        publicPoint = domain.G.Multiply(d).Normalize();
        return new ECPrivateKeyParameters(d, domain);
    }

    private static ECPoint DecodePoint(ECDomainParameters domain, byte[] encoded)
    {
        try
        {
            ECPoint point = domain.Curve.DecodePoint(encoded).Normalize();

            // A point off the curve or at infinity would let a malicious chip steer the
            // agreement. BouncyCastle validates curve membership on decode; infinity is
            // checked explicitly.
            if (point.IsInfinity)
            {
                throw new MrtdEncodingException("The chip sent the point at infinity.");
            }

            return point;
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException)
        {
            throw new MrtdEncodingException(
                "The chip sent a public key that is not a valid point on the agreed curve.",
                exception);
        }
    }

    /// <summary>
    /// The authentication token: a CMAC over the other party's ephemeral public key,
    /// wrapped in the public-key template together with the protocol OID.
    /// </summary>
    /// <remarks>
    /// Binding the OID into the token is what stops a downgrade: a token computed for one
    /// PACE variant will not verify under another, so an attacker cannot negotiate the
    /// session down to a weaker cipher and replay the tokens.
    /// </remarks>
    private byte[] ComputeToken(byte[] macKey, byte[] otherPartyPublicKey)
    {
        byte[] oidBytes = new DerObjectIdentifier(_paceInfo.Algorithm.Oid).GetEncoded()[2..];

        byte[] template = BerTlv.Encode(
            TagPublicKeyTemplate,
            [
                .. BerTlv.Encode(TagOid, oidBytes),
                .. BerTlv.Encode(TagPoint, otherPartyPublicKey),
            ]);

        Org.BouncyCastle.Crypto.Macs.CMac mac =
            new(new Org.BouncyCastle.Crypto.Engines.AesEngine());
        mac.Init(new KeyParameter(macKey));
        mac.BlockUpdate(template, 0, template.Length);

        byte[] full = new byte[mac.GetMacSize()];
        mac.DoFinal(full, 0);

        return full[..8];
    }
}
