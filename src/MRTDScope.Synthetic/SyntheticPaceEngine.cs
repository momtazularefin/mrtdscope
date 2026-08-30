using System.Security.Cryptography;
using MRTDScope.Core.Apdu;
using MRTDScope.Core.Crypto;
using MRTDScope.Core.Protocol.Pace;
using MRTDScope.Core.Protocol.SecureMessaging;
using MRTDScope.Core.Tlv;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;

namespace MRTDScope.Synthetic;

/// <summary>
/// The card side of PACE with Generic Mapping, so the terminal implementation can be
/// exercised end to end with no hardware (NFR2).
/// </summary>
/// <remarks>
/// This is the mirror of <see cref="PaceProtocol"/>, written independently rather than by
/// sharing its steps: the chip generates its own nonce and ephemeral keys, performs its
/// own mapping and agreement, and computes both authentication tokens from its own view
/// of the exchange. A terminal that mapped the generator differently, derived keys with
/// the wrong counter, or MAC'd the wrong party's public key fails here rather than
/// appearing to work.
/// </remarks>
internal sealed class SyntheticPaceEngine
{
    private const int TagDynamicAuthenticationData = 0x7C;
    private const int TagEncryptedNonce = 0x80;
    private const int TagMappingDataTerminal = 0x81;
    private const int TagMappingDataChip = 0x82;
    private const int TagKeyAgreementTerminal = 0x83;
    private const int TagKeyAgreementChip = 0x84;
    private const int TagTokenTerminal = 0x85;
    private const int TagTokenChip = 0x86;

    private readonly string _protocolOid;
    private readonly PaceAlgorithm _algorithm;
    private readonly ECDomainParameters _domain;
    private readonly byte[] _password;
    private readonly SecureRandom _random = new();

    private byte[]? _nonce;
    private ECDomainParameters? _mappedDomain;
    private ECPoint? _chipAgreementPublic;
    private ECPoint? _terminalAgreementPublic;
    private byte[]? _encryptionKey;
    private byte[]? _macKey;

    public SyntheticPaceEngine(string protocolOid, int parameterId, byte[] password)
    {
        _protocolOid = protocolOid;
        _algorithm = PaceAlgorithm.FromOid(protocolOid)
            ?? throw new ArgumentException($"'{protocolOid}' is not a PACE OID.", nameof(protocolOid));

        string curveName = PaceDomainParameters.CurveFor(parameterId)
            ?? throw new ArgumentException(
                $"Parameter {parameterId} names no curve.", nameof(parameterId));

        X9ECParameters curve = ECNamedCurveTable.GetByName(curveName)!;
        _domain = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);
        _password = password;
    }

    /// <summary>Whether mutual authentication completed and a channel exists.</summary>
    public bool ChannelEstablished { get; private set; }

    // The chip's own view of the AES channel: its own keys and its own counter, starting
    // at zero exactly as the terminal's does.
    private SendSequenceCounter? _smCounter;

    private const int BlockSize = 16;
    private const int MacLength = 8;

    /// <summary>Unwraps a protected command: verifies its checksum, decrypts its data.</summary>
    public CommandApdu UnwrapCommand(CommandApdu command)
    {
        _smCounter!.Increment();

        IReadOnlyList<BerTlv> objects = BerTlv.Parse(command.Data.Span);

        BerTlv? do87 = BerTlv.Find(objects, 0x87);
        BerTlv? do97 = BerTlv.Find(objects, 0x97);
        BerTlv do8e = BerTlv.Find(objects, 0x8E)
            ?? throw new MRTDScope.Core.Errors.CardTransportException(
                "The terminal sent no DO'8E' checksum.");

        byte[] header = Iso7816Padding.Add(
            [command.Cla, command.Ins, command.P1, command.P2], BlockSize);

        ReadOnlyMemory<byte> encrypted = do87?.RawBytes ?? default;
        ReadOnlyMemory<byte> expectedLength = do97?.RawBytes ?? default;

        byte[] macInput =
        [
            .. _smCounter.Value, .. header, .. encrypted.Span, .. expectedLength.Span,
        ];

        if (!CryptographicOperations.FixedTimeEquals(
            Mac(Iso7816Padding.Add(macInput, BlockSize)), do8e.Value.Span))
        {
            throw new MRTDScope.Core.Errors.CardTransportException(
                "The terminal's protected command failed its checksum.");
        }

        byte[] data = [];

        if (do87 is not null)
        {
            byte[] plaintext = Crypt(do87.Value.Span[1..], encrypt: false);
            data = Iso7816Padding.Remove(plaintext) ?? [];
        }

        int? le = null;

        if (do97 is not null)
        {
            le = do97.Value.Length == 1
                ? (do97.Value.Span[0] == 0 ? 256 : do97.Value.Span[0])
                : (do97.Value.Span[0] << 8) | do97.Value.Span[1];
        }

        return new CommandApdu(
            (byte)(command.Cla & 0xF3),
            command.Ins,
            command.P1,
            command.P2,
            new ReadOnlyMemory<byte>(data),
            le);
    }

    /// <summary>Wraps a response: encrypts its data and appends a checksum.</summary>
    public ResponseApdu WrapResponse(ResponseApdu response)
    {
        _smCounter!.Increment();

        byte[] do87 = [];

        if (response.Data.Length > 0)
        {
            byte[] ciphertext = Crypt(
                Iso7816Padding.Add(response.Data.Span, BlockSize), encrypt: true);
            do87 = BerTlv.Encode(0x87, [0x01, .. ciphertext]);
        }

        byte[] do99 = BerTlv.Encode(0x99, [response.StatusWord.Sw1, response.StatusWord.Sw2]);
        byte[] macInput = [.. _smCounter.Value, .. do87, .. do99];
        byte[] do8e = BerTlv.Encode(0x8E, Mac(Iso7816Padding.Add(macInput, BlockSize)));

        byte[] payload = [.. do87, .. do99, .. do8e];

        return new ResponseApdu(payload, new StatusWord(StatusWord.Success));
    }

    /// <summary>The IV is the current counter encrypted under the session key in ECB.</summary>
    private byte[] Crypt(ReadOnlySpan<byte> input, bool encrypt)
    {
        using Aes aes = Aes.Create();
        aes.Key = _encryptionKey!;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;

        byte[] iv = aes.EncryptEcb(_smCounter!.Value, PaddingMode.None);

        aes.Mode = CipherMode.CBC;

        return encrypt
            ? aes.EncryptCbc(input.ToArray(), iv, PaddingMode.None)
            : aes.DecryptCbc(input.ToArray(), iv, PaddingMode.None);
    }

    private byte[] Mac(ReadOnlySpan<byte> padded)
    {
        CMac mac = new(new AesEngine());
        mac.Init(new KeyParameter(_macKey!));

        byte[] input = padded.ToArray();
        mac.BlockUpdate(input, 0, input.Length);

        byte[] full = new byte[mac.GetMacSize()];
        mac.DoFinal(full, 0);

        return full[..MacLength];
    }

    /// <summary>Handles MSE:Set AT, accepting only the variant this document advertises.</summary>
    /// <remarks>
    /// Deliberately strict about the conditional domain-parameter reference. Doc 9303
    /// Part 11 §4.4.4.1 makes tag 0x84 required only when a chip offers more than one set
    /// of domain parameters; this chip offers exactly one, so a terminal that sends the
    /// reference anyway is asking it to resolve something it has no table for. Real chips
    /// answer 6A88, and a permissive model here would let that terminal bug reach hardware
    /// undetected — which is exactly what happened before this check existed.
    /// </remarks>
    public ResponseApdu ManageSecurityEnvironment(CommandApdu command)
    {
        IReadOnlyList<BerTlv> objects = BerTlv.Parse(command.Data.Span);
        BerTlv? oid = BerTlv.Find(objects, 0x80);

        if (oid is null)
        {
            return Status(0x6A80);
        }

        if (BerTlv.Find(objects, 0x84) is not null)
        {
            // 6A88: referenced data not found.
            return Status(0x6A88);
        }

        byte[] expected = new DerObjectIdentifier(_protocolOid).GetEncoded()[2..];

        return oid.Value.Span.SequenceEqual(expected)
            ? Status(StatusWord.Success)
            : Status(0x6A80);
    }

    /// <summary>Handles each GENERAL AUTHENTICATE step, dispatching on the inner tag.</summary>
    public ResponseApdu GeneralAuthenticate(CommandApdu command)
    {
        IReadOnlyList<BerTlv> outer = BerTlv.Parse(command.Data.Span);
        BerTlv? container = BerTlv.Find(outer, TagDynamicAuthenticationData);

        if (container is null)
        {
            return Status(0x6A80);
        }

        IReadOnlyList<BerTlv> inner = container.Value.Length == 0 ? [] : container.Children();

        if (inner.Count == 0)
        {
            return EncryptedNonce();
        }

        BerTlv element = inner[0];

        return element.Tag switch
        {
            TagMappingDataTerminal => MapNonce(element.Value.Span),
            TagKeyAgreementTerminal => AgreeKey(element.Value.Span),
            TagTokenTerminal => MutualAuthenticate(element.Value.Span),
            _ => Status(0x6A80),
        };
    }

    private ResponseApdu EncryptedNonce()
    {
        // The nonce is a full cipher block of randomness, encrypted under a key derived
        // from the password. A terminal with the wrong password decrypts it to noise and
        // discovers that only when its token is rejected.
        _nonce = RandomNumberGenerator.GetBytes(16);

        byte[] passwordKey = PaceKeyDerivation.DerivePasswordKey(_password, _algorithm.Cipher);

        using Aes aes = Aes.Create();
        aes.Key = passwordKey;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.None;

        byte[] encrypted = aes.EncryptCbc(_nonce, new byte[16], PaddingMode.None);

        return Respond(TagEncryptedNonce, encrypted);
    }

    private ResponseApdu MapNonce(ReadOnlySpan<byte> terminalPublicKey)
    {
        if (_nonce is null)
        {
            return Status(StatusWord.ConditionsNotSatisfied);
        }

        ECPoint terminalPoint;
        try
        {
            terminalPoint = _domain.Curve.DecodePoint(terminalPublicKey.ToArray()).Normalize();
        }
        catch (ArgumentException)
        {
            return Status(0x6A80);
        }

        BigInteger chipPrivate = NewScalar(_domain.N);
        ECPoint chipPublic = _domain.G.Multiply(chipPrivate).Normalize();

        ECPoint shared = terminalPoint.Multiply(chipPrivate).Normalize();
        ECPoint mappedGenerator = _domain.G
            .Multiply(new BigInteger(1, _nonce))
            .Add(shared)
            .Normalize();

        _mappedDomain = new ECDomainParameters(
            _domain.Curve, mappedGenerator, _domain.N, _domain.H);

        return Respond(TagMappingDataChip, chipPublic.GetEncoded(compressed: false));
    }

    private ResponseApdu AgreeKey(ReadOnlySpan<byte> terminalPublicKey)
    {
        if (_mappedDomain is null)
        {
            return Status(StatusWord.ConditionsNotSatisfied);
        }

        ECPoint terminalPoint;
        try
        {
            terminalPoint = _mappedDomain.Curve.DecodePoint(terminalPublicKey.ToArray()).Normalize();
        }
        catch (ArgumentException)
        {
            return Status(0x6A80);
        }

        _terminalAgreementPublic = terminalPoint;

        BigInteger chipPrivate = NewScalar(_mappedDomain.N);
        _chipAgreementPublic = _mappedDomain.G.Multiply(chipPrivate).Normalize();

        ECPoint sharedPoint = terminalPoint.Multiply(chipPrivate).Normalize();

        byte[] sharedSecret = BigIntegers.AsUnsignedByteArray(
            (_domain.Curve.FieldSize + 7) / 8,
            sharedPoint.AffineXCoord.ToBigInteger());

        _encryptionKey = PaceKeyDerivation.DeriveEncryptionKey(sharedSecret, _algorithm.Cipher);
        _macKey = PaceKeyDerivation.DeriveMacKey(sharedSecret, _algorithm.Cipher);

        return Respond(
            TagKeyAgreementChip, _chipAgreementPublic.GetEncoded(compressed: false));
    }

    private ResponseApdu MutualAuthenticate(ReadOnlySpan<byte> terminalToken)
    {
        if (_macKey is null || _chipAgreementPublic is null || _terminalAgreementPublic is null)
        {
            return Status(StatusWord.ConditionsNotSatisfied);
        }

        // The terminal MACs the chip's ephemeral key; the chip MACs the terminal's. A
        // wrong password produces a different mapped generator, hence different keys,
        // hence a token that does not verify — which is where PACE actually rejects it.
        byte[] expected = Token(_chipAgreementPublic.GetEncoded(compressed: false));

        if (!CryptographicOperations.FixedTimeEquals(expected, terminalToken))
        {
            return Status(0x6300);
        }

        byte[] chipToken = Token(_terminalAgreementPublic.GetEncoded(compressed: false));

        _smCounter = new SendSequenceCounter(new byte[16]);
        ChannelEstablished = true;

        return Respond(TagTokenChip, chipToken);
    }

    private byte[] Token(byte[] publicKey)
    {
        byte[] oidBytes = new DerObjectIdentifier(_protocolOid).GetEncoded()[2..];

        byte[] template = BerTlv.Encode(
            0x7F49,
            [.. BerTlv.Encode(0x06, oidBytes), .. BerTlv.Encode(0x86, publicKey)]);

        CMac mac = new(new AesEngine());
        mac.Init(new KeyParameter(_macKey!));
        mac.BlockUpdate(template, 0, template.Length);

        byte[] full = new byte[mac.GetMacSize()];
        mac.DoFinal(full, 0);

        return full[..8];
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

    private static ResponseApdu Respond(int tag, byte[] value)
    {
        byte[] payload = BerTlv.Encode(
            TagDynamicAuthenticationData, BerTlv.Encode(tag, value));

        return new ResponseApdu(payload, new StatusWord(StatusWord.Success));
    }

    private static ResponseApdu Status(ushort statusWord) =>
        new(default, new StatusWord(statusWord));
}
