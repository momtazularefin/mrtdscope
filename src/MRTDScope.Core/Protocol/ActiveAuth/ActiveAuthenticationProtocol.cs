using System.Security.Cryptography;
using MRTDScope.Core.Apdu;
using MRTDScope.Core.Errors;
using MRTDScope.Core.Inspection;
using MRTDScope.Core.Lds;
using MRTDScope.Core.Tlv;
using MRTDScope.Core.Transport;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace MRTDScope.Core.Protocol.ActiveAuth;

/// <summary>The outcome of an Active Authentication attempt.</summary>
public sealed record ActiveAuthenticationResult(
    bool Succeeded,
    string? FailureReason,
    string Detail,
    string? Algorithm = null,
    string? Digest = null);

/// <summary>
/// Active Authentication: the chip proves it holds the private key matching the public
/// key the issuer signed into DG15 (ICAO Doc 9303 Part 11 §6.1).
/// </summary>
/// <remarks>
/// This is what distinguishes a genuine chip from a perfect copy of its data. Passive
/// Authentication proves the <em>contents</em> are authentic and unaltered; it says
/// nothing about the silicon, so a byte-for-byte clone onto a blank chip passes it
/// completely. Active Authentication closes that by requiring a signature over a nonce
/// the terminal chose a moment ago, which only the real private key can produce.
/// <para>
/// The RSA case uses ISO/IEC 9796-2 Digital Signature Scheme 1 <b>with message
/// recovery</b> — the chip's own nonce is embedded in and recovered from the signature,
/// not sent alongside it. The code this project harvests from verified a plain
/// <c>SHA1withRSA</c> signature instead, which would reject every genuine document it
/// ever met.
/// </para>
/// </remarks>
public sealed class ActiveAuthenticationProtocol
{
    private const byte ClaPlain = 0x00;
    private const byte InsInternalAuthenticate = 0x88;

    /// <summary>Doc 9303 Part 11 §6.1.2.1 fixes the terminal nonce at 8 bytes.</summary>
    public const int NonceLength = 8;

    private readonly AsymmetricKeyParameter _publicKey;
    private readonly RandomNumberGenerator _random;

    public ActiveAuthenticationProtocol(
        AsymmetricKeyParameter publicKey,
        RandomNumberGenerator? random = null)
    {
        ArgumentNullException.ThrowIfNull(publicKey);

        _publicKey = publicKey;
        _random = random ?? RandomNumberGenerator.Create();
    }

    /// <summary>
    /// Parses the Active Authentication public key from DG15.
    /// </summary>
    public static AsymmetricKeyParameter ParseDg15(ReadOnlySpan<byte> fileContent)
    {
        IReadOnlyList<BerTlv> outer = BerTlv.Parse(fileContent);
        BerTlv root = BerTlv.Find(outer, DataGroup.Dg15.Tag)
            ?? throw new MrtdEncodingException(
                $"DG15 must be wrapped in tag 0x{DataGroup.Dg15.Tag:X2}.");

        try
        {
            return PublicKeyFactory.CreateKey(
                SubjectPublicKeyInfo.GetInstance(
                    Asn1Object.FromByteArray(root.Value.ToArray())));
        }
        catch (Exception exception) when (exception is IOException or ArgumentException or SecurityUtilityException)
        {
            throw new MrtdEncodingException(
                "DG15 does not carry a well-formed SubjectPublicKeyInfo.", exception);
        }
    }

    /// <summary>
    /// Challenges the chip and verifies its response.
    /// </summary>
    /// <param name="transport">
    /// The established secure channel. Doc 9303 requires Active Authentication to run
    /// inside secure messaging once it has been established.
    /// </param>
    public ActiveAuthenticationResult Authenticate(ICardTransport transport)
    {
        ArgumentNullException.ThrowIfNull(transport);

        byte[] challenge = new byte[NonceLength];
        _random.GetBytes(challenge);

        return AuthenticateWith(transport, challenge);
    }

    /// <summary>
    /// Challenges the chip with a caller-supplied nonce, so a replayed response can be
    /// exercised deliberately.
    /// </summary>
    public ActiveAuthenticationResult AuthenticateWith(ICardTransport transport, byte[] challenge)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(challenge);

        if (challenge.Length != NonceLength)
        {
            throw new ArgumentException(
                $"The Active Authentication nonce is {NonceLength} bytes.", nameof(challenge));
        }

        ResponseApdu response = transport.Transmit(new CommandApdu(
            ClaPlain,
            InsInternalAuthenticate,
            p1: 0x00,
            p2: 0x00,
            challenge,
            expectedLength: CommandApdu.MaxShortLength));

        if (!response.IsSuccess)
        {
            return new ActiveAuthenticationResult(
                false,
                ReasonCodes.AccessDenied,
                $"INTERNAL AUTHENTICATE returned {response.StatusWord}.");
        }

        byte[] signature = response.Data.ToArray();

        return _publicKey switch
        {
            RsaKeyParameters rsa => VerifyRsa(rsa, signature, challenge),
            ECPublicKeyParameters ec => VerifyEcdsa(ec, signature, challenge),
            _ => new ActiveAuthenticationResult(
                false,
                ReasonCodes.NotImplemented,
                $"DG15 carries a {_publicKey.GetType().Name} key, which this build cannot verify."),
        };
    }

    /// <summary>
    /// Verifies an ISO/IEC 9796-2 Digital Signature Scheme 1 signature with message
    /// recovery (Doc 9303 Part 11 §6.1.2.2).
    /// </summary>
    /// <remarks>
    /// The signed message is <c>M1 || M2</c>, where M1 is a nonce the chip generated and
    /// embedded recoverably in the signature, and M2 is the terminal's challenge, which
    /// is never transmitted inside it. Verification therefore recovers M1, appends the
    /// challenge, and checks the hash — which is exactly what binds the response to
    /// <em>this</em> session.
    /// <para>
    /// The digest is determined by trying each permitted option rather than by reading
    /// the trailer's hash-function identifier. That is deliberate: the identifier table
    /// lives in ISO/IEC 9796-2 Annex C, which is not reliably legible in the conversion
    /// available here, and guessing a byte value would be worse than an honest search.
    /// Trying candidates weakens nothing — a signature still verifies under exactly one —
    /// and the digest that succeeded is recorded as evidence.
    /// </para>
    /// </remarks>
    private static ActiveAuthenticationResult VerifyRsa(
        RsaKeyParameters publicKey,
        byte[] signature,
        byte[] challenge)
    {
        // Trailer option 1 is mandated with SHA-1, option 2 otherwise.
        (Func<IDigest> Digest, bool ImplicitTrailer, string Name)[] candidates =
        [
            (() => new Sha1Digest(), true, "SHA-1"),
            (() => new Sha256Digest(), false, "SHA-256"),
            (() => new Sha512Digest(), false, "SHA-512"),
            (() => new Sha384Digest(), false, "SHA-384"),
            (() => new Sha224Digest(), false, "SHA-224"),
        ];

        foreach ((Func<IDigest> digest, bool implicitTrailer, string name) in candidates)
        {
            try
            {
                Iso9796d2Signer signer = new(new RsaEngine(), digest(), implicitTrailer);
                signer.Init(forSigning: false, publicKey);

                // Recover M1 from the signature, then append the challenge as M2.
                signer.UpdateWithRecoveredMessage(signature);
                signer.BlockUpdate(challenge, 0, challenge.Length);

                if (signer.VerifySignature(signature))
                {
                    int recovered = signer.GetRecoveredMessage().Length;

                    return new ActiveAuthenticationResult(
                        true,
                        null,
                        "The chip produced a valid ISO/IEC 9796-2 signature over the " +
                        "terminal's challenge, so it holds the private key matching DG15.",
                        $"RSA-{publicKey.Modulus.BitLength}",
                        $"{name} (trailer option {(implicitTrailer ? 1 : 2)}, " +
                        $"{recovered}-byte recovered nonce)");
                }
            }
            catch (Exception exception) when (exception is InvalidCipherTextException
                or ArgumentException or InvalidOperationException or DataLengthException)
            {
                // Wrong digest for this signature; try the next candidate.
            }
        }

        return new ActiveAuthenticationResult(
            false,
            ReasonCodes.SignatureInvalid,
            "The chip's Active Authentication signature did not verify under the DG15 " +
            "public key with any permitted hash. Either the response does not bind to " +
            "this session's challenge, or the chip does not hold the matching private key.");
    }

    /// <summary>
    /// Verifies a plain ECDSA signature over the challenge
    /// (Doc 9303 Part 11 §6.1.2.3, TR-03111 plain format).
    /// </summary>
    /// <remarks>
    /// The plain format is <c>r || s</c>, each padded to the curve's field size — not the
    /// DER SEQUENCE that most libraries produce by default. There is no message recovery
    /// here: the challenge itself is the signed message.
    /// </remarks>
    private static ActiveAuthenticationResult VerifyEcdsa(
        ECPublicKeyParameters publicKey,
        byte[] signature,
        byte[] challenge)
    {
        if (signature.Length % 2 != 0)
        {
            return new ActiveAuthenticationResult(
                false,
                ReasonCodes.MalformedData,
                $"A plain ECDSA signature is an even number of bytes; got {signature.Length}.");
        }

        int half = signature.Length / 2;
        BigInteger r = new(1, signature, 0, half);
        BigInteger s = new(1, signature, half, half);

        // The hash must be no longer than the key, so the digest is chosen to match.
        int fieldBits = publicKey.Parameters.Curve.FieldSize;

        (IDigest Digest, string Name)[] candidates = fieldBits switch
        {
            <= 224 => [(new Sha224Digest(), "SHA-224"), (new Sha1Digest(), "SHA-1")],
            <= 256 => [(new Sha256Digest(), "SHA-256"), (new Sha224Digest(), "SHA-224")],
            <= 384 => [(new Sha384Digest(), "SHA-384"), (new Sha256Digest(), "SHA-256")],
            _ => [(new Sha512Digest(), "SHA-512"), (new Sha384Digest(), "SHA-384")],
        };

        foreach ((IDigest digest, string name) in candidates)
        {
            byte[] hash = new byte[digest.GetDigestSize()];
            digest.BlockUpdate(challenge, 0, challenge.Length);
            digest.DoFinal(hash, 0);

            ECDsaSigner verifier = new();
            verifier.Init(forSigning: false, publicKey);

            if (verifier.VerifySignature(hash, r, s))
            {
                return new ActiveAuthenticationResult(
                    true,
                    null,
                    "The chip produced a valid ECDSA signature over the terminal's " +
                    "challenge, so it holds the private key matching DG15.",
                    $"ECDSA-{fieldBits}",
                    name);
            }
        }

        return new ActiveAuthenticationResult(
            false,
            ReasonCodes.SignatureInvalid,
            "The chip's ECDSA Active Authentication signature did not verify under the " +
            "DG15 public key.");
    }
}
