using System.Security.Cryptography;
using MRTDScope.Core.Apdu;
using MRTDScope.Core.Crypto;
using MRTDScope.Core.Errors;
using MRTDScope.Core.Lds;
using MRTDScope.Core.Protocol;
using MRTDScope.Core.Protocol.SecureMessaging;
using MRTDScope.Core.Tlv;
using MRTDScope.Core.Transport;

namespace MRTDScope.Synthetic;

/// <summary>
/// An in-process eMRTD that speaks APDUs, implementing the card side of BAC and 3DES
/// secure messaging (FR9).
/// </summary>
/// <remarks>
/// This sits at the <see cref="ICardTransport"/> boundary, which is the whole point: the
/// production BAC, secure-messaging, LDS-reading, and Passive Authentication code runs
/// against it completely unmodified — the same code, byte for byte, that talks to a
/// physical passport. A test double placed higher up would only prove the double works.
/// <para>
/// The chip implements the <em>card</em> half of each protocol independently: it holds
/// its own session keys and its own send sequence counter, verifies the terminal's
/// authentication token, unwraps protected commands and wraps its own responses. It does
/// not borrow the reader's channel object, so a desynchronised counter or a mismatched
/// key genuinely fails here rather than being papered over.
/// </para>
/// <para>
/// The two halves do share low-level primitives — DES, the retail MAC, key derivation —
/// where a common bug could in principle hide. That risk is closed by M1, which pinned
/// those primitives against the ICAO Doc 9303 Appendix D published vectors rather than
/// against this chip.
/// </para>
/// </remarks>
public sealed class SyntheticChip : ICardTransport
{
    private const byte InsSelect = 0xA4;
    private const byte InsReadBinary = 0xB0;
    private const byte InsGetChallenge = 0x84;
    private const byte InsExternalAuthenticate = 0x82;
    private const byte InsManageSecurityEnvironment = 0x22;
    private const byte InsGeneralAuthenticate = 0x86;
    private const byte InsInternalAuthenticate = 0x88;

    private readonly SyntheticDocument _document;
    private readonly DocumentFault _fault;
    private readonly Dictionary<ushort, byte[]> _files = [];

    private byte[]? _pendingChallenge;
    private ushort _selectedFile;

    // Active Authentication replay state: the challenge and signature from the "earlier
    // session" the chip keeps answering with.
    private byte[]? _replayedChallenge;
    private byte[]? _replayedSignature;

    // PACE establishes its security context in the Master File, so the chip has to
    // know whether the eMRTD application is currently selected.
    private bool _applicationSelected;

    // Card-side session state, established by mutual authentication.
    private byte[] _sessionEncryptionKey = [];
    private byte[] _sessionMacKey = [];
    private SendSequenceCounter? _counter;
    private int _protectedResponses;

    // PACE runs its own card-side engine; on success it hands back an AES channel that
    // replaces the 3DES one BAC would have built.
    private readonly SyntheticPaceEngine? _pace;
    private bool _paceChannelOpen;

    // Chip Authentication state. The channel it establishes takes over from whatever
    // access control built, but only after the response that completes it has been sent.
    private string? _pendingChipAuthOid;
    private SyntheticAesMessaging? _chipAuthChannel;
    private SyntheticAesMessaging? _chipAuthPending;

    public SyntheticChip(SyntheticDocument document, DocumentFault fault = DocumentFault.None)
    {
        ArgumentNullException.ThrowIfNull(document);

        _document = document;
        _fault = fault;

        _files[DataGroup.Com.FileId] = document.EfCom;
        _files[DataGroup.Sod.FileId] = document.EfSod;

        if (document.EfCardAccess is { } cardAccess)
        {
            _files[DataGroup.CardAccess.FileId] = cardAccess;
        }

        foreach ((int number, byte[] content) in document.DataGroups)
        {
            DataGroup? group = DataGroup.FromNumber(number);

            if (group is not null)
            {
                _files[group.FileId] = content;
            }
        }

        if (document.PaceProtocolOid is { } oid && document.PaceParameterId is { } parameterId)
        {
            _pace = new SyntheticPaceEngine(
                oid,
                parameterId,
                MRTDScope.Core.Crypto.PaceKeyDerivation.MrzPassword(document.MrzKey));
        }
    }

    /// <summary>The document this chip serves.</summary>
    public SyntheticDocument Document => _document;

    public string Name => "synthetic-emrtd";

    public bool IsConnected { get; private set; }

    /// <summary>A plausible contactless ATS. Not derived from any real product.</summary>
    public ReadOnlyMemory<byte> AnswerToReset { get; } =
        new byte[] { 0x3B, 0x88, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00, 0x77, 0x81, 0x81, 0x00, 0x6E };

    /// <summary>Whether a secure channel is currently established.</summary>
    public bool HasSecureChannel => _counter is not null || _paceChannelOpen;

    /// <summary>Whether the established channel came from PACE rather than BAC.</summary>
    public bool UsedPace => _paceChannelOpen;

    /// <summary>How many APDUs the chip has processed since connection.</summary>
    public int CommandsProcessed { get; private set; }

    public void Connect() => IsConnected = true;

    public void Disconnect()
    {
        IsConnected = false;
        _counter = null;
        _pendingChallenge = null;
        _protectedResponses = 0;
        CryptographicOperations.ZeroMemory(_sessionEncryptionKey);
        CryptographicOperations.ZeroMemory(_sessionMacKey);
    }

    public void Dispose() => Disconnect();

    public ResponseApdu Transmit(CommandApdu command)
    {
        ArgumentNullException.ThrowIfNull(command);

        if (!IsConnected)
        {
            throw new CardTransportException("No card is connected to the synthetic reader.");
        }

        CommandsProcessed++;

        if (!command.IsSecureMessaging)
        {
            return Process(command);
        }

        if (_chipAuthChannel is not null)
        {
            CommandApdu caPlain = _chipAuthChannel.UnwrapCommand(command);
            ResponseApdu caResponse = Process(caPlain);
            return _chipAuthChannel.WrapResponse(caResponse);
        }

        if (_paceChannelOpen)
        {
            CommandApdu pacePlain = _pace!.UnwrapCommand(command);
            ResponseApdu paceResponse = Process(pacePlain);
            ResponseApdu wrapped = _pace.WrapResponse(paceResponse);

            // Doc 9303 restarts secure messaging *after* the response that completed
            // Chip Authentication, so the swap happens here rather than inside the
            // handler.
            ActivatePendingChipAuthChannel();
            return wrapped;
        }

        if (_counter is null)
        {
            return Process(command);
        }

        CommandApdu plain = UnwrapCommand(command);
        ResponseApdu response = Process(plain);
        ResponseApdu wrappedResponse = WrapResponse(response);

        ActivatePendingChipAuthChannel();
        return wrappedResponse;
    }

    private ResponseApdu Process(CommandApdu command) => command.Ins switch
    {
        InsSelect => Select(command),
        InsReadBinary => ReadBinary(command),
        InsGetChallenge => GetChallenge(command),
        InsExternalAuthenticate => ExternalAuthenticate(command),
        InsManageSecurityEnvironment => command.P1 == 0x41
            ? ChipAuthManageSecurityEnvironment(command)
            : ManageSecurityEnvironment(command),
        InsGeneralAuthenticate => _pendingChipAuthOid is not null
            ? ChipAuthGeneralAuthenticate(command)
            : GeneralAuthenticate(command),
        InsInternalAuthenticate => InternalAuthenticate(command),
        _ => Status(0x6D00),
    };

    /// <summary>
    /// The card side of Active Authentication: an ISO/IEC 9796-2 Digital Signature
    /// Scheme 1 signature with message recovery.
    /// </summary>
    /// <remarks>
    /// The chip generates its own nonce M1, signs <c>M1 || RND.IFD</c>, and returns a
    /// signature from which the terminal recovers M1. Producing a genuine one requires the
    /// private key, which is the point.
    /// </remarks>
    private ResponseApdu InternalAuthenticate(CommandApdu command)
    {
        if (_document.ActiveAuthPrivateKey is not Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters key)
        {
            return Status(0x6D00);
        }

        if (command.Data.Length != 8)
        {
            return Status(0x6700);
        }

        // The replay fault answers with a signature produced for an earlier challenge.
        // It verifies under DG15 perfectly; it simply does not bind to this session.
        byte[] challenge = _fault == DocumentFault.ReplayedActiveAuthentication
            ? (_replayedChallenge ??= RandomNumberGenerator.GetBytes(8))
            : command.Data.ToArray();

        if (_fault == DocumentFault.ReplayedActiveAuthentication && _replayedSignature is not null)
        {
            return new ResponseApdu(_replayedSignature, new StatusWord(StatusWord.Success));
        }

        Org.BouncyCastle.Crypto.Signers.Iso9796d2Signer signer = new(
            new Org.BouncyCastle.Crypto.Engines.RsaEngine(),
            new Org.BouncyCastle.Crypto.Digests.Sha1Digest(),
            true);

        signer.Init(forSigning: true, key);

        // M1 must fill the signature's recoverable capacity exactly. If it is short, the
        // implementation recovers fewer bytes than the chip intended and the verifier's
        // M1/M2 split no longer matches the signer's, so the hash disagrees and a
        // perfectly genuine signature is rejected.
        //
        // Capacity is the modulus in whole bytes, less the digest, less one trailer byte,
        // less one header byte.
        int digestSize = 20;
        int capacity = ((key.Modulus.BitLength + 7) / 8) - digestSize - 2;
        byte[] chipNonce = RandomNumberGenerator.GetBytes(Math.Max(capacity, 1));

        signer.BlockUpdate(chipNonce, 0, chipNonce.Length);
        signer.BlockUpdate(challenge, 0, challenge.Length);

        byte[] signature = signer.GenerateSignature();

        if (_fault == DocumentFault.ReplayedActiveAuthentication)
        {
            _replayedSignature = signature;
        }

        return new ResponseApdu(signature, new StatusWord(StatusWord.Success));
    }

    /// <summary>
    /// PACE may only be started from the Master File.
    /// </summary>
    /// <remarks>
    /// Doc 9303 Part 11 §4.4 places the PACE security context in the Master File, and the
    /// numbered inspection flow runs PACE <em>before</em> selecting the eMRTD application.
    /// A chip asked to start PACE from inside the application answers 6985, "conditions of
    /// use not satisfied". Modelling that is what turns a terminal ordering bug into a CI
    /// failure instead of a hardware-only surprise.
    /// </remarks>
    private ResponseApdu ManageSecurityEnvironment(CommandApdu command)
    {
        if (_pace is null)
        {
            return Status(0x6D00);
        }

        return _applicationSelected
            ? Status(StatusWord.ConditionsNotSatisfied)
            : _pace.ManageSecurityEnvironment(command);
    }

    /// <summary>
    /// The card side of Chip Authentication.
    /// </summary>
    /// <remarks>
    /// Unlike PACE, this runs inside the eMRTD application and inside the channel access
    /// control already established, so its commands arrive protected and its response
    /// leaves protected under the <em>old</em> keys. The new channel only takes effect
    /// from the next command, which is what Doc 9303 means by restarting secure messaging.
    /// </remarks>
    private ResponseApdu ChipAuthManageSecurityEnvironment(CommandApdu command)
    {
        if (_document.ChipAuthPrivateKey is null)
        {
            return Status(0x6D00);
        }

        IReadOnlyList<BerTlv> objects = BerTlv.Parse(command.Data.Span);
        BerTlv? oid = BerTlv.Find(objects, 0x80);

        if (oid is null)
        {
            return Status(0x6A80);
        }

        _pendingChipAuthOid = new Org.BouncyCastle.Asn1.DerObjectIdentifier(
            "0.4.0.127.0.7.2.2.3.2.2").GetEncoded()[2..].SequenceEqual(oid.Value.ToArray())
                ? "0.4.0.127.0.7.2.2.3.2.2"
                : null;

        return _pendingChipAuthOid is null ? Status(0x6A80) : Status(StatusWord.Success);
    }

    private ResponseApdu ChipAuthGeneralAuthenticate(CommandApdu command)
    {
        if (_pendingChipAuthOid is null
            || _document.ChipAuthPrivateKey is not Org.BouncyCastle.Crypto.Parameters.ECPrivateKeyParameters key)
        {
            return Status(StatusWord.ConditionsNotSatisfied);
        }

        IReadOnlyList<BerTlv> outer = BerTlv.Parse(command.Data.Span);
        BerTlv? container = BerTlv.Find(outer, 0x7C);
        BerTlv? ephemeral = container is null ? null : BerTlv.Find(container.Children(), 0x80);

        if (ephemeral is null)
        {
            return Status(0x6A80);
        }

        Org.BouncyCastle.Math.EC.ECPoint terminalPoint;
        try
        {
            terminalPoint = key.Parameters.Curve
                .DecodePoint(ephemeral.Value.ToArray())
                .Normalize();
        }
        catch (ArgumentException)
        {
            return Status(0x6A80);
        }

        Org.BouncyCastle.Math.EC.ECPoint shared = terminalPoint.Multiply(key.D).Normalize();

        byte[] secret = Org.BouncyCastle.Utilities.BigIntegers.AsUnsignedByteArray(
            (key.Parameters.Curve.FieldSize + 7) / 8,
            shared.AffineXCoord.ToBigInteger());

        _chipAuthPending = new SyntheticAesMessaging(
            MRTDScope.Core.Crypto.PaceKeyDerivation.DeriveEncryptionKey(
                secret, MRTDScope.Core.Protocol.Pace.PaceCipher.Aes128),
            MRTDScope.Core.Crypto.PaceKeyDerivation.DeriveMacKey(
                secret, MRTDScope.Core.Protocol.Pace.PaceCipher.Aes128));

        return new ResponseApdu(
            BerTlv.Encode(0x7C, []), new StatusWord(StatusWord.Success));
    }

    private ResponseApdu GeneralAuthenticate(CommandApdu command)
    {
        if (_pace is null)
        {
            return Status(0x6D00);
        }

        if (_applicationSelected && !_paceChannelOpen)
        {
            return Status(StatusWord.ConditionsNotSatisfied);
        }

        ResponseApdu response = _pace.GeneralAuthenticate(command);

        // Once PACE completes, its AES channel takes over from any BAC state.
        if (_pace.ChannelEstablished && !_paceChannelOpen)
        {
            _paceChannelOpen = true;
            _counter = null;
        }

        return response;
    }

    private ResponseApdu Select(CommandApdu command)
    {
        // P1 = 0x00 selects the Master File, which is where EF.CardAccess lives.
        if (command.P1 == 0x00)
        {
            _applicationSelected = false;
            return Status(StatusWord.Success);
        }

        // P1 = 0x04 selects by application identifier.
        if (command.P1 == 0x04)
        {
            if (!command.Data.Span.SequenceEqual(MrtdApplication.Lds1ApplicationId))
            {
                return Status(StatusWord.FileNotFound);
            }

            _applicationSelected = true;
            return Status(StatusWord.Success);
        }

        // P1 = 0x02 selects an elementary file under the current DF.
        if (command.P1 == 0x02 && command.Data.Length == 2)
        {
            ushort fileId = (ushort)((command.Data.Span[0] << 8) | command.Data.Span[1]);

            if (!_files.ContainsKey(fileId))
            {
                return Status(StatusWord.FileNotFound);
            }

            if (_counter is null && !_paceChannelOpen
                && fileId != DataGroup.CardAccess.FileId)
            {
                return Status(StatusWord.SecurityStatusNotSatisfied);
            }

            _selectedFile = fileId;
            return Status(StatusWord.Success);
        }

        return Status(0x6A86);
    }

    private ResponseApdu ReadBinary(CommandApdu command)
    {
        // EF.CardAccess is readable with no access control at all — that is the whole
        // point of it, since a terminal must discover which protocols a chip offers
        // before it can choose one. Every other file is behind the secure channel.
        if (_counter is null && !_paceChannelOpen
            && _selectedFile != DataGroup.CardAccess.FileId)
        {
            return Status(StatusWord.SecurityStatusNotSatisfied);
        }

        if (!_files.TryGetValue(_selectedFile, out byte[]? file))
        {
            return Status(0x6986);
        }

        int offset = (command.P1 << 8) | command.P2;

        if (offset > file.Length)
        {
            return Status(0x6B00);
        }

        int requested = command.ExpectedLength ?? 256;
        int available = Math.Min(requested, file.Length - offset);

        return new ResponseApdu(
            file.AsSpan(offset, available).ToArray(),
            new StatusWord(StatusWord.Success));
    }

    private ResponseApdu GetChallenge(CommandApdu command)
    {
        if (command.ExpectedLength != 8)
        {
            return Status(0x6700);
        }

        _pendingChallenge = RandomNumberGenerator.GetBytes(8);
        return new ResponseApdu(_pendingChallenge, new StatusWord(StatusWord.Success));
    }

    /// <summary>The card side of BAC mutual authentication.</summary>
    private ResponseApdu ExternalAuthenticate(CommandApdu command)
    {
        if (_pendingChallenge is null)
        {
            return Status(StatusWord.ConditionsNotSatisfied);
        }

        if (command.Data.Length != 40)
        {
            return Status(0x6700);
        }

        byte[] rndIc = _pendingChallenge;
        _pendingChallenge = null;

        BacKeyDerivation.KeyPair documentKeys = _document.MrzKey.DeriveDocumentKeys();

        byte[] eIfd = command.Data.Span[..32].ToArray();
        ReadOnlySpan<byte> mIfd = command.Data.Span[32..];

        // A wrong MRZ produces a token whose MAC does not verify. Real chips answer 6300.
        byte[] expectedMac = TripleDes.RetailMac(documentKeys.Mac, eIfd);

        if (!CryptographicOperations.FixedTimeEquals(expectedMac, mIfd))
        {
            return Status(0x6300);
        }

        byte[] s = TripleDes.DecryptCbc(documentKeys.Encryption, eIfd);

        // S = RND.IFD || RND.IC || K.IFD. The chip checks its own nonce came back,
        // which is what stops a replayed terminal token.
        if (!CryptographicOperations.FixedTimeEquals(s.AsSpan(8, 8), rndIc))
        {
            return Status(0x6300);
        }

        byte[] rndIfd = s[..8];
        byte[] kIfd = s[16..32];
        byte[] kIc = RandomNumberGenerator.GetBytes(16);

        // R = RND.IC || RND.IFD || K.IC
        byte[] r = [.. rndIc, .. rndIfd, .. kIc];

        byte[] eIc = TripleDes.EncryptCbc(documentKeys.Encryption, r);
        byte[] mIc = TripleDes.RetailMac(documentKeys.Mac, eIc);

        byte[] sessionSeed = new byte[16];
        for (int i = 0; i < sessionSeed.Length; i++)
        {
            sessionSeed[i] = (byte)(kIfd[i] ^ kIc[i]);
        }

        BacKeyDerivation.KeyPair sessionKeys = BacKeyDerivation.Derive(sessionSeed);

        _sessionEncryptionKey = sessionKeys.Encryption;
        _sessionMacKey = sessionKeys.Mac;
        _counter = new SendSequenceCounter([.. rndIc.AsSpan(4, 4), .. rndIfd.AsSpan(4, 4)]);
        _protectedResponses = 0;

        byte[] token = [.. eIc, .. mIc];

        return new ResponseApdu(token, new StatusWord(StatusWord.Success));
    }

    /// <summary>Unwraps a protected command: verifies its checksum, decrypts its data.</summary>
    private CommandApdu UnwrapCommand(CommandApdu command)
    {
        _counter!.Increment();

        IReadOnlyList<BerTlv> objects = BerTlv.Parse(command.Data.Span);

        BerTlv? do87 = BerTlv.Find(objects, 0x87);
        BerTlv? do97 = BerTlv.Find(objects, 0x97);
        BerTlv do8e = BerTlv.Find(objects, 0x8E)
            ?? throw new CardTransportException("The terminal sent no DO'8E' checksum.");

        byte[] header = Iso7816Padding.Add([command.Cla, command.Ins, command.P1, command.P2]);

        ReadOnlyMemory<byte> encrypted = do87?.RawBytes ?? default;
        ReadOnlyMemory<byte> expectedLength = do97?.RawBytes ?? default;

        byte[] macInput =
        [
            .. _counter.Value,
            .. header,
            .. encrypted.Span,
            .. expectedLength.Span,
        ];

        byte[] expected = TripleDes.RetailMac(_sessionMacKey, macInput);

        if (!CryptographicOperations.FixedTimeEquals(expected, do8e.Value.Span))
        {
            throw new CardTransportException(
                "The terminal's protected command failed its checksum.");
        }

        byte[] data = [];

        if (do87 is not null)
        {
            byte[] plaintext = TripleDes.DecryptCbc(_sessionEncryptionKey, do87.Value.Span[1..]);
            data = Iso7816Padding.Remove(plaintext) ?? [];
        }

        int? le = null;

        if (do97 is not null)
        {
            le = do97.Value.Length == 1
                ? (do97.Value.Span[0] == 0 ? 256 : do97.Value.Span[0])
                : (do97.Value.Span[0] << 8) | do97.Value.Span[1];
        }

        // Strip the secure-messaging bits so the plain handler sees a normal command.
        return new CommandApdu(
            (byte)(command.Cla & ~0x0C),
            command.Ins,
            command.P1,
            command.P2,
            new ReadOnlyMemory<byte>(data),
            le);
    }

    /// <summary>Wraps a response: encrypts its data and appends a checksum.</summary>
    private ResponseApdu WrapResponse(ResponseApdu response)
    {
        _counter!.Increment();

        byte[] do87 = [];

        if (response.Data.Length > 0)
        {
            byte[] padded = Iso7816Padding.Add(response.Data.Span);
            byte[] ciphertext = TripleDes.EncryptCbc(_sessionEncryptionKey, padded);
            do87 = BerTlv.Encode(0x87, [0x01, .. ciphertext]);
        }

        byte[] do99 = BerTlv.Encode(0x99, [response.StatusWord.Sw1, response.StatusWord.Sw2]);
        byte[] mac = TripleDes.RetailMac(_sessionMacKey, [.. _counter.Value, .. do87, .. do99]);

        _protectedResponses++;

        // The active-attacker case: a response arriving with a checksum that does not
        // verify. Applied from the second protected response onward, so the session is
        // genuinely established first — that makes it a mid-session tamper rather than a
        // failed handshake, which is the harder case for a reader to handle correctly.
        if (_fault == DocumentFault.CorruptedSecureMessagingMac && _protectedResponses >= 2)
        {
            mac[^1] ^= 0xFF;
        }

        byte[] do8e = BerTlv.Encode(0x8E, mac);

        byte[] payload = [.. do87, .. do99, .. do8e];

        return new ResponseApdu(payload, new StatusWord(StatusWord.Success));
    }

    private void ActivatePendingChipAuthChannel()
    {
        if (_chipAuthPending is not null)
        {
            _chipAuthChannel = _chipAuthPending;
            _chipAuthPending = null;
        }
    }

    private static ResponseApdu Status(ushort statusWord) =>
        new(default, new StatusWord(statusWord));
}
