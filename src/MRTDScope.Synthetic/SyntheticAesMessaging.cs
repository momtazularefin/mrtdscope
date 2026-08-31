using System.Security.Cryptography;
using MRTDScope.Core.Apdu;
using MRTDScope.Core.Crypto;
using MRTDScope.Core.Errors;
using MRTDScope.Core.Protocol.SecureMessaging;
using MRTDScope.Core.Tlv;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace MRTDScope.Synthetic;

/// <summary>
/// The card side of AES secure messaging, shared by PACE and Chip Authentication.
/// </summary>
/// <remarks>
/// Both protocols establish the same kind of channel and differ only in how the keys were
/// agreed, so the chip keeps one implementation and creates a fresh instance whenever a
/// protocol restarts messaging. Each instance owns its own send sequence counter starting
/// at zero, which is what makes a restart a genuine restart rather than a rekey.
/// </remarks>
internal sealed class SyntheticAesMessaging
{
    private const int BlockSize = 16;
    private const int MacLength = 8;

    private readonly byte[] _encryptionKey;
    private readonly byte[] _macKey;
    private readonly SendSequenceCounter _counter;

    public SyntheticAesMessaging(byte[] encryptionKey, byte[] macKey)
    {
        _encryptionKey = encryptionKey;
        _macKey = macKey;
        _counter = new SendSequenceCounter(new byte[BlockSize]);
    }

    /// <summary>Unwraps a protected command: verifies its checksum, decrypts its data.</summary>
    public CommandApdu UnwrapCommand(CommandApdu command)
    {
        _counter.Increment();

        IReadOnlyList<BerTlv> objects = BerTlv.Parse(command.Data.Span);

        BerTlv? do87 = BerTlv.Find(objects, 0x87);
        BerTlv? do97 = BerTlv.Find(objects, 0x97);
        BerTlv do8e = BerTlv.Find(objects, 0x8E)
            ?? throw new CardTransportException("The terminal sent no DO'8E' checksum.");

        byte[] header = Iso7816Padding.Add(
            [command.Cla, command.Ins, command.P1, command.P2], BlockSize);

        ReadOnlyMemory<byte> encrypted = do87?.RawBytes ?? default;
        ReadOnlyMemory<byte> expectedLength = do97?.RawBytes ?? default;

        byte[] macInput =
        [
            .. _counter.Value, .. header, .. encrypted.Span, .. expectedLength.Span,
        ];

        if (!CryptographicOperations.FixedTimeEquals(
            Mac(Iso7816Padding.Add(macInput, BlockSize)), do8e.Value.Span))
        {
            throw new CardTransportException(
                "The terminal's protected command failed its checksum.");
        }

        byte[] data = [];

        if (do87 is not null)
        {
            data = Iso7816Padding.Remove(Crypt(do87.Value.Span[1..], encrypt: false)) ?? [];
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
        _counter.Increment();

        byte[] do87 = [];

        if (response.Data.Length > 0)
        {
            byte[] ciphertext = Crypt(
                Iso7816Padding.Add(response.Data.Span, BlockSize), encrypt: true);
            do87 = BerTlv.Encode(0x87, [0x01, .. ciphertext]);
        }

        byte[] do99 = BerTlv.Encode(0x99, [response.StatusWord.Sw1, response.StatusWord.Sw2]);
        byte[] macInput = [.. _counter.Value, .. do87, .. do99];
        byte[] do8e = BerTlv.Encode(0x8E, Mac(Iso7816Padding.Add(macInput, BlockSize)));

        byte[] payload = [.. do87, .. do99, .. do8e];

        return new ResponseApdu(payload, new StatusWord(StatusWord.Success));
    }

    /// <summary>The IV is the current counter encrypted under the session key in ECB.</summary>
    private byte[] Crypt(ReadOnlySpan<byte> input, bool encrypt)
    {
        using Aes aes = Aes.Create();
        aes.Key = _encryptionKey;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;

        byte[] iv = aes.EncryptEcb(_counter.Value, PaddingMode.None);

        aes.Mode = CipherMode.CBC;

        return encrypt
            ? aes.EncryptCbc(input.ToArray(), iv, PaddingMode.None)
            : aes.DecryptCbc(input.ToArray(), iv, PaddingMode.None);
    }

    private byte[] Mac(ReadOnlySpan<byte> padded)
    {
        CMac mac = new(new AesEngine());
        mac.Init(new KeyParameter(_macKey));

        byte[] input = padded.ToArray();
        mac.BlockUpdate(input, 0, input.Length);

        byte[] full = new byte[mac.GetMacSize()];
        mac.DoFinal(full, 0);

        return full[..MacLength];
    }
}
