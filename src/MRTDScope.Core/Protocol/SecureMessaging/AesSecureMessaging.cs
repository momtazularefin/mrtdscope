using System.Security.Cryptography;
using MRTDScope.Core.Apdu;
using MRTDScope.Core.Crypto;
using MRTDScope.Core.Errors;
using MRTDScope.Core.Tlv;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace MRTDScope.Core.Protocol.SecureMessaging;

/// <summary>
/// Secure messaging with AES-CBC encryption and AES-CMAC, as established by PACE
/// (ICAO Doc 9303 Part 11 §9.8.6).
/// </summary>
/// <remarks>
/// Structurally the same data objects as the 3DES channel, with three differences that
/// each break the session silently if missed:
/// <list type="bullet">
/// <item>The send sequence counter is 16 bytes, not 8, and starts at zero after PACE
/// rather than being derived from nonces.</item>
/// <item>The CBC initialisation vector is not zero. It is the current SSC encrypted
/// under the session key in ECB mode, so every message gets a distinct IV.</item>
/// <item>The checksum is AES-CMAC truncated to 8 bytes, not the retail MAC.</item>
/// </list>
/// </remarks>
public sealed class AesSecureMessaging : ISecureMessaging
{
    private const int TagEncryptedData = 0x87;
    private const int TagExpectedLength = 0x97;
    private const int TagStatusWord = 0x99;
    private const int TagMac = 0x8E;

    private const byte PaddingIndicator = 0x01;

    /// <summary>AES block size in bytes.</summary>
    private const int BlockSize = 16;

    /// <summary>Doc 9303 truncates the CMAC to eight bytes.</summary>
    private const int MacLength = 8;

    private readonly byte[] _encryptionKey;
    private readonly byte[] _macKey;
    private readonly SendSequenceCounter _ssc;

    public AesSecureMessaging(
        ReadOnlySpan<byte> encryptionKey,
        ReadOnlySpan<byte> macKey,
        SendSequenceCounter sendSequenceCounter)
    {
        ArgumentNullException.ThrowIfNull(sendSequenceCounter);

        if (sendSequenceCounter.Length != BlockSize)
        {
            throw new ArgumentException(
                $"AES secure messaging uses a {BlockSize}-byte send sequence counter; " +
                $"got {sendSequenceCounter.Length}.",
                nameof(sendSequenceCounter));
        }

        _encryptionKey = encryptionKey.ToArray();
        _macKey = macKey.ToArray();
        _ssc = sendSequenceCounter;
    }

    public string Algorithm => $"AES-{_encryptionKey.Length * 8}-CBC / AES-CMAC";

    public CommandApdu Protect(CommandApdu command)
    {
        ArgumentNullException.ThrowIfNull(command);

        _ssc.Increment();

        byte protectedCla = (byte)(command.Cla | 0x0C);

        byte[] do87 = BuildEncryptedDataObject(command.Data.Span);
        byte[] do97 = BuildExpectedLengthObject(command.ExpectedLength);

        byte[] header = Iso7816Padding.Add(
            [protectedCla, command.Ins, command.P1, command.P2], BlockSize);

        byte[] macInput = Concat(_ssc.Value, header, do87, do97);
        byte[] mac = ComputeMac(Iso7816Padding.Add(macInput, BlockSize));
        byte[] do8e = BerTlv.Encode(TagMac, mac);

        byte[] payload = Concat(do87, do97, do8e);

        return new CommandApdu(
            protectedCla,
            command.Ins,
            command.P1,
            command.P2,
            payload,
            expectedLength: CommandApdu.MaxShortLength);
    }

    public ResponseApdu Unprotect(ResponseApdu response)
    {
        ArgumentNullException.ThrowIfNull(response);

        _ssc.Increment();

        if (response.Data.Length == 0)
        {
            return response;
        }

        IReadOnlyList<BerTlv> objects;
        try
        {
            objects = BerTlv.Parse(response.Data.Span);
        }
        catch (MrtdEncodingException exception)
        {
            throw new SecureMessagingException(
                "The protected response was not well-formed BER-TLV.", exception);
        }

        BerTlv? do87 = BerTlv.Find(objects, TagEncryptedData);
        BerTlv? do99 = BerTlv.Find(objects, TagStatusWord)
            ?? throw new SecureMessagingException(
                "The protected response carried no DO'99' status word.");
        BerTlv do8e = BerTlv.Find(objects, TagMac)
            ?? throw new SecureMessagingException(
                "The protected response carried no DO'8E' checksum.");

        ReadOnlyMemory<byte> encrypted = do87?.RawBytes ?? default;
        byte[] macInput = Concat(_ssc.Value, encrypted.Span, do99.RawBytes.Span);
        byte[] expected = ComputeMac(Iso7816Padding.Add(macInput, BlockSize));

        if (!CryptographicOperations.FixedTimeEquals(expected, do8e.Value.Span))
        {
            throw new SecureMessagingException(
                "The protected response failed its checksum. The secure channel is no " +
                "longer trustworthy and the session cannot continue.");
        }

        if (do99.Value.Length != 2)
        {
            throw new SecureMessagingException(
                $"DO'99' must hold a 2-byte status word; got {do99.Value.Length}.");
        }

        StatusWord statusWord = new((ushort)((do99.Value.Span[0] << 8) | do99.Value.Span[1]));

        return do87 is null
            ? new ResponseApdu(default, statusWord)
            : new ResponseApdu(Decrypt(do87.Value.Span), statusWord);
    }

    /// <summary>
    /// The CBC initialisation vector: the current SSC encrypted under the session key in
    /// ECB mode.
    /// </summary>
    /// <remarks>
    /// This is the difference most easily missed when moving from the 3DES channel, which
    /// uses an all-zero IV. Using zero here produces ciphertext the chip cannot decrypt,
    /// and the resulting failure looks like a key-derivation problem rather than a mode
    /// problem.
    /// </remarks>
    private byte[] ComputeIv()
    {
        using Aes aes = Aes.Create();
        aes.Key = _encryptionKey;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;

        return aes.EncryptEcb(_ssc.Value, PaddingMode.None);
    }

    private byte[] ComputeMac(ReadOnlySpan<byte> paddedInput)
    {
        CMac mac = new(new AesEngine());
        mac.Init(new KeyParameter(_macKey));

        byte[] input = paddedInput.ToArray();
        mac.BlockUpdate(input, 0, input.Length);

        byte[] full = new byte[mac.GetMacSize()];
        mac.DoFinal(full, 0);

        return full[..MacLength];
    }

    private byte[] BuildEncryptedDataObject(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0)
        {
            return [];
        }

        byte[] padded = Iso7816Padding.Add(data, BlockSize);

        using Aes aes = Aes.Create();
        aes.Key = _encryptionKey;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.None;

        byte[] ciphertext = aes.EncryptCbc(padded, ComputeIv(), PaddingMode.None);

        byte[] value = new byte[ciphertext.Length + 1];
        value[0] = PaddingIndicator;
        ciphertext.CopyTo(value, 1);

        return BerTlv.Encode(TagEncryptedData, value);
    }

    private static byte[] BuildExpectedLengthObject(int? expectedLength)
    {
        if (expectedLength is not { } le)
        {
            return [];
        }

        byte[] value = le switch
        {
            CommandApdu.MaxShortLength => [0x00],
            <= 0xFF => [(byte)le],
            _ => [(byte)(le >> 8), (byte)le],
        };

        return BerTlv.Encode(TagExpectedLength, value);
    }

    private byte[] Decrypt(ReadOnlySpan<byte> do87Value)
    {
        if (do87Value.Length < 2 || do87Value[0] != PaddingIndicator)
        {
            throw new SecureMessagingException(
                $"DO'87' must begin with padding indicator 0x{PaddingIndicator:X2}.");
        }

        ReadOnlySpan<byte> ciphertext = do87Value[1..];

        if (ciphertext.Length % BlockSize != 0)
        {
            throw new SecureMessagingException(
                $"DO'87' ciphertext is {ciphertext.Length} bytes, not a multiple of {BlockSize}.");
        }

        using Aes aes = Aes.Create();
        aes.Key = _encryptionKey;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.None;

        byte[] plaintext = aes.DecryptCbc(ciphertext.ToArray(), ComputeIv(), PaddingMode.None);
        byte[]? unpadded = Iso7816Padding.Remove(plaintext);

        return unpadded
            ?? throw new SecureMessagingException(
                "The decrypted response did not carry valid ISO/IEC 7816-4 padding, " +
                "despite a verified checksum.");
    }

    private static byte[] Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c)
    {
        byte[] buffer = new byte[a.Length + b.Length + c.Length];
        a.CopyTo(buffer);
        b.CopyTo(buffer.AsSpan(a.Length));
        c.CopyTo(buffer.AsSpan(a.Length + b.Length));
        return buffer;
    }

    private static byte[] Concat(
        ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c, ReadOnlySpan<byte> d)
    {
        byte[] buffer = new byte[a.Length + b.Length + c.Length + d.Length];
        a.CopyTo(buffer);
        b.CopyTo(buffer.AsSpan(a.Length));
        c.CopyTo(buffer.AsSpan(a.Length + b.Length));
        d.CopyTo(buffer.AsSpan(a.Length + b.Length + c.Length));
        return buffer;
    }
}
