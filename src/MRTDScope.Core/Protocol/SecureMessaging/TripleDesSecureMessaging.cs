using System.Security.Cryptography;
using MRTDScope.Core.Apdu;
using MRTDScope.Core.Crypto;
using MRTDScope.Core.Errors;
using MRTDScope.Core.Tlv;

namespace MRTDScope.Core.Protocol.SecureMessaging;

/// <summary>
/// Secure messaging with 3DES encryption and the ISO/IEC 9797-1 Algorithm 3 retail MAC,
/// as established by BAC (ICAO Doc 9303 Part 11, section 9.8).
/// </summary>
public sealed class TripleDesSecureMessaging : ISecureMessaging
{
    private const int TagEncryptedData = 0x87;
    private const int TagExpectedLength = 0x97;
    private const int TagStatusWord = 0x99;
    private const int TagMac = 0x8E;

    /// <summary>Padding-content indicator preceding the ciphertext inside DO'87'.</summary>
    private const byte PaddingIndicator = 0x01;

    private readonly byte[] _encryptionKey;
    private readonly byte[] _macKey;
    private readonly SendSequenceCounter _ssc;

    public TripleDesSecureMessaging(
        ReadOnlySpan<byte> encryptionKey,
        ReadOnlySpan<byte> macKey,
        SendSequenceCounter sendSequenceCounter)
    {
        ArgumentNullException.ThrowIfNull(sendSequenceCounter);

        _encryptionKey = encryptionKey.ToArray();
        _macKey = macKey.ToArray();
        _ssc = sendSequenceCounter;
    }

    public string Algorithm => "3DES-CBC / ISO 9797-1 MAC Algorithm 3";

    public CommandApdu Protect(CommandApdu command)
    {
        ArgumentNullException.ThrowIfNull(command);

        _ssc.Increment();

        // Bits b4 and b3 of CLA mark the command as carrying secure messaging.
        byte protectedCla = (byte)(command.Cla | 0x0C);

        byte[] do87 = BuildEncryptedDataObject(command.Data.Span);
        byte[] do97 = BuildExpectedLengthObject(command.ExpectedLength);

        // MAC input is SSC || padded command header || DO'87' || DO'97'.
        byte[] header = Iso7816Padding.Add([protectedCla, command.Ins, command.P1, command.P2]);

        byte[] macInput = Concat(_ssc.Value, header, do87, do97);
        byte[] mac = TripleDes.RetailMac(_macKey, macInput);
        byte[] do8e = BerTlv.Encode(TagMac, mac);

        byte[] payload = Concat(do87, do97, do8e);

        // A protected command always requests a response, since the response at minimum
        // carries DO'99' and DO'8E'.
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
            // The card rejected the command before secure messaging applied — for
            // example 6987 or 6988. There is nothing to verify; pass the status through
            // so the caller can report it precisely.
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
        BerTlv? do99 = BerTlv.Find(objects, TagStatusWord);
        BerTlv? do8e = BerTlv.Find(objects, TagMac);

        if (do8e is null)
        {
            throw new SecureMessagingException(
                "The protected response carried no DO'8E' checksum.");
        }

        if (do99 is null)
        {
            throw new SecureMessagingException(
                "The protected response carried no DO'99' status word.");
        }

        // The MAC covers SSC and the received data objects exactly as encoded.
        ReadOnlyMemory<byte> encryptedRaw = do87?.RawBytes ?? default;
        byte[] macInput = Concat(_ssc.Value, encryptedRaw.Span, do99.RawBytes.Span);

        byte[] expected = TripleDes.RetailMac(_macKey, macInput);

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

        if (do87 is null)
        {
            return new ResponseApdu(default, statusWord);
        }

        return new ResponseApdu(Decrypt(do87.Value.Span), statusWord);
    }

    private byte[] BuildEncryptedDataObject(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0)
        {
            return [];
        }

        byte[] padded = Iso7816Padding.Add(data);
        byte[] ciphertext = TripleDes.EncryptCbc(_encryptionKey, padded);

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

        // 256 encodes as a single 0x00 byte, mirroring the plain APDU encoding.
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

        if (ciphertext.Length % TripleDes.BlockSize != 0)
        {
            throw new SecureMessagingException(
                $"DO'87' ciphertext is {ciphertext.Length} bytes, not a multiple of " +
                $"{TripleDes.BlockSize}.");
        }

        byte[] plaintext = TripleDes.DecryptCbc(_encryptionKey, ciphertext);
        byte[]? unpadded = Iso7816Padding.Remove(plaintext);

        if (unpadded is null)
        {
            throw new SecureMessagingException(
                "The decrypted response did not carry valid ISO/IEC 7816-4 padding, " +
                "despite a verified checksum.");
        }

        return unpadded;
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
        ReadOnlySpan<byte> a,
        ReadOnlySpan<byte> b,
        ReadOnlySpan<byte> c,
        ReadOnlySpan<byte> d)
    {
        byte[] buffer = new byte[a.Length + b.Length + c.Length + d.Length];
        a.CopyTo(buffer);
        b.CopyTo(buffer.AsSpan(a.Length));
        c.CopyTo(buffer.AsSpan(a.Length + b.Length));
        d.CopyTo(buffer.AsSpan(a.Length + b.Length + c.Length));
        return buffer;
    }
}
