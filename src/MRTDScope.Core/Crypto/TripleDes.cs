using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;

namespace MRTDScope.Core.Crypto;

/// <summary>
/// The 3DES primitives BAC secure messaging is built from.
/// </summary>
public static class TripleDes
{
    /// <summary>The DES block size in bytes.</summary>
    public const int BlockSize = 8;

    /// <summary>The retail MAC output size in bytes.</summary>
    public const int MacSize = 8;

    private static readonly byte[] ZeroIv = new byte[BlockSize];

    /// <summary>
    /// Encrypts with two-key 3DES in CBC mode under an all-zero IV, as Doc 9303 specifies
    /// for BAC secure messaging.
    /// </summary>
    public static byte[] EncryptCbc(ReadOnlySpan<byte> key, ReadOnlySpan<byte> plaintext) =>
        ProcessCbc(key, plaintext, forEncryption: true);

    /// <summary>Decrypts with two-key 3DES in CBC mode under an all-zero IV.</summary>
    public static byte[] DecryptCbc(ReadOnlySpan<byte> key, ReadOnlySpan<byte> ciphertext) =>
        ProcessCbc(key, ciphertext, forEncryption: false);

    private static byte[] ProcessCbc(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, bool forEncryption)
    {
        if (input.Length % BlockSize != 0)
        {
            throw new ArgumentException(
                $"3DES-CBC input must be a multiple of {BlockSize} bytes; got {input.Length}.",
                nameof(input));
        }

        CbcBlockCipher cipher = new(new DesEdeEngine());
        cipher.Init(forEncryption, new ParametersWithIV(new KeyParameter(Expand(key)), ZeroIv));

        byte[] source = input.ToArray();
        byte[] output = new byte[source.Length];

        for (int offset = 0; offset < source.Length; offset += BlockSize)
        {
            cipher.ProcessBlock(source, offset, output, offset);
        }

        return output;
    }

    /// <summary>
    /// Computes the ISO/IEC 9797-1 Algorithm 3 retail MAC with DES, padding method 2.
    /// </summary>
    /// <remarks>
    /// The caller supplies the message already concatenated; this method applies the
    /// padding, matching the specification's definition of the MAC input.
    /// </remarks>
    public static byte[] RetailMac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message)
    {
        ISO9797Alg3Mac mac = new(new DesEngine(), MacSize * 8, new ISO7816d4Padding());
        mac.Init(new KeyParameter(Expand(key)));

        byte[] source = message.ToArray();
        mac.BlockUpdate(source, 0, source.Length);

        byte[] output = new byte[mac.GetMacSize()];
        mac.DoFinal(output, 0);
        return output;
    }

    /// <summary>
    /// Expands a 16-byte two-key 3DES key to the 24-byte three-key form by repeating the
    /// first block, which is what the underlying engine expects.
    /// </summary>
    private static byte[] Expand(ReadOnlySpan<byte> key)
    {
        if (key.Length == 24)
        {
            return key.ToArray();
        }

        if (key.Length != 16)
        {
            throw new ArgumentException(
                $"A 3DES key is 16 or 24 bytes; got {key.Length}.", nameof(key));
        }

        byte[] expanded = new byte[24];
        key.CopyTo(expanded);
        key[..8].CopyTo(expanded.AsSpan(16));
        return expanded;
    }
}
