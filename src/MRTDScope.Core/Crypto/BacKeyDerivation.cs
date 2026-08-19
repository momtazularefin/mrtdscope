using System.Security.Cryptography;

namespace MRTDScope.Core.Crypto;

/// <summary>
/// The 3DES key derivation mechanism of ICAO Doc 9303 Part 11, used by BAC for both the
/// document keys and the session keys.
/// </summary>
public static class BacKeyDerivation
{
    /// <summary>Counter selecting the encryption key.</summary>
    private const byte EncryptionCounter = 0x01;

    /// <summary>Counter selecting the MAC key.</summary>
    private const byte MacCounter = 0x02;

    /// <summary>A pair of 2-key 3DES keys derived from one seed.</summary>
    /// <param name="Encryption">K_Enc, for 3DES-CBC.</param>
    /// <param name="Mac">K_MAC, for the ISO/IEC 9797-1 Algorithm 3 retail MAC.</param>
    public readonly record struct KeyPair(byte[] Encryption, byte[] Mac);

    /// <summary>
    /// Derives K_Enc and K_MAC from a 16-byte seed.
    /// </summary>
    /// <remarks>
    /// Doc 9303 Part 11 section 9.7.1: D = K_seed || c, H = SHA-1(D), then the first two
    /// 8-byte halves of H become the 3DES key parts after odd-parity adjustment.
    /// </remarks>
    public static KeyPair Derive(ReadOnlySpan<byte> seed)
    {
        if (seed.Length != 16)
        {
            throw new ArgumentException(
                $"The BAC key seed is 16 bytes; got {seed.Length}.", nameof(seed));
        }

        return new KeyPair(
            DeriveKey(seed, EncryptionCounter),
            DeriveKey(seed, MacCounter));
    }

    private static byte[] DeriveKey(ReadOnlySpan<byte> seed, byte counter)
    {
        Span<byte> input = stackalloc byte[seed.Length + 4];
        seed.CopyTo(input);
        input[seed.Length] = 0x00;
        input[seed.Length + 1] = 0x00;
        input[seed.Length + 2] = 0x00;
        input[seed.Length + 3] = counter;

        Span<byte> hash = stackalloc byte[20];
        SHA1.HashData(input, hash);

        byte[] key = hash[..16].ToArray();
        AdjustParity(key);
        return key;
    }

    /// <summary>
    /// Forces odd parity on the low bit of every byte, as DES key bytes require.
    /// </summary>
    /// <remarks>
    /// This is cosmetic for most libraries, which ignore the parity bit, but the derived
    /// key must match the specification's published value byte for byte or the Doc 9303
    /// Appendix D test vectors will not reproduce.
    /// </remarks>
    internal static void AdjustParity(Span<byte> key)
    {
        for (int i = 0; i < key.Length; i++)
        {
            int value = key[i];
            int onesInHighBits = System.Numerics.BitOperations.PopCount((uint)(value & 0xFE));
            key[i] = (byte)((value & 0xFE) | (onesInHighBits % 2 == 0 ? 1 : 0));
        }
    }
}
