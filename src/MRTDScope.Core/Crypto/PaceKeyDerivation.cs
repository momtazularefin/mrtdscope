using System.Security.Cryptography;
using MRTDScope.Core.Protocol.Pace;

namespace MRTDScope.Core.Crypto;

/// <summary>
/// The key derivation function of ICAO Doc 9303 Part 11 §9.7.1, used by PACE and by
/// Chip Authentication.
/// </summary>
/// <remarks>
/// <c>KDF(K, c) = H(K || c)</c>, where the hash and the output length follow the cipher:
/// SHA-1 truncated to 16 bytes for AES-128, SHA-256 truncated to 24 for AES-192, and
/// SHA-256 in full for AES-256. The counter <c>c</c> is a 32-bit big-endian integer
/// selecting which key is being derived.
/// <para>
/// SHA-1 appears here for AES-128 because the specification says so, not as a choice.
/// It is a key-derivation step over a freshly agreed secret, where collision resistance
/// is not the property being relied on.
/// </para>
/// </remarks>
public static class PaceKeyDerivation
{
    private const int CounterEncryption = 1;
    private const int CounterMac = 2;
    private const int CounterPassword = 3;

    /// <summary>Derives the encryption key from an agreed shared secret.</summary>
    public static byte[] DeriveEncryptionKey(ReadOnlySpan<byte> sharedSecret, PaceCipher cipher) =>
        Derive(sharedSecret, CounterEncryption, cipher);

    /// <summary>Derives the MAC key from an agreed shared secret.</summary>
    public static byte[] DeriveMacKey(ReadOnlySpan<byte> sharedSecret, PaceCipher cipher) =>
        Derive(sharedSecret, CounterMac, cipher);

    /// <summary>
    /// Derives the password key that decrypts the chip's nonce.
    /// </summary>
    /// <param name="password">
    /// For an MRZ password this is SHA-1 over the MRZ information — the full 20-byte
    /// digest, not the 16-byte truncation BAC uses as its seed. Conflating the two
    /// produces a key that decrypts the nonce to garbage with no error anywhere.
    /// </param>
    public static byte[] DerivePasswordKey(ReadOnlySpan<byte> password, PaceCipher cipher) =>
        Derive(password, CounterPassword, cipher);

    /// <summary>
    /// The MRZ password for PACE: SHA-1 over the same MRZ information BAC hashes.
    /// </summary>
    public static byte[] MrzPassword(Mrz.MrzKey mrzKey)
    {
        ArgumentNullException.ThrowIfNull(mrzKey);

        return SHA1.HashData(
            System.Text.Encoding.ASCII.GetBytes(mrzKey.MrzInformation));
    }

    private static byte[] Derive(ReadOnlySpan<byte> secret, int counter, PaceCipher cipher)
    {
        byte[] input = new byte[secret.Length + 4];
        secret.CopyTo(input);
        input[^4] = (byte)(counter >> 24);
        input[^3] = (byte)(counter >> 16);
        input[^2] = (byte)(counter >> 8);
        input[^1] = (byte)counter;

        byte[] digest = cipher == PaceCipher.Aes128
            ? SHA1.HashData(input)
            : SHA256.HashData(input);

        return digest[..KeyLength(cipher)];
    }

    /// <summary>The session key length in bytes for a cipher.</summary>
    public static int KeyLength(PaceCipher cipher) => cipher switch
    {
        PaceCipher.TripleDes => 16,
        PaceCipher.Aes128 => 16,
        PaceCipher.Aes192 => 24,
        PaceCipher.Aes256 => 32,
        _ => throw new ArgumentOutOfRangeException(nameof(cipher)),
    };
}
