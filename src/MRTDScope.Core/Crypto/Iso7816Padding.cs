namespace MRTDScope.Core.Crypto;

/// <summary>
/// ISO/IEC 7816-4 padding method 2: append 0x80, then 0x00 to the block boundary.
/// </summary>
public static class Iso7816Padding
{
    /// <summary>
    /// Pads to a multiple of <paramref name="blockSize"/>.
    /// </summary>
    /// <remarks>
    /// A full block of padding is appended when the input is already aligned. That is
    /// not an oversight: without it, a message ending in 0x80 would be indistinguishable
    /// from a padded one, and <see cref="Remove"/> could not tell them apart.
    /// </remarks>
    public static byte[] Add(ReadOnlySpan<byte> data, int blockSize = 8)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(blockSize, 1);

        int padLength = blockSize - (data.Length % blockSize);
        byte[] padded = new byte[data.Length + padLength];
        data.CopyTo(padded);
        padded[data.Length] = 0x80;
        return padded;
    }

    /// <summary>
    /// Strips the padding, or returns <c>null</c> when the trailer is not valid padding.
    /// </summary>
    /// <remarks>
    /// Returning null rather than throwing lets the caller decide. Invalid padding after
    /// a verified MAC means a decryption problem worth reporting precisely, not a
    /// generic parse failure.
    /// </remarks>
    public static byte[]? Remove(ReadOnlySpan<byte> padded)
    {
        int index = padded.Length - 1;

        while (index >= 0 && padded[index] == 0x00)
        {
            index--;
        }

        if (index < 0 || padded[index] != 0x80)
        {
            return null;
        }

        return padded[..index].ToArray();
    }
}
