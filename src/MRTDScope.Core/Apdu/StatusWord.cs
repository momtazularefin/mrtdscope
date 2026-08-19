namespace MRTDScope.Core.Apdu;

/// <summary>
/// An ISO/IEC 7816-4 status word.
/// </summary>
public readonly record struct StatusWord(ushort Value)
{
    /// <summary>Normal completion.</summary>
    public const ushort Success = 0x9000;

    /// <summary>Security status not satisfied — the file needs an established secure channel.</summary>
    public const ushort SecurityStatusNotSatisfied = 0x6982;

    /// <summary>Authentication failed, or the supplied password was wrong.</summary>
    public const ushort SecurityMessageIncorrect = 0x6988;

    /// <summary>Incorrect parameters P1-P2 — commonly a read beyond end of file.</summary>
    public const ushort WrongParameters = 0x6A86;

    /// <summary>Referenced file or application not found.</summary>
    public const ushort FileNotFound = 0x6A82;

    /// <summary>Conditions of use not satisfied.</summary>
    public const ushort ConditionsNotSatisfied = 0x6985;

    public byte Sw1 => (byte)(Value >> 8);

    public byte Sw2 => (byte)(Value & 0xFF);

    /// <summary>Whether the command completed normally.</summary>
    public bool IsSuccess => Value == Success;

    /// <summary>
    /// Whether the card is reporting that more data is available, with the count in SW2
    /// (61xx). The caller should follow with GET RESPONSE.
    /// </summary>
    public bool HasMoreData => Sw1 == 0x61;

    /// <summary>
    /// Whether the card is reporting that a different Le should have been used, with the
    /// correct length in SW2 (6Cxx).
    /// </summary>
    public bool WrongLength => Sw1 == 0x6C;

    public override string ToString() => $"{Value:X4}";
}
