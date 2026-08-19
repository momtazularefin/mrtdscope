using System.Security.Cryptography;
using System.Text;
using MRTDScope.Core.Errors;

namespace MRTDScope.Core.Mrz;

/// <summary>
/// The document key derived from the Machine Readable Zone, used as the BAC password and
/// as one of the PACE password options.
/// </summary>
/// <remarks>
/// This is the single implementation of the MRZ seed. The code this project harvests
/// from computed it in two places — one encoding the MRZ information as UTF-8, the other
/// as ASCII — which agree for the MRZ character set and would silently diverge the
/// moment anything outside it appeared. One implementation, one encoding.
/// </remarks>
public sealed class MrzKey
{
    /// <summary>The MRZ filler character, which pads short fields and counts as zero.</summary>
    public const char Filler = '<';

    private MrzKey(string documentNumber, string dateOfBirth, string dateOfExpiry, string mrzInformation)
    {
        DocumentNumber = documentNumber;
        DateOfBirth = dateOfBirth;
        DateOfExpiry = dateOfExpiry;
        MrzInformation = mrzInformation;
    }

    /// <summary>The document number, filler-padded to nine characters.</summary>
    public string DocumentNumber { get; }

    /// <summary>Date of birth as YYMMDD.</summary>
    public string DateOfBirth { get; }

    /// <summary>Date of expiry as YYMMDD.</summary>
    public string DateOfExpiry { get; }

    /// <summary>
    /// The concatenated MRZ information: each field followed by its check digit. This is
    /// the exact string hashed to produce the seed.
    /// </summary>
    public string MrzInformation { get; }

    /// <summary>
    /// Builds the key from the three MRZ fields, computing each check digit.
    /// </summary>
    /// <param name="documentNumber">
    /// The document number. Padded with filler to nine characters when shorter.
    /// </param>
    /// <param name="dateOfBirth">Date of birth as YYMMDD.</param>
    /// <param name="dateOfExpiry">Date of expiry as YYMMDD.</param>
    public static MrzKey Create(string documentNumber, string dateOfBirth, string dateOfExpiry)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(documentNumber);
        ArgumentException.ThrowIfNullOrWhiteSpace(dateOfBirth);
        ArgumentException.ThrowIfNullOrWhiteSpace(dateOfExpiry);

        string normalizedNumber = Normalize(documentNumber);
        string birth = Normalize(dateOfBirth);
        string expiry = Normalize(dateOfExpiry);

        RequireLength(birth, 6, nameof(dateOfBirth));
        RequireLength(expiry, 6, nameof(dateOfExpiry));

        if (normalizedNumber.Length > 9)
        {
            throw new MrtdEncodingException(
                "Document numbers longer than nine characters use the extended MRZ form, " +
                "which is not supported yet. Supply the nine-character field as printed.");
        }

        normalizedNumber = normalizedNumber.PadRight(9, Filler);

        string information =
            normalizedNumber + ComputeCheckDigit(normalizedNumber) +
            birth + ComputeCheckDigit(birth) +
            expiry + ComputeCheckDigit(expiry);

        return new MrzKey(normalizedNumber, birth, expiry, information);
    }

    /// <summary>
    /// Computes the 16-byte BAC key seed: the first 16 bytes of SHA-1 over the MRZ
    /// information (Doc 9303 Part 11, section 9.7.2).
    /// </summary>
    public byte[] ComputeSeed()
    {
        byte[] encoded = Encoding.ASCII.GetBytes(MrzInformation);
        byte[] hash = SHA1.HashData(encoded);
        return hash[..16];
    }

    /// <summary>Derives the BAC document keys from this MRZ.</summary>
    public Crypto.BacKeyDerivation.KeyPair DeriveDocumentKeys() =>
        Crypto.BacKeyDerivation.Derive(ComputeSeed());

    /// <summary>
    /// Computes the ICAO 7-3-1 weighted check digit over an MRZ field.
    /// </summary>
    public static char ComputeCheckDigit(string field)
    {
        ArgumentNullException.ThrowIfNull(field);

        ReadOnlySpan<int> weights = [7, 3, 1];
        int sum = 0;

        for (int i = 0; i < field.Length; i++)
        {
            sum += CharacterValue(field[i]) * weights[i % 3];
        }

        return (char)('0' + (sum % 10));
    }

    private static int CharacterValue(char character) => character switch
    {
        >= '0' and <= '9' => character - '0',
        >= 'A' and <= 'Z' => character - 'A' + 10,
        Filler => 0,
        _ => throw new MrtdEncodingException(
            $"'{character}' is not a valid MRZ character; expected 0-9, A-Z, or '{Filler}'."),
    };

    private static string Normalize(string value) =>
        value.Trim().ToUpperInvariant().Replace(" ", string.Empty, StringComparison.Ordinal);

    private static void RequireLength(string value, int expected, string parameterName)
    {
        if (value.Length != expected)
        {
            throw new MrtdEncodingException(
                $"{parameterName} must be {expected} characters (YYMMDD); got '{value}'.");
        }
    }
}
