using System.Text;
using MRTDScope.Core.Errors;
using MRTDScope.Core.Mrz;
using MRTDScope.Core.Tlv;

namespace MRTDScope.Core.Lds;

/// <summary>The MRZ document format, identified by its total character count.</summary>
public enum MrzFormat
{
    /// <summary>Three lines of 30 characters — ID cards and residence permits.</summary>
    Td1,

    /// <summary>Two lines of 36 characters — older travel documents.</summary>
    Td2,

    /// <summary>Two lines of 44 characters — passports.</summary>
    Td3,
}

/// <summary>
/// DG1 — the Machine Readable Zone as stored on the chip (Doc 9303 Part 10 §4.7.1).
/// </summary>
/// <remarks>
/// DG1 should reproduce the printed MRZ exactly. Comparing them is a genuine
/// cross-check, because a chip substitution that leaves the printed page intact shows up
/// as a mismatch here — but note that DG1 is covered by the security object, so a
/// tampered DG1 is already caught by the data-group hash check.
/// </remarks>
public sealed class MrzInfo
{
    private const int TagMrzData = 0x5F1F;

    private MrzInfo(MrzFormat format, string raw, IReadOnlyList<string> lines)
    {
        Format = format;
        Raw = raw;
        Lines = lines;
    }

    public MrzFormat Format { get; }

    /// <summary>The MRZ characters exactly as stored, without line separators.</summary>
    public string Raw { get; }

    /// <summary>The MRZ split into its fixed-width lines.</summary>
    public IReadOnlyList<string> Lines { get; }

    /// <summary>The three-letter issuing State or organization code.</summary>
    public string IssuingState { get; private init; } = string.Empty;

    /// <summary>The document number as printed, filler included.</summary>
    public string DocumentNumber { get; private init; } = string.Empty;

    /// <summary>Date of birth as YYMMDD.</summary>
    public string DateOfBirth { get; private init; } = string.Empty;

    /// <summary>Date of expiry as YYMMDD.</summary>
    public string DateOfExpiry { get; private init; } = string.Empty;

    /// <summary>The three-letter nationality code.</summary>
    public string Nationality { get; private init; } = string.Empty;

    /// <summary>Sex as printed: <c>M</c>, <c>F</c>, or <c>&lt;</c> for unspecified.</summary>
    public char Sex { get; private init; } = Mrz.MrzKey.Filler;

    /// <summary>The primary identifier — the surname, in most naming conventions.</summary>
    public string PrimaryIdentifier { get; private init; } = string.Empty;

    /// <summary>The secondary identifiers — given names, space-separated.</summary>
    public string SecondaryIdentifier { get; private init; } = string.Empty;

    /// <summary>
    /// The holder's name for display, secondary identifiers first.
    /// </summary>
    /// <remarks>
    /// Presentation only. The MRZ is a transliteration into a 37-character A-Z subset, so
    /// it routinely differs from the name printed in the visual zone: diacritics are
    /// stripped, non-Latin scripts are romanized, and a long name is simply truncated to
    /// fit. Displaying this as "the holder's name" is fine; treating it as an identity
    /// match against another document is not.
    /// </remarks>
    public string HolderName =>
        string.Join(' ', new[] { SecondaryIdentifier, PrimaryIdentifier }
            .Where(part => !string.IsNullOrEmpty(part)));

    /// <summary>
    /// Splits an MRZ name field into its primary and secondary identifiers.
    /// </summary>
    /// <remarks>
    /// Doc 9303 Part 3 §4: the primary identifier comes first, a double filler separates
    /// it from the secondary identifiers, and single fillers separate the parts of each.
    /// A name too long for the field is truncated, which means the double separator can
    /// be absent entirely — in that case the whole field is the primary identifier rather
    /// than a parse failure, because a truncated name is a legitimate MRZ.
    /// </remarks>
    private static (string Primary, string Secondary) ParseName(string field)
    {
        string trimmed = field.TrimEnd(Mrz.MrzKey.Filler);
        int separator = trimmed.IndexOf("<<", StringComparison.Ordinal);

        return separator < 0
            ? (Clean(trimmed), string.Empty)
            : (Clean(trimmed[..separator]), Clean(trimmed[(separator + 2)..]));

        static string Clean(string part) =>
            string.Join(' ', part.Split(Mrz.MrzKey.Filler, StringSplitOptions.RemoveEmptyEntries));
    }

    /// <summary>Parses the raw DG1 file content, tag 0x61 included.</summary>
    public static MrzInfo Parse(ReadOnlySpan<byte> fileContent)
    {
        IReadOnlyList<BerTlv> outer = BerTlv.Parse(fileContent);
        BerTlv root = BerTlv.Find(outer, DataGroup.Dg1.Tag)
            ?? throw new MrtdEncodingException(
                $"DG1 must be wrapped in tag 0x{DataGroup.Dg1.Tag:X2}.");

        BerTlv mrz = BerTlv.Find(root.Children(), TagMrzData)
            ?? throw new MrtdEncodingException("DG1 carries no MRZ data object (tag 0x5F1F).");

        string raw = Encoding.ASCII.GetString(mrz.Value.Span);

        (MrzFormat format, int lineLength, int lineCount) = raw.Length switch
        {
            90 => (MrzFormat.Td1, 30, 3),
            72 => (MrzFormat.Td2, 36, 2),
            88 => (MrzFormat.Td3, 44, 2),
            _ => throw new MrtdEncodingException(
                $"An MRZ of {raw.Length} characters matches no known format " +
                "(TD1 is 90, TD2 is 72, TD3 is 88)."),
        };

        List<string> lines = [];
        for (int i = 0; i < lineCount; i++)
        {
            lines.Add(raw.Substring(i * lineLength, lineLength));
        }

        // Field positions differ by format. TD1 carries the document number on line 1 and
        // the name on a third line, where TD2 and TD3 carry the document number on line 2
        // and the name on the remainder of line 1. TD2 and TD3 share every offset used
        // here; only their line width differs, which the name field absorbs.
        (string primary, string secondary) = ParseName(
            format == MrzFormat.Td1 ? lines[2] : lines[0][5..]);

        return format == MrzFormat.Td1
            ? new MrzInfo(format, raw, lines)
            {
                IssuingState = lines[0].Substring(2, 3),
                DocumentNumber = lines[0].Substring(5, 9),
                DateOfBirth = lines[1][..6],
                DateOfExpiry = lines[1].Substring(8, 6),
                Nationality = lines[1].Substring(15, 3),
                Sex = lines[1][7],
                PrimaryIdentifier = primary,
                SecondaryIdentifier = secondary,
            }
            : new MrzInfo(format, raw, lines)
            {
                IssuingState = lines[0].Substring(2, 3),
                DocumentNumber = lines[1][..9],
                DateOfBirth = lines[1].Substring(13, 6),
                DateOfExpiry = lines[1].Substring(21, 6),
                Nationality = lines[1].Substring(10, 3),
                Sex = lines[1][20],
                PrimaryIdentifier = primary,
                SecondaryIdentifier = secondary,
            };
    }

    /// <summary>
    /// Rebuilds the BAC key from this MRZ, for cross-checking a key derived from
    /// operator-typed fields against what the chip actually holds.
    /// </summary>
    public MrzKey ToKey() => MrzKey.Create(
        DocumentNumber.TrimEnd(MrzKey.Filler),
        DateOfBirth,
        DateOfExpiry);
}
