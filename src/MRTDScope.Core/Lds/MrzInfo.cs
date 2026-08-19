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

        // Field positions differ by format. TD1 carries the document number on line 1,
        // where TD2 and TD3 carry it on line 2.
        return format == MrzFormat.Td1
            ? new MrzInfo(format, raw, lines)
            {
                IssuingState = lines[0].Substring(2, 3),
                DocumentNumber = lines[0].Substring(5, 9),
                DateOfBirth = lines[1][..6],
                DateOfExpiry = lines[1].Substring(8, 6),
            }
            : new MrzInfo(format, raw, lines)
            {
                IssuingState = lines[0].Substring(2, 3),
                DocumentNumber = lines[1][..9],
                DateOfBirth = lines[1].Substring(13, 6),
                DateOfExpiry = lines[1].Substring(21, 6),
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
