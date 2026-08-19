using System.Text;
using MRTDScope.Core.Errors;
using MRTDScope.Core.Tlv;

namespace MRTDScope.Core.Lds;

/// <summary>
/// EF.COM — the common data element file listing which data groups the chip claims to
/// hold (ICAO Doc 9303 Part 10 §4.6.1, Table "EF.COM Normative Tags").
/// </summary>
/// <remarks>
/// EF.COM is <b>not</b> a security artefact and must never be treated as one. It is
/// unsigned, so a chip can list anything it likes. Doc 9303 itself recommends that
/// inspection systems rely on the SOD instead.
/// <para>
/// MRTDScope reads it for one specific reason: comparing what EF.COM advertises against
/// what the SOD actually protects reveals a data group that was added or removed without
/// re-signing. That comparison is evidence; the list on its own is not.
/// </para>
/// </remarks>
public sealed class EfCom
{
    private const int TagLdsVersion = 0x5F01;
    private const int TagUnicodeVersion = 0x5F36;
    private const int TagDataGroupList = 0x5C;

    private EfCom(string? ldsVersion, string? unicodeVersion, IReadOnlyList<DataGroup> dataGroups)
    {
        LdsVersion = ldsVersion;
        UnicodeVersion = unicodeVersion;
        DataGroups = dataGroups;
    }

    /// <summary>LDS version as "aabb", or <c>null</c> when absent or unreadable.</summary>
    public string? LdsVersion { get; }

    /// <summary>Unicode version as "aabbcc", or <c>null</c>.</summary>
    public string? UnicodeVersion { get; }

    /// <summary>The data groups EF.COM claims are present, in the order listed.</summary>
    public IReadOnlyList<DataGroup> DataGroups { get; }

    /// <summary>Tags in the presence map that map to no known data group.</summary>
    public IReadOnlyList<int> UnknownTags { get; private init; } = [];

    /// <summary>Parses the raw EF.COM file content, tag 0x60 included.</summary>
    public static EfCom Parse(ReadOnlySpan<byte> fileContent)
    {
        IReadOnlyList<BerTlv> outer = BerTlv.Parse(fileContent);
        BerTlv root = BerTlv.Find(outer, DataGroup.Com.Tag)
            ?? throw new MrtdEncodingException(
                $"EF.COM must be wrapped in tag 0x{DataGroup.Com.Tag:X2}.");

        IReadOnlyList<BerTlv> elements = root.Children();

        string? ldsVersion = ReadAscii(BerTlv.Find(elements, TagLdsVersion));
        string? unicodeVersion = ReadAscii(BerTlv.Find(elements, TagUnicodeVersion));

        BerTlv? list = BerTlv.Find(elements, TagDataGroupList);

        List<DataGroup> groups = [];
        List<int> unknown = [];

        if (list is not null)
        {
            foreach (byte tag in list.Value.Span)
            {
                DataGroup? group = DataGroup.FromTag(tag);

                if (group is null)
                {
                    unknown.Add(tag);
                }
                else if (!groups.Contains(group))
                {
                    groups.Add(group);
                }
            }
        }

        return new EfCom(ldsVersion, unicodeVersion, groups) { UnknownTags = unknown };
    }

    private static string? ReadAscii(BerTlv? element)
    {
        if (element is null || element.Value.Length == 0)
        {
            return null;
        }

        return Encoding.ASCII.GetString(element.Value.Span).TrimEnd('\0', ' ');
    }
}
