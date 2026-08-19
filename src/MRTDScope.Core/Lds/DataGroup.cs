namespace MRTDScope.Core.Lds;

/// <summary>
/// An LDS1 elementary file: its data-group number, BER tag, and file identifier.
/// </summary>
/// <remarks>
/// Values from ICAO Doc 9303 Part 10 §4.7, Table "LDS1 eMRTD Application Files".
/// </remarks>
public sealed record DataGroup(int Number, string Name, int Tag, ushort FileId)
{
    public static readonly DataGroup Com = new(0, "EF.COM", 0x60, 0x011E);
    public static readonly DataGroup Sod = new(0, "EF.SOD", 0x77, 0x011D);
    public static readonly DataGroup CardAccess = new(0, "EF.CardAccess", 0x00, 0x011C);

    public static readonly DataGroup Dg1 = new(1, "EF.DG1", 0x61, 0x0101);
    public static readonly DataGroup Dg2 = new(2, "EF.DG2", 0x75, 0x0102);
    public static readonly DataGroup Dg3 = new(3, "EF.DG3", 0x63, 0x0103);
    public static readonly DataGroup Dg4 = new(4, "EF.DG4", 0x76, 0x0104);
    public static readonly DataGroup Dg5 = new(5, "EF.DG5", 0x65, 0x0105);
    public static readonly DataGroup Dg6 = new(6, "EF.DG6", 0x66, 0x0106);
    public static readonly DataGroup Dg7 = new(7, "EF.DG7", 0x67, 0x0107);
    public static readonly DataGroup Dg8 = new(8, "EF.DG8", 0x68, 0x0108);
    public static readonly DataGroup Dg9 = new(9, "EF.DG9", 0x69, 0x0109);
    public static readonly DataGroup Dg10 = new(10, "EF.DG10", 0x6A, 0x010A);
    public static readonly DataGroup Dg11 = new(11, "EF.DG11", 0x6B, 0x010B);
    public static readonly DataGroup Dg12 = new(12, "EF.DG12", 0x6C, 0x010C);
    public static readonly DataGroup Dg13 = new(13, "EF.DG13", 0x6D, 0x010D);
    public static readonly DataGroup Dg14 = new(14, "EF.DG14", 0x6E, 0x010E);
    public static readonly DataGroup Dg15 = new(15, "EF.DG15", 0x6F, 0x010F);
    public static readonly DataGroup Dg16 = new(16, "EF.DG16", 0x70, 0x0110);

    /// <summary>Every numbered data group, DG1 through DG16.</summary>
    public static IReadOnlyList<DataGroup> All { get; } =
    [
        Dg1, Dg2, Dg3, Dg4, Dg5, Dg6, Dg7, Dg8,
        Dg9, Dg10, Dg11, Dg12, Dg13, Dg14, Dg15, Dg16,
    ];

    /// <summary>
    /// Data groups protected by Extended Access Control, which MRTDScope never reads (D008).
    /// </summary>
    public static IReadOnlySet<int> ExtendedAccessControlProtected { get; } =
        new HashSet<int> { 3, 4 };

    /// <summary>Whether reading this group requires a terminal certificate chain.</summary>
    public bool RequiresExtendedAccessControl =>
        ExtendedAccessControlProtected.Contains(Number);

    /// <summary>Looks up a data group by its number, or <c>null</c> if out of range.</summary>
    public static DataGroup? FromNumber(int number) =>
        All.FirstOrDefault(group => group.Number == number);

    /// <summary>
    /// Looks up a data group by the BER tag EF.COM lists it under, or <c>null</c>.
    /// </summary>
    public static DataGroup? FromTag(int tag) =>
        All.FirstOrDefault(group => group.Tag == tag);

    public override string ToString() => Name;
}
