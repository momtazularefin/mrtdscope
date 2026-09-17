using PCSC;

namespace MRTDScope.Pcsc;

/// <summary>
/// Discovers PC/SC readers and picks the one to use.
/// </summary>
/// <remarks>
/// Reader choice is environment-driven with a sensible default (NFR6). The code this
/// harvests from carried a hard-coded array of two OMNIKEY product names and an index,
/// which made the build machine-specific.
/// </remarks>
public static class PcscReaderResolver
{
    /// <summary>
    /// Environment variable holding a case-insensitive substring of the reader name.
    /// </summary>
    public const string ReaderEnvironmentVariable = "MRTDSCOPE_READER";

    /// <summary>
    /// Name fragments that identify a contactless interface.
    /// </summary>
    /// <remarks>
    /// A single physical reader commonly exposes two PC/SC names — one per interface —
    /// and they sort with the contact interface first, so taking the first reader picks
    /// the wrong one. An eMRTD is an ISO/IEC 14443 contactless document, so the contact
    /// interface can never read it: it reports a card removal because its own slot is
    /// genuinely empty, which is a confusing way to learn you chose the wrong interface.
    /// <para>
    /// These markers cover the common vendor conventions: OMNIKEY appends "-CL", ACS uses
    /// "PICC Interface", Identiv and others spell out "Contactless".
    /// </para>
    /// </remarks>
    private static readonly string[] ContactlessMarkers =
        ["-CL", " CL ", "CL0", "PICC", "CONTACTLESS", "NFC", "RFID"];

    /// <summary>Lists every reader the PC/SC subsystem currently reports.</summary>
    public static IReadOnlyList<string> ListReaders() =>
        ListReaders(static () =>
        {
            using ISCardContext context = ContextFactory.Instance.Establish(SCardScope.System);
            return context.GetReaders() ?? [];
        });

    /// <summary>
    /// Runs a reader enumeration, treating an absent PC/SC subsystem as no readers.
    /// </summary>
    /// <remarks>
    /// "No smart-card service here" arrives in two shapes. With the service installed but
    /// stopped, the library raises a <see cref="PCSC.Exceptions.PCSCException"/>. With the
    /// native library missing altogether — any Linux machine without <c>libpcsclite</c>,
    /// including the CI runner — the call fails to bind and raises
    /// <see cref="DllNotFoundException"/>, possibly wrapped in a type initializer. Only the
    /// first shape was handled, so the desktop window threw while listing readers and could
    /// not even open a synthetic demo, which needs no reader at all. It surfaced as six
    /// failing desktop tests on Ubuntu and green on Windows, where the library always ships.
    /// </remarks>
    internal static IReadOnlyList<string> ListReaders(Func<IReadOnlyList<string>> enumerate)
    {
        ArgumentNullException.ThrowIfNull(enumerate);

        try
        {
            return enumerate();
        }
        catch (Exception exception) when (IsSubsystemAbsent(exception))
        {
            // No smart-card service, or no reader subsystem on this machine. An empty
            // list is the honest answer; it is not an error worth propagating.
            return [];
        }
    }

    private static bool IsSubsystemAbsent(Exception exception) => exception switch
    {
        PCSC.Exceptions.PCSCException => true,
        DllNotFoundException => true,
        TypeInitializationException { InnerException: DllNotFoundException } => true,
        _ => false,
    };

    /// <summary>
    /// Whether a reader name looks like a contactless interface.
    /// </summary>
    public static bool LooksContactless(string readerName)
    {
        ArgumentNullException.ThrowIfNull(readerName);

        string upper = readerName.ToUpperInvariant();

        return ContactlessMarkers.Any(marker => upper.Contains(marker, StringComparison.Ordinal))
            || upper.EndsWith("CL", StringComparison.Ordinal);
    }

    /// <summary>
    /// Chooses a reader from a known list. Pure, so the preference order is testable
    /// without a reader attached.
    /// </summary>
    /// <param name="readers">Available reader names.</param>
    /// <param name="preferred">
    /// A case-insensitive substring the caller requires. When supplied and nothing
    /// matches, the result is <c>null</c> rather than a silent fallback — an operator who
    /// named a reader wants that reader, not whichever one happened to be first.
    /// </param>
    public static string? SelectPreferred(IReadOnlyList<string> readers, string? preferred = null)
    {
        ArgumentNullException.ThrowIfNull(readers);

        if (readers.Count == 0)
        {
            return null;
        }

        if (!string.IsNullOrWhiteSpace(preferred))
        {
            return readers.FirstOrDefault(
                reader => reader.Contains(preferred, StringComparison.OrdinalIgnoreCase));
        }

        // No explicit preference: a contactless interface is the only one that can read
        // an eMRTD, so prefer it over whatever sorts first.
        return readers.FirstOrDefault(LooksContactless) ?? readers[0];
    }

    /// <summary>
    /// Picks a reader: the one matching <paramref name="preferredName"/> or the
    /// <c>MRTDSCOPE_READER</c> environment variable, otherwise a contactless interface,
    /// otherwise the first available.
    /// </summary>
    /// <returns>The reader name, or <c>null</c> when none is available or matches.</returns>
    public static string? Resolve(string? preferredName = null)
    {
        string? wanted = preferredName
            ?? Environment.GetEnvironmentVariable(ReaderEnvironmentVariable);

        return SelectPreferred(ListReaders(), wanted);
    }
}
