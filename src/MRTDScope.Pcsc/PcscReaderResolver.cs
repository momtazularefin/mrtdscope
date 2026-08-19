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

    /// <summary>Lists every reader the PC/SC subsystem currently reports.</summary>
    public static IReadOnlyList<string> ListReaders()
    {
        try
        {
            using ISCardContext context = ContextFactory.Instance.Establish(SCardScope.System);
            return context.GetReaders() ?? [];
        }
        catch (PCSC.Exceptions.PCSCException)
        {
            // No smart-card service, or no reader subsystem on this machine. An empty
            // list is the honest answer; it is not an error worth propagating.
            return [];
        }
    }

    /// <summary>
    /// Picks a reader: the one matching <paramref name="preferredName"/> or the
    /// <c>MRTDSCOPE_READER</c> environment variable, otherwise the first available.
    /// </summary>
    /// <returns>The reader name, or <c>null</c> when none is available.</returns>
    public static string? Resolve(string? preferredName = null)
    {
        IReadOnlyList<string> readers = ListReaders();

        if (readers.Count == 0)
        {
            return null;
        }

        string? wanted = preferredName
            ?? Environment.GetEnvironmentVariable(ReaderEnvironmentVariable);

        if (string.IsNullOrWhiteSpace(wanted))
        {
            return readers[0];
        }

        return readers.FirstOrDefault(
            reader => reader.Contains(wanted, StringComparison.OrdinalIgnoreCase));
    }
}
