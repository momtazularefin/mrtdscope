using System.Text.Json;
using System.Text.Json.Serialization;
using MRTDScope.Pcsc;

namespace MRTDScope.Cli;

/// <summary>
/// Headless entry point (FR13).
/// </summary>
/// <remarks>
/// The full inspection command arrives with the report pipeline in M2. Until then this
/// reports what the build can actually do and what readers it can see — both true
/// statements about the current state rather than a placeholder that implies more.
/// </remarks>
internal static class Program
{
    private static int Main(string[] args)
    {
        string command = args.Length > 0 ? args[0] : "--capabilities";

        switch (command)
        {
            case "--help" or "-h":
                PrintHelp();
                return 0;

            case "--readers":
                return ListReaders();

            case "--capabilities":
                Console.WriteLine(JsonSerializer.Serialize(Capabilities(), JsonOptions));
                return 0;

            default:
                Console.Error.WriteLine($"Unknown command '{command}'.");
                PrintHelp();
                return 2;
        }
    }

    private static void PrintHelp()
    {
        Console.WriteLine("mrtdscope - eMRTD inspection instrument");
        Console.WriteLine();
        Console.WriteLine("Usage: mrtdscope [command]");
        Console.WriteLine();
        Console.WriteLine("  --capabilities  What this build implements (default).");
        Console.WriteLine("  --readers       List visible PC/SC readers.");
        Console.WriteLine("  --help, -h      Show this help.");
        Console.WriteLine();
        Console.WriteLine($"Environment: {PcscReaderResolver.ReaderEnvironmentVariable} selects a reader by name substring.");
    }

    private static int ListReaders()
    {
        IReadOnlyList<string> readers = PcscReaderResolver.ListReaders();

        if (readers.Count == 0)
        {
            Console.WriteLine("No PC/SC readers found.");
            return 1;
        }

        string? selected = PcscReaderResolver.Resolve();

        foreach (string reader in readers)
        {
            Console.WriteLine(reader == selected ? $"* {reader}" : $"  {reader}");
        }

        return 0;
    }

    /// <param name="Protocol">The protocol or capability.</param>
    /// <param name="Implemented">Whether this build performs it.</param>
    /// <param name="Note">Why not, or what it rests on.</param>
    private sealed record Capability(
        [property: JsonPropertyOrder(0)] string Protocol,
        [property: JsonPropertyOrder(1)] bool Implemented,
        [property: JsonPropertyOrder(2)] string Note);

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    /// <summary>
    /// What this build implements. Nothing here is inferred; each entry changes only when
    /// its milestone actually lands.
    /// </summary>
    private static IReadOnlyList<Capability> Capabilities() =>
    [
        new("access-control.bac", true,
            "Basic Access Control with 3DES secure messaging, verified against the ICAO " +
            "Doc 9303 Appendix D worked example."),
        new("secure-messaging.3des", true,
            "3DES-CBC with ISO/IEC 9797-1 Algorithm 3 retail MAC, all four APDU cases."),
        new("transport.pcsc", true, "PC/SC contactless readers on Windows and Linux."),
        new("access-control.pace", false, "Lands at M4."),
        new("lds.parsing", false, "Lands at M2."),
        new("passive-auth", false, "Lands at M2."),
        new("active-auth", false, "Lands at M5."),
        new("chip-auth", false, "Lands at M5."),
        new("transport.android-nfc", false, "Lands at M6."),
        new("terminal-auth", false,
            "Never. MRTDScope holds no Inspection System certificate chain, so Extended " +
            "Access Control cannot be performed. This is a permanent boundary."),
    ];
}
