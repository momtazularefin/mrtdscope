using System.Text.Json;
using System.Text.Json.Serialization;
using MRTDScope.Core.Inspection;
using MRTDScope.Core.Verification;
using MRTDScope.Pcsc;
using MRTDScope.Synthetic;

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

            case "--trust":
                return ShowTrust(args.Length > 1 ? args[1] : null);

            case "--demo":
                return Demo(
                    args.Length > 1 && !args[1].StartsWith("--", StringComparison.Ordinal)
                        ? args[1]
                        : null,
                    args.Contains("--pace"));

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
        Console.WriteLine("  --demo [fault] [--pace]");
        Console.WriteLine("                  Inspect a synthetic document and print its report.");
        Console.WriteLine("  --trust [dir]   Validate a CSCA trust-anchor directory.");
        Console.WriteLine("  --help, -h      Show this help.");
        Console.WriteLine();
        Console.WriteLine("Faults for --demo: " + string.Join(", ", Enum.GetNames<DocumentFault>()));
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
            string marker = reader == selected ? "*" : " ";
            string kind = PcscReaderResolver.LooksContactless(reader) ? "contactless" : "contact";
            Console.WriteLine($"{marker} {reader}  [{kind}]");
        }

        Console.WriteLine();
        Console.WriteLine(
            "* marks the reader that will be used. An eMRTD is a contactless document, " +
            "so a contact interface cannot read it.");
        Console.WriteLine(
            $"Override with {PcscReaderResolver.ReaderEnvironmentVariable}=<name substring>.");

        return 0;
    }

    /// <summary>
    /// Loads a trust-anchor directory and reports what it actually parsed.
    /// </summary>
    /// <remarks>
    /// MRTDScope ships no CSCA certificates and no master list (D005): trust material is
    /// operator-supplied, typically extracted from the ICAO PKD. That makes "did my
    /// anchors actually load?" a real question worth answering before an inspection,
    /// rather than discovering mid-read that a directory of certificates yielded nothing.
    /// </remarks>
    private static int ShowTrust(string? directory)
    {
        directory ??= Environment.GetEnvironmentVariable("MRTDSCOPE_TRUST_DIR");

        if (string.IsNullOrWhiteSpace(directory))
        {
            Console.Error.WriteLine(
                "Supply a directory, or set MRTDSCOPE_TRUST_DIR. MRTDScope ships no trust " +
                "anchors; they are operator-supplied.");
            return 2;
        }

        if (!Directory.Exists(directory))
        {
            Console.Error.WriteLine($"No such directory: {directory}");
            return 2;
        }

        int files = Directory.EnumerateFiles(directory).Count();

        TrustStore trust = new();
        int loaded = trust.LoadDirectory(directory);

        Console.WriteLine($"{directory}");
        Console.WriteLine($"{files} file(s), {loaded} distinct trust anchor(s) loaded.");
        Console.WriteLine();

        DateTime now = DateTime.UtcNow;

        foreach (var anchor in trust.Anchors.OrderBy(a => a.SubjectDN.ToString(), StringComparer.Ordinal))
        {
            bool current = anchor.NotBefore <= now && anchor.NotAfter >= now;
            Console.WriteLine($"  {(current ? "valid  " : "expired")}  {anchor.SubjectDN}");
            Console.WriteLine($"           {anchor.NotBefore:yyyy-MM-dd} to {anchor.NotAfter:yyyy-MM-dd}");
        }

        if (loaded == 0)
        {
            Console.Error.WriteLine();
            Console.Error.WriteLine(
                "No anchors parsed. Files that are not X.509 certificates are skipped, " +
                "so a directory of CRLs or archives yields nothing.");
            return 1;
        }

        return 0;
    }

    /// <summary>
    /// Runs a full inspection against a synthetic document and prints the report.
    /// </summary>
    /// <remarks>
    /// This is the whole chain — SELECT, BAC, secure messaging, chunked LDS reads,
    /// Passive Authentication — with no reader and no real document. Passing a fault name
    /// shows what the report looks like when a document is wrong, which is the part worth
    /// seeing.
    /// </remarks>
    private static int Demo(string? faultName, bool pace = false)
    {
        DocumentFault fault = DocumentFault.None;

        if (faultName is not null && !Enum.TryParse(faultName, ignoreCase: true, out fault))
        {
            Console.Error.WriteLine(
                $"Unknown fault '{faultName}'. Known faults: " +
                string.Join(", ", Enum.GetNames<DocumentFault>()));
            return 2;
        }

        SyntheticDocumentBuilder builder = SyntheticDocument.Build().WithFault(fault);

        if (pace)
        {
            builder = builder.AdvertisingPace();
        }

        using SyntheticChip chip = builder.CreateChip();
        chip.Connect();

        InspectionOutcome outcome = new InspectionSession(new TrustStore([chip.Document.Csca]))
            .Inspect(chip, chip.Document.MrzKey);

        Console.Error.WriteLine(
            $"Synthetic document, fault: {fault}, access control: " +
            $"{(chip.UsedPace ? "PACE" : "BAC")}. " +
            $"{chip.CommandsProcessed} APDUs exchanged, no hardware involved.");
        Console.WriteLine(outcome.Report.ToDeterministicJson());

        return outcome.Report.HasFailure ? 1 : 0;
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
        new("lds.parsing", true,
            "EF.COM, EF.SOD, DG1 (TD1/TD2/TD3), and DG2 portraits (ISO/IEC 19794-5, " +
            "JPEG and JPEG 2000)."),
        new("passive-auth.sod-signature", true,
            "CMS signature over the LDS Security Object, verified independently of " +
            "certificate validity."),
        new("passive-auth.document-signer-chain", true,
            "Document Signer chained to an operator-supplied CSCA. Absent anchor is " +
            "reported inconclusive, never as a failure."),
        new("passive-auth.data-group-hashes", true,
            "Every data group read is hashed against the signed security object and " +
            "reported per group. This is the check that detects a substituted portrait."),
        new("lds.com-sod-consistency", true,
            "EF.COM's advertised data groups compared against what the security object " +
            "protects, catching content the issuer never signed."),
        new("synthetic-chip", true,
            "An in-process eMRTD at the transport boundary, with a fault corpus proving " +
            "each forgery class is detected. Run with --demo."),
        new("access-control.pace", true,
            "PACE with Generic Mapping over elliptic curves, AES-128/192/256, preferred " +
            "over BAC whenever the chip advertises an executable variant."),
        new("secure-messaging.aes", true,
            "AES-CBC with AES-CMAC and a counter-derived IV, as established by PACE."),
        new("active-auth", false, "Lands at M5."),
        new("chip-auth", false, "Lands at M5."),
        new("transport.android-nfc", false, "Lands at M6."),
        new("terminal-auth", false,
            "Never. MRTDScope holds no Inspection System certificate chain, so Extended " +
            "Access Control cannot be performed. This is a permanent boundary."),
    ];
}
