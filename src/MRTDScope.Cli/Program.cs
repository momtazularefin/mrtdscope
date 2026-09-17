using System.Text.Json;
using System.Text.Json.Serialization;
using MRTDScope.Core.Errors;
using MRTDScope.Core.Inspection;
using MRTDScope.Core.Mrz;
using MRTDScope.Core.Transport;
using MRTDScope.Core.Verification;
using MRTDScope.Pcsc;
using MRTDScope.Synthetic;

namespace MRTDScope.Cli;

/// <summary>
/// Headless entry point (FR13).
/// </summary>
/// <remarks>
/// Exit codes are the contract for anything scripting this: <c>0</c> when the inspection
/// ran and no check failed, <c>1</c> when a check actively found the document wanting,
/// and <c>2</c> when the inspection could not be performed at all. The distinction
/// between 1 and 2 is the point — a script that cannot separate "this document failed"
/// from "no reader was attached" will eventually treat one as the other.
/// </remarks>
internal static class Program
{
    private const int ExitOk = 0;
    private const int ExitCheckFailed = 1;
    private const int ExitCouldNotRun = 2;

    private static readonly HashSet<string> ExportOptions =
        ["json", "text", "trace", "portrait"];

    private static int Main(string[] args)
    {
        string command = args.Length > 0 ? args[0] : "--capabilities";
        string[] rest = args.Length > 1 ? args[1..] : [];

        switch (command)
        {
            case "--help" or "-h" or "help":
                PrintHelp();
                return ExitOk;

            case "--readers" or "readers":
                return ListReaders();

            case "--trust" or "trust":
                return ShowTrust(rest.Length > 0 ? rest[0] : null);

            case "--demo" or "demo":
                return Demo(rest);

            case "inspect":
                return Inspect(rest);

            case "--capabilities" or "capabilities":
                Console.WriteLine(JsonSerializer.Serialize(Capabilities(), JsonOptions));
                return ExitOk;

            default:
                Console.Error.WriteLine($"Unknown command '{command}'.");
                PrintHelp();
                return ExitCouldNotRun;
        }
    }

    private static void PrintHelp()
    {
        Console.WriteLine("mrtdscope - eMRTD inspection instrument");
        Console.WriteLine();
        Console.WriteLine("Usage: mrtdscope <command> [options]");
        Console.WriteLine();
        Console.WriteLine("  inspect         Inspect a document on a PC/SC reader.");
        Console.WriteLine("      --doc <n> --dob <yymmdd> --doe <yymmdd>   MRZ key fields (required).");
        Console.WriteLine("      --reader <substring>   Choose a reader by name.");
        Console.WriteLine("      --trust <dir>          CSCA anchors. Absent means the chain is inconclusive.");
        Console.WriteLine("      --format text|json     What goes to stdout. Default text.");
        Console.WriteLine();
        Console.WriteLine("  demo [fault] [--pace]");
        Console.WriteLine("                  Inspect a synthetic document. No reader, no real document.");
        Console.WriteLine("  readers         List visible PC/SC readers.");
        Console.WriteLine("  trust [dir]     Validate a CSCA trust-anchor directory.");
        Console.WriteLine("  capabilities    What this build implements (default).");
        Console.WriteLine("  help            Show this help.");
        Console.WriteLine();
        Console.WriteLine("Export options, accepted by both inspect and demo:");
        Console.WriteLine("      --json <file>      The deterministic report.");
        Console.WriteLine("      --text <file>      The report rendered for a person.");
        Console.WriteLine("      --trace <file>     The APDU trace, key material redacted.");
        Console.WriteLine("      --portrait <file>  The DG2 image. The extension follows the encoding.");
        Console.WriteLine();
        Console.WriteLine("Exit codes: 0 nothing failed, 1 a check failed, 2 could not inspect.");
        Console.WriteLine();
        Console.WriteLine("Faults for demo: " + string.Join(", ", Enum.GetNames<DocumentFault>()));
        Console.WriteLine();
        Console.WriteLine($"Environment: {PcscReaderResolver.ReaderEnvironmentVariable} selects a reader " +
            "by name substring, MRTDSCOPE_TRUST_DIR supplies trust anchors.");
        Console.WriteLine(
            "Exports of a real document carry the holder's portrait and MRZ. Nothing is " +
            "written unless you name a path.");
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

        return ExitOk;
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
            return ExitCouldNotRun;
        }

        if (!Directory.Exists(directory))
        {
            Console.Error.WriteLine($"No such directory: {directory}");
            return ExitCouldNotRun;
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

        return ExitOk;
    }

    /// <summary>
    /// Inspects a physical document on a PC/SC reader.
    /// </summary>
    private static int Inspect(string[] args)
    {
        HashSet<string> values =
            ["doc", "dob", "doe", "reader", "trust", "format", .. ExportOptions];

        CommandLine? parsed = CommandLine.TryParse(args, values, [], out string error);

        if (parsed is null)
        {
            Console.Error.WriteLine(error);
            return ExitCouldNotRun;
        }

        string? documentNumber = parsed.Value("doc");
        string? dateOfBirth = parsed.Value("dob");
        string? dateOfExpiry = parsed.Value("doe");

        if (documentNumber is null || dateOfBirth is null || dateOfExpiry is null)
        {
            Console.Error.WriteLine(
                "inspect needs --doc, --dob and --doe, exactly as printed in the machine " +
                "readable zone. These derive the access key; the chip stays locked without them.");
            return ExitCouldNotRun;
        }

        string format = parsed.Value("format") ?? "text";

        if (format is not ("text" or "json"))
        {
            Console.Error.WriteLine($"--format must be 'text' or 'json', not '{format}'.");
            return ExitCouldNotRun;
        }

        MrzKey key;
        try
        {
            key = MrzKey.Create(documentNumber, dateOfBirth, dateOfExpiry);
        }
        catch (ArgumentException exception)
        {
            Console.Error.WriteLine(exception.Message);
            return ExitCouldNotRun;
        }

        string? reader = PcscReaderResolver.Resolve(parsed.Value("reader"));

        if (reader is null)
        {
            Console.Error.WriteLine(
                "No PC/SC reader found. Run 'mrtdscope readers' to see what is visible.");
            return ExitCouldNotRun;
        }

        TrustStore trust = LoadTrust(parsed.Value("trust"));
        ApduTracer tracer = new();

        try
        {
            using PcscCardTransport pcsc = new(reader, tracer);
            using ResilientTransport transport = new(pcsc, TransportResilience.Wired);

            transport.Connect();

            Console.Error.WriteLine($"Reader: {reader}");

            InspectionOutcome outcome = new InspectionSession(trust).Inspect(transport, key);

            return Emit(outcome, parsed, tracer, format, outcome.Report.ElapsedMilliseconds);
        }
        catch (CardTransportException exception)
        {
            Console.Error.WriteLine($"Could not read the document: {exception.Message}");
            return ExitCouldNotRun;
        }
    }

    /// <summary>
    /// Runs a full inspection against a synthetic document and prints the report.
    /// </summary>
    /// <remarks>
    /// This is the whole chain — SELECT, access control, secure messaging, chunked LDS
    /// reads, Passive Authentication — with no reader and no real document. Passing a
    /// fault name shows what the report looks like when a document is wrong, which is the
    /// part worth seeing.
    /// </remarks>
    private static int Demo(string[] args)
    {
        CommandLine? parsed = CommandLine.TryParse(
            args, [.. ExportOptions, "format"], ["pace"], out string error);

        if (parsed is null)
        {
            Console.Error.WriteLine(error);
            return ExitCouldNotRun;
        }

        string? faultName = parsed.Positional.Count > 0 ? parsed.Positional[0] : null;
        DocumentFault fault = DocumentFault.None;

        if (faultName is not null && !Enum.TryParse(faultName, ignoreCase: true, out fault))
        {
            Console.Error.WriteLine(
                $"Unknown fault '{faultName}'. Known faults: " +
                string.Join(", ", Enum.GetNames<DocumentFault>()));
            return ExitCouldNotRun;
        }

        SyntheticDocumentBuilder builder = SyntheticDocument.Build().WithFault(fault);

        if (parsed.Has("pace"))
        {
            builder = builder.AdvertisingPace().WithActiveAuthentication().WithChipAuthentication();
        }

        using SyntheticChip chip = builder.CreateChip();
        chip.Connect();

        InspectionOutcome outcome = new InspectionSession(new TrustStore([chip.Document.Csca]))
            .Inspect(chip, chip.Document.MrzKey);

        Console.Error.WriteLine(
            $"Synthetic document, fault: {fault}, access control: " +
            $"{(chip.UsedPace ? "PACE" : "BAC")}. " +
            $"{chip.CommandsProcessed} APDUs exchanged, no hardware involved.");

        return Emit(outcome, parsed, tracer: null, parsed.Value("format") ?? "json", elapsed: null);
    }

    /// <summary>
    /// Prints the report and writes whatever exports were requested.
    /// </summary>
    private static int Emit(
        InspectionOutcome outcome,
        CommandLine parsed,
        ApduTracer? tracer,
        string format,
        long? elapsed)
    {
        Console.WriteLine(format == "json"
            ? outcome.Report.ToDeterministicJson()
            : ReportFormatter.ToText(outcome.Report));

        if (format == "text" && outcome.Mrz is { } mrz)
        {
            Console.WriteLine($"Holder:   {mrz.HolderName}");
            Console.WriteLine($"Document: {mrz.DocumentNumber.TrimEnd('<')} ({mrz.IssuingState})");
            Console.WriteLine();
        }

        if (elapsed is { } milliseconds)
        {
            Console.Error.WriteLine($"Completed in {milliseconds} ms.");
        }

        ExportTargets targets = new(
            parsed.Value("json"),
            parsed.Value("text"),
            parsed.Value("trace"),
            parsed.Value("portrait"));

        if (targets.Any)
        {
            foreach (string path in ReportExport.Write(outcome, targets, tracer))
            {
                Console.Error.WriteLine($"Wrote {path}");
            }

            if (targets.Portrait is not null && outcome.Portrait is null)
            {
                Console.Error.WriteLine("No portrait was read, so none was written.");
            }

            if (targets.Trace is not null && tracer is null)
            {
                Console.Error.WriteLine("A synthetic run captures no APDU trace to write.");
            }
        }

        return outcome.Report.HasFailure ? ExitCheckFailed : ExitOk;
    }

    private static TrustStore LoadTrust(string? directory)
    {
        directory ??= Environment.GetEnvironmentVariable("MRTDSCOPE_TRUST_DIR");

        if (string.IsNullOrWhiteSpace(directory))
        {
            Console.Error.WriteLine(
                "No trust anchors supplied, so the Document Signer chain will be reported " +
                "inconclusive. Pass --trust <dir> to change that.");
            return new TrustStore();
        }

        TrustStore trust = new();
        int loaded = trust.LoadDirectory(directory);
        Console.Error.WriteLine($"Trust anchors: {loaded} loaded from {directory}");

        return trust;
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
            "each forgery class is detected. Run with 'demo'."),
        new("access-control.pace", true,
            "PACE with Generic Mapping over elliptic curves, AES-128/192/256, preferred " +
            "over BAC whenever the chip advertises an executable variant."),
        new("secure-messaging.aes", true,
            "AES-CBC with AES-CMAC and a counter-derived IV, as established by PACE."),
        new("active-auth", true,
            "ISO/IEC 9796-2 Digital Signature Scheme 1 with message recovery (RSA) and " +
            "plain-format ECDSA, binding the chip's response to the terminal's nonce."),
        new("chip-auth", true,
            "Ephemeral-static ECDH against the signed DG14 key, restarting secure " +
            "messaging on fresh session keys."),
        new("transport.android-nfc", true,
            "Android NFC over ISO-DEP, with retry and tag-loss policy in Core. Verified " +
            "against a genuine passport on a handset: PACE, Passive, Chip and Active " +
            "Authentication, with the certificate chain inconclusive for want of " +
            "on-device trust anchors."),
        new("terminal-auth", false,
            "Never. MRTDScope holds no Inspection System certificate chain, so Extended " +
            "Access Control cannot be performed. This is a permanent boundary."),
    ];
}
