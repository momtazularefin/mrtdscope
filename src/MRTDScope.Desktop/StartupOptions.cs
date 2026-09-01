using MRTDScope.Synthetic;

namespace MRTDScope.Desktop;

/// <summary>
/// What the application was asked to do before any window existed.
/// </summary>
/// <remarks>
/// Only demo mode, which opens straight onto a synthetic document and inspects it without
/// waiting to be driven. It exists so the application can be shown, taught with and
/// screenshotted from a single command, with no reader and no real passport — which is
/// also what keeps the published screenshots free of any genuine document (NFR3).
/// </remarks>
internal static class StartupOptions
{
    /// <summary>The fault to inject, when the application was started in demo mode.</summary>
    public static DocumentFault? Demo { get; private set; }

    /// <summary>Whether the demo document should also offer PACE, Chip and Active Authentication.</summary>
    public static bool Rich { get; private set; }

    /// <summary>
    /// Reads the command line. Returns false when the arguments were not usable, having
    /// already explained why.
    /// </summary>
    public static bool TryParse(string[] args)
    {
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--demo":
                    DocumentFault fault = DocumentFault.None;

                    if (i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal))
                    {
                        string name = args[++i];

                        if (!Enum.TryParse(name, ignoreCase: true, out fault))
                        {
                            Console.Error.WriteLine(
                                $"Unknown fault '{name}'. Known faults: " +
                                string.Join(", ", Enum.GetNames<DocumentFault>()));
                            return false;
                        }
                    }

                    Demo = fault;
                    break;

                case "--rich":
                    Rich = true;
                    break;

                case "--help" or "-h":
                    Console.WriteLine("mrtdscope-desktop [--demo [fault]] [--rich]");
                    Console.WriteLine();
                    Console.WriteLine("  --demo [fault]  Open on a synthetic document and inspect it immediately.");
                    Console.WriteLine("  --rich          Give the demo document PACE, Chip and Active Authentication.");
                    Console.WriteLine();
                    Console.WriteLine("Faults: " + string.Join(", ", Enum.GetNames<DocumentFault>()));
                    return false;

                default:
                    Console.Error.WriteLine($"Unknown argument '{args[i]}'. Try --help.");
                    return false;
            }
        }

        return true;
    }
}
