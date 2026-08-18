using MRTDScope.Core.Inspection;

namespace MRTDScope.Cli;

/// <summary>
/// Headless inspection entry point (FR13).
/// </summary>
/// <remarks>
/// At M0 this reports the build's capability posture rather than reading a document.
/// Every protocol path is declared <see cref="CheckStatus.Unavailable"/> until the
/// milestone that implements it lands, which is the honest description of a scaffold
/// and the first demonstration of D003: nothing here claims to have verified anything.
/// </remarks>
internal static class Program
{
    private static int Main(string[] args)
    {
        if (args.Length > 0 && (args[0] == "--help" || args[0] == "-h"))
        {
            Console.WriteLine("mrtdscope - eMRTD inspection instrument");
            Console.WriteLine();
            Console.WriteLine("Usage: mrtdscope [--capabilities]");
            Console.WriteLine();
            Console.WriteLine("  --capabilities  Print this build's capability posture as a report.");
            Console.WriteLine("  --help, -h      Show this help.");
            return 0;
        }

        InspectionReport report = InspectionReport.Create(CapabilityPosture());
        Console.WriteLine(report.ToDeterministicJson());
        return report.HasFailure ? 1 : 0;
    }

    /// <summary>
    /// The checks this build can perform, and the reason for each it cannot.
    /// </summary>
    private static IEnumerable<InspectionCheck> CapabilityPosture()
    {
        yield return InspectionCheck.Unavailable(
            CheckIds.AccessControlBac,
            ReasonCodes.NotImplemented,
            "Basic Access Control lands at M1.");

        yield return InspectionCheck.Unavailable(
            CheckIds.AccessControlPace,
            ReasonCodes.NotImplemented,
            "PACE lands at M4.");

        yield return InspectionCheck.Unavailable(
            CheckIds.PassiveAuthSodSignature,
            ReasonCodes.NotImplemented,
            "Passive Authentication lands at M2.");

        yield return InspectionCheck.Unavailable(
            CheckIds.PassiveAuthDocumentSignerChain,
            ReasonCodes.NotImplemented,
            "Passive Authentication lands at M2.");

        yield return InspectionCheck.Unavailable(
            CheckIds.PassiveAuthDataGroupHashes,
            ReasonCodes.NotImplemented,
            "Passive Authentication lands at M2.");

        yield return InspectionCheck.Unavailable(
            CheckIds.ActiveAuth,
            ReasonCodes.NotImplemented,
            "Active Authentication lands at M5.");

        yield return InspectionCheck.Unavailable(
            CheckIds.ChipAuth,
            ReasonCodes.NotImplemented,
            "Chip Authentication lands at M5.");

        yield return InspectionCheck.Unavailable(
            CheckIds.TerminalAuth,
            ReasonCodes.CredentialsNotHeld,
            "MRTDScope holds no Inspection System certificate chain and cannot perform " +
            "Terminal Authentication. This is a permanent boundary, not a pending feature (D008).");
    }
}
