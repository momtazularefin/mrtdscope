using System.Collections.ObjectModel;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.Headless.XUnit;
using MRTDScope.Core.Inspection;
using MRTDScope.Core.Verification;
using MRTDScope.Desktop;
using MRTDScope.Desktop.Tests;
using MRTDScope.Synthetic;

[assembly: AvaloniaTestApplication(typeof(TestAppBuilder))]

namespace MRTDScope.Desktop.Tests;

/// <summary>Hosts the real <see cref="App"/> on Avalonia's headless platform.</summary>
public static class TestAppBuilder
{
    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>().UseHeadless(new AvaloniaHeadlessPlatformOptions());
}

/// <summary>
/// Proves the desktop window actually constructs and renders a report.
/// </summary>
/// <remarks>
/// A XAML file that compiles is not a window that opens. Compiled bindings are resolved
/// at load time, a mistyped <c>x:Name</c> becomes a null field, and both fail only when
/// the window is first shown — which, without these tests, would be on the machine of
/// whoever opened the application first.
/// <para>
/// The inspection driven here is synthetic, so the whole surface is exercised with no
/// reader, no chip, and no real document (NFR3).
/// </para>
/// </remarks>
public sealed class DesktopSurfaceTests
{
    private static InspectionOutcome InspectSynthetic(DocumentFault fault = DocumentFault.None)
    {
        using SyntheticChip chip = SyntheticDocument.Build()
            .WithFault(fault)
            .WithActiveAuthentication()
            .CreateChip();

        chip.Connect();

        return new InspectionSession(new TrustStore([chip.Document.Csca]))
            .Inspect(chip, chip.Document.MrzKey);
    }

    [AvaloniaFact]
    public void TheWindowConstructsAndShows()
    {
        MainWindow window = new();
        window.Show();

        Assert.Equal("MRTDScope", window.Title);
    }

    /// <summary>
    /// Every check the report carries reaches the list. A surface that silently dropped a
    /// failing check would be worse than no surface at all.
    /// </summary>
    [AvaloniaFact]
    public void EveryCheckInTheReportReachesTheList()
    {
        MainWindow window = new();
        window.Show();

        InspectionOutcome outcome = InspectSynthetic();
        window.Render(outcome, tracer: null);

        ObservableCollection<CheckRow> rows =
            Assert.IsType<ObservableCollection<CheckRow>>(window.ChecksList.ItemsSource);

        Assert.Equal(outcome.Report.Checks.Count, rows.Count);
        Assert.Equal([.. outcome.Report.Checks.Select(check => check.Id)], rows.Select(row => row.Id));
    }

    /// <summary>
    /// The failing check is visibly a failure, and the summary does not hide it.
    /// </summary>
    [AvaloniaFact]
    public void ATamperedDataGroupIsShownAsAFailure()
    {
        MainWindow window = new();
        window.Show();

        InspectionOutcome outcome = InspectSynthetic(DocumentFault.TamperedDataGroup);
        window.Render(outcome, tracer: null);

        ObservableCollection<CheckRow> rows = (ObservableCollection<CheckRow>)window.ChecksList.ItemsSource!;
        CheckRow hashes = rows.Single(row => row.Id == CheckIds.PassiveAuthDataGroupHashes);

        Assert.Equal("FAIL", hashes.Badge);
        Assert.Equal(ReasonCodes.HashMismatch, hashes.Reason);
        Assert.Contains("DG2: MISMATCH", hashes.Evidence, StringComparison.Ordinal);

        Assert.Contains("1 failed", window.SummaryText.Text, StringComparison.Ordinal);
    }

    /// <summary>
    /// Export stays disabled until there is something to export, and the portrait button
    /// tracks whether a portrait was actually read rather than whether one was expected.
    /// </summary>
    [AvaloniaFact]
    public void ExportsUnlockOnlyForWhatWasActuallyRead()
    {
        MainWindow window = new();
        window.Show();

        Assert.False(window.ExportReportButton.IsEnabled);
        Assert.False(window.ExportPortraitButton.IsEnabled);

        InspectionOutcome outcome = InspectSynthetic();
        window.Render(outcome, tracer: null);

        Assert.True(window.ExportReportButton.IsEnabled);
        Assert.Equal(outcome.Portrait is not null, window.ExportPortraitButton.IsEnabled);

        // No trace is captured for a synthetic run, so there is nothing to write.
        Assert.False(window.ExportTraceButton.IsEnabled);
    }

    /// <summary>
    /// Choosing the synthetic source hides the MRZ fields, because a synthetic document
    /// carries its own key and typing one would suggest it were used.
    /// </summary>
    [AvaloniaFact]
    public void ChoosingASyntheticDocumentHidesTheMrzFields()
    {
        MainWindow window = new();
        window.Show();

        Assert.True(window.MrzPanel.IsVisible);
        Assert.False(window.SyntheticPanel.IsVisible);

        window.SyntheticSourceOption.IsChecked = true;

        Assert.False(window.MrzPanel.IsVisible);
        Assert.True(window.SyntheticPanel.IsVisible);
    }

    /// <summary>
    /// DG1 reaches the document tab as the holder's name rather than as raw MRZ only.
    /// </summary>
    [AvaloniaFact]
    public void TheDocumentTabShowsTheHolderAndTheStoredMrz()
    {
        MainWindow window = new();
        window.Show();

        InspectionOutcome outcome = InspectSynthetic();
        window.Render(outcome, tracer: null);

        Assert.Equal(outcome.Mrz!.HolderName, window.HolderNameText.Text);
        Assert.Contains(outcome.Mrz.Lines[0], window.MrzText.Text!, StringComparison.Ordinal);
    }
}
