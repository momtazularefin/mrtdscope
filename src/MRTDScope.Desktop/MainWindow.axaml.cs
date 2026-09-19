using System.Collections.ObjectModel;
using Avalonia.Controls;
using Avalonia.Media.Imaging;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using MRTDScope.Core.Errors;
using MRTDScope.Core.Inspection;
using MRTDScope.Core.Lds;
using MRTDScope.Core.Mrz;
using MRTDScope.Core.Transport;
using MRTDScope.Core.Verification;
using MRTDScope.Pcsc;
using MRTDScope.Synthetic;

namespace MRTDScope.Desktop;

/// <summary>
/// The desktop inspection surface.
/// </summary>
/// <remarks>
/// Code-behind rather than an MVVM framework. The window has one job — collect three
/// fields, run an inspection off the UI thread, and render the report it returns — and a
/// view-model layer over that would be indirection without a second consumer to justify
/// it. Everything worth testing already lives in <c>MRTDScope.Core</c> and is tested
/// there.
/// </remarks>
public partial class MainWindow : Window
{
    private readonly ObservableCollection<CheckRow> _rows = [];

    private InspectionOutcome? _outcome;
    private ApduTracer? _tracer;

    public MainWindow()
    {
        InitializeComponent();

        ChecksList.ItemsSource = _rows;

        FaultBox.ItemsSource = Enum.GetValues<DocumentFault>();
        FaultBox.SelectedIndex = 0;

        ReaderSourceOption.IsCheckedChanged += (_, _) => UpdateSourceVisibility();
        RefreshReadersButton.Click += (_, _) => RefreshReaders();
        BrowseTrustButton.Click += async (_, _) => await BrowseForTrustDirectory();
        InspectButton.Click += async (_, _) => await RunInspection();

        ExportReportButton.Click += async (_, _) => await ExportReport();
        ExportTraceButton.Click += async (_, _) => await ExportTrace();
        ExportPortraitButton.Click += async (_, _) => await ExportPortrait();

        UpdateSourceVisibility();
        RefreshReaders();

        ApplyDemoMode();
    }

    /// <summary>
    /// Opens straight onto a synthetic document and inspects it, when started with
    /// <c>--demo</c>.
    /// </summary>
    /// <remarks>
    /// The inspection is posted rather than run inline: the window is still being
    /// constructed here, and rendering a report into controls that have not been laid out
    /// yet is how a surface ends up showing half a result.
    /// </remarks>
    private void ApplyDemoMode()
    {
        if (StartupOptions.Demo is not { } fault)
        {
            return;
        }

        SyntheticSourceOption.IsChecked = true;
        SyntheticPaceOption.IsChecked = StartupOptions.Rich;
        FaultBox.SelectedItem = fault;

        Dispatcher.UIThread.Post(async () => await RunInspection());
    }

    private bool UsingSynthetic => SyntheticSourceOption.IsChecked == true;

    private void UpdateSourceVisibility()
    {
        bool synthetic = UsingSynthetic;

        ReaderPanel.IsVisible = !synthetic;
        SyntheticPanel.IsVisible = synthetic;

        // A synthetic document carries its own MRZ, so typing one would be theatre.
        MrzPanel.IsVisible = !synthetic;
    }

    private void RefreshReaders()
    {
        IReadOnlyList<string> readers = PcscReaderResolver.ListReaders();

        ReaderBox.ItemsSource = readers;

        // Nothing to choose from is a disabled control, not an enabled one showing dimmed
        // placeholder text that the user cannot read and cannot act on.
        ReaderBox.IsEnabled = readers.Count > 0;

        if (readers.Count == 0)
        {
            ReaderHint.Text =
                "No PC/SC reader is visible. Attach a contactless reader and refresh. On Linux " +
                "this also needs pcscd and libpcsclite installed. Synthetic documents need neither.";
            return;
        }

        string? preferred = PcscReaderResolver.SelectPreferred(readers);
        ReaderBox.SelectedItem = preferred ?? readers[0];

        int contactless = readers.Count(PcscReaderResolver.LooksContactless);

        // A reader with both interfaces publishes two names, and the contact one cannot
        // read a passport. Saying which was chosen is cheaper than the confusion.
        ReaderHint.Text = contactless == 0
            ? "None of these look contactless. An eMRTD cannot be read over a contact interface."
            : $"{readers.Count} reader(s), {contactless} contactless. " +
              $"Selected: {preferred ?? readers[0]}";
    }

    private async Task BrowseForTrustDirectory()
    {
        IReadOnlyList<IStorageFolder> chosen = await StorageProvider.OpenFolderPickerAsync(
            new FolderPickerOpenOptions
            {
                Title = "CSCA trust anchors",
                AllowMultiple = false,
            });

        if (chosen.Count > 0)
        {
            TrustDirectoryBox.Text = chosen[0].Path.LocalPath;
        }
    }

    private async Task RunInspection()
    {
        InspectButton.IsEnabled = false;
        Progress.IsVisible = true;
        StatusText.Text = "Inspecting…";

        _rows.Clear();
        SetExportsEnabled(false);

        bool synthetic = UsingSynthetic;
        string? reader = ReaderBox.SelectedItem as string;
        string trustDirectory = TrustDirectoryBox.Text ?? string.Empty;
        DocumentFault fault = FaultBox.SelectedItem is DocumentFault selected
            ? selected
            : DocumentFault.None;
        bool syntheticPace = SyntheticPaceOption.IsChecked == true;

        string documentNumber = DocumentNumberBox.Text ?? string.Empty;
        string dateOfBirth = DateOfBirthBox.Text ?? string.Empty;
        string dateOfExpiry = DateOfExpiryBox.Text ?? string.Empty;

        try
        {
            (InspectionOutcome outcome, ApduTracer? tracer) = await Task.Run(() => synthetic
                ? InspectSynthetic(fault, syntheticPace)
                : InspectReader(reader, documentNumber, dateOfBirth, dateOfExpiry, trustDirectory));

            _outcome = outcome;
            _tracer = tracer;

            Render(outcome, tracer);
        }
        catch (Exception exception) when (
            exception is CardTransportException
                or MrtdEncodingException
                or ArgumentException
                or InvalidOperationException)
        {
            // The message is the operator's whole diagnosis, so it is shown verbatim
            // rather than replaced with something reassuring.
            StatusText.Text = exception.Message;
            SummaryText.Text = "The inspection could not be completed.";
        }
        finally
        {
            Progress.IsVisible = false;
            InspectButton.IsEnabled = true;
        }
    }

    private static (InspectionOutcome, ApduTracer?) InspectSynthetic(DocumentFault fault, bool rich)
    {
        SyntheticDocumentBuilder builder = SyntheticDocument.Build().WithFault(fault);

        if (rich)
        {
            builder = builder.AdvertisingPace().WithActiveAuthentication().WithChipAuthentication();
        }

        using SyntheticChip chip = builder.CreateChip();
        chip.Connect();

        InspectionOutcome outcome = new InspectionSession(new TrustStore([chip.Document.Csca]))
            .Inspect(chip, chip.Document.MrzKey);

        return (outcome, null);
    }

    private static (InspectionOutcome, ApduTracer?) InspectReader(
        string? reader,
        string documentNumber,
        string dateOfBirth,
        string dateOfExpiry,
        string trustDirectory)
    {
        if (string.IsNullOrWhiteSpace(reader))
        {
            throw new InvalidOperationException(
                "No reader selected. Attach a contactless reader and press Refresh.");
        }

        MrzKey key = MrzKey.Create(documentNumber, dateOfBirth, dateOfExpiry);

        TrustStore trust = new();

        if (!string.IsNullOrWhiteSpace(trustDirectory) && Directory.Exists(trustDirectory))
        {
            trust.LoadDirectory(trustDirectory);
        }

        ApduTracer tracer = new();

        using PcscCardTransport pcsc = new(reader, tracer);
        using ResilientTransport transport = new(pcsc, TransportResilience.Wired);

        transport.Connect();

        return (new InspectionSession(trust).Inspect(transport, key), tracer);
    }

    /// <summary>
    /// Renders a completed inspection. Internal so the headless UI tests can drive
    /// the window with a synthetic outcome and assert what an operator would see.
    /// </summary>
    internal void Render(InspectionOutcome outcome, ApduTracer? tracer)
    {
        foreach (InspectionCheck check in outcome.Report.Checks)
        {
            _rows.Add(new CheckRow(check));
        }

        SummaryText.Text = ReportFormatter.Summarize(outcome.Report);
        StatusText.Text = $"Completed in {outcome.Report.ElapsedMilliseconds} ms.";

        TraceText.Text = tracer?.ToText() ?? "A synthetic run captures no APDU trace.";

        RenderDocument(outcome);

        ExportReportButton.IsEnabled = true;
        ExportTraceButton.IsEnabled = tracer is not null;
        ExportPortraitButton.IsEnabled = outcome.Portrait is not null;

        ScrollToFirstFailure();
    }

    /// <summary>
    /// Scrolls the first failing check into view.
    /// </summary>
    /// <remarks>
    /// The list stays in Doc 9303 order — reordering by severity would misrepresent the
    /// sequence the protocols actually ran in — but a failure sitting below the fold is a
    /// failure the operator has to go looking for. Checks are listed in the order they
    /// were performed, and the view opens on the one that matters.
    /// </remarks>
    private void ScrollToFirstFailure()
    {
        int index = -1;

        for (int i = 0; i < _rows.Count; i++)
        {
            if (_rows[i].Badge == "FAIL")
            {
                index = i;
                break;
            }
        }

        if (index < 0)
        {
            return;
        }

        // Posted so the containers exist: the items were added moments ago and the
        // layout pass that realises them has not run yet.
        Dispatcher.UIThread.Post(
            () => (ChecksList.ContainerFromIndex(index) as Control)?.BringIntoView(),
            DispatcherPriority.Loaded);
    }

    private void RenderDocument(InspectionOutcome outcome)
    {
        if (outcome.Mrz is { } mrz)
        {
            HolderNameText.Text = string.IsNullOrEmpty(mrz.HolderName) ? "—" : mrz.HolderName;
            DocumentSummaryText.Text =
                $"{mrz.DocumentNumber.TrimEnd(MrzKey.Filler)} · {mrz.IssuingState} · " +
                $"{mrz.Nationality} · born {mrz.DateOfBirth} · expires {mrz.DateOfExpiry}";
            MrzText.Text = string.Join(Environment.NewLine, mrz.Lines);
        }
        else
        {
            HolderNameText.Text = "—";
            DocumentSummaryText.Text = "DG1 was not read.";
            MrzText.Text = string.Empty;
        }

        PortraitImage.Source = null;

        if (outcome.Portrait is not { } portrait)
        {
            PortraitNote.Text = "No portrait read.";
            return;
        }

        try
        {
            using MemoryStream stream = new(portrait.Data.ToArray());
            PortraitImage.Source = new Bitmap(stream);
            PortraitNote.Text =
                $"DG2, {portrait.Encoding}, {portrait.Width}×{portrait.Height}, " +
                $"{portrait.Data.Length:N0} bytes.";
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            // Many issuers store JPEG 2000, which Skia does not decode. The bytes are
            // still genuine and still exportable, so this is reported rather than hidden
            // behind a broken image.
            PortraitNote.Text =
                $"DG2 holds a {portrait.Encoding} image, {portrait.Data.Length:N0} bytes, " +
                "which this build cannot display. Export it to open it elsewhere.";
        }
    }

    private void SetExportsEnabled(bool enabled)
    {
        ExportReportButton.IsEnabled = enabled;
        ExportTraceButton.IsEnabled = enabled;
        ExportPortraitButton.IsEnabled = enabled;
    }

    private async Task ExportReport()
    {
        if (_outcome is not { } outcome)
        {
            return;
        }

        IStorageFile? file = await Save(
            "Export report",
            "mrtdscope-report.json",
            "json",
            new FilePickerFileType("JSON report") { Patterns = ["*.json"] },
            new FilePickerFileType("Text report") { Patterns = ["*.txt"] });

        if (file is null)
        {
            return;
        }

        string path = file.Path.LocalPath;
        bool json = Path.GetExtension(path).Equals(".json", StringComparison.OrdinalIgnoreCase);

        ReportExport.Write(
            outcome,
            json ? new ExportTargets(Json: path) : new ExportTargets(Text: path));

        StatusText.Text = $"Wrote {path}";
    }

    private async Task ExportTrace()
    {
        if (_outcome is not { } outcome || _tracer is not { } tracer)
        {
            return;
        }

        IStorageFile? file = await Save(
            "Export APDU trace",
            "mrtdscope-trace.txt",
            "txt",
            new FilePickerFileType("Text") { Patterns = ["*.txt"] });

        if (file is null)
        {
            return;
        }

        ReportExport.Write(outcome, new ExportTargets(Trace: file.Path.LocalPath), tracer);
        StatusText.Text = $"Wrote {file.Path.LocalPath}";
    }

    private async Task ExportPortrait()
    {
        if (_outcome is not { Portrait: { } portrait } outcome)
        {
            return;
        }

        IStorageFile? file = await Save(
            "Export portrait",
            "portrait" + portrait.FileExtension,
            portrait.FileExtension.TrimStart('.'),
            new FilePickerFileType("Portrait") { Patterns = ["*" + portrait.FileExtension] });

        if (file is null)
        {
            return;
        }

        IReadOnlyList<string> written = ReportExport.Write(
            outcome, new ExportTargets(Portrait: file.Path.LocalPath));

        StatusText.Text = written.Count > 0
            ? $"Wrote {written[0]}"
            : "Nothing was written.";
    }

    private async Task<IStorageFile?> Save(
        string title,
        string suggested,
        string defaultExtension,
        params FilePickerFileType[] types) =>
        await StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = title,
            SuggestedFileName = suggested,
            DefaultExtension = defaultExtension,
            FileTypeChoices = types,
            ShowOverwritePrompt = true,
        });
}
