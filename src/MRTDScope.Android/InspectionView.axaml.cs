using Android.Nfc;
using Avalonia.Controls;
using Avalonia.Media.Imaging;
using Avalonia.Threading;
using MRTDScope.Core.Inspection;
using MRTDScope.Core.Lds;
using MRTDScope.Core.Mrz;
using MRTDScope.Core.Transport;
using MRTDScope.Core.Verification;

namespace MRTDScope.Droid;

/// <summary>One check, flattened for display.</summary>
/// <remarks>
/// The badge text comes from <see cref="ReportFormatter"/> rather than being written
/// again here, so this surface cannot come to disagree with the CLI and the desktop
/// about what a status is called.
/// </remarks>
public sealed record CheckRow(string Badge, string Id, string Detail);

/// <summary>
/// The Android inspection surface: MRZ entry, live status, and the per-check report.
/// </summary>
/// <remarks>
/// The view deliberately shows every check with its own outcome rather than a single
/// verdict, which is the same commitment the report model makes. A phone screen is the
/// place where the temptation to collapse it into one green tick is strongest, and where
/// doing so would be most misleading — "passport valid" is not a claim this or any reader
/// can make.
/// </remarks>
public sealed partial class InspectionView : UserControl
{
    private readonly List<CheckRow> _rows = [];
    private bool _busy;

    public InspectionView()
    {
        // The generated InitializeComponent, not AvaloniaXamlLoader.Load(this). The raw
        // loader builds the visual tree but never assigns the x:Name fields, so every
        // named control stays null — and the first one touched throws. That shipped once:
        // the head compiled, CI was green, and it crashed on opening.
        InitializeComponent();

        ChecksList.ItemsSource = _rows;
        ShowNfcState(MainActivity.NfcAvailable);

        MainActivity.TagDiscovered += OnTagDiscovered;
        MainActivity.NfcStateChanged += available =>
            Dispatcher.UIThread.Post(() => ShowNfcState(available));
    }

    /// <summary>
    /// Shows whether a document can be read right now, unless a read is under way.
    /// </summary>
    /// <remarks>
    /// This view is created by the Avalonia application before the activity exists, so
    /// at construction the NFC state is simply not known yet. It is reported again each
    /// time the activity resumes — which also covers switching NFC on in system settings
    /// and coming back, the most likely thing a user does after reading the message.
    /// </remarks>
    private void ShowNfcState(bool available)
    {
        if (_busy)
        {
            return;
        }

        StatusText.Text = available
            ? "Waiting for a document."
            : "NFC is unavailable or switched off. Enable it in system settings.";
    }

    private void OnTagDiscovered(Tag tag)
    {
        // Discovery arrives on the platform thread; everything below touches the UI.
        Dispatcher.UIThread.Post(() => _ = InspectAsync(tag));
    }

    private async Task InspectAsync(Tag tag)
    {
        if (_busy)
        {
            return;
        }

        MrzKey key;
        try
        {
            key = MrzKey.Create(
                DocumentNumberBox.Text ?? string.Empty,
                DateOfBirthBox.Text ?? string.Empty,
                DateOfExpiryBox.Text ?? string.Empty);
        }
        catch (Exception exception)
        {
            StatusText.Text = $"Check the MRZ fields: {exception.Message}";
            return;
        }

        _busy = true;
        _rows.Clear();
        ChecksList.ItemsSource = null;
        PortraitImage.Source = null;
        StatusText.Text = "Reading — hold the phone still against the datapage.";

        try
        {
            InspectionOutcome outcome = await Task.Run(() =>
            {
                using IsoDepTransport nfc = new(tag);

                // Handheld resilience: the document is held by hand and an 18 KB portrait
                // takes several seconds, so brief tag loss is routine.
                using ResilientTransport transport =
                    new(nfc, TransportResilience.Handheld);

                transport.Connect();

                // No trust anchors are bundled (D005), so the chain check reports
                // inconclusive unless the operator supplies a CSCA.
                return new InspectionSession(new TrustStore()).Inspect(transport, key);
            });

            Render(outcome);
        }
        catch (Exception exception)
        {
            StatusText.Text = $"The read did not complete: {exception.Message}";
        }
        finally
        {
            _busy = false;
        }
    }

    private void Render(InspectionOutcome outcome)
    {
        foreach (InspectionCheck check in outcome.Report.Checks)
        {
            _rows.Add(new CheckRow(
                ReportFormatter.Badge(check.Status).TrimEnd(), check.Id, check.Detail));
        }

        ChecksList.ItemsSource = null;
        ChecksList.ItemsSource = _rows;

        StatusText.Text =
            $"Read complete in {outcome.Report.ElapsedMilliseconds} ms. " +
            ReportFormatter.Summarize(outcome.Report) +
            " Read each result below rather than treating this as a verdict.";

        RenderPortrait(outcome.Portrait);
    }

    /// <summary>
    /// Shows the portrait, or says why it cannot be shown.
    /// </summary>
    /// <remarks>
    /// Many issuers store JPEG 2000, which the platform decoder does not handle. Leaving
    /// the pane blank would read as "this document has no portrait", which is a different
    /// and wrong statement about the document.
    /// </remarks>
    private void RenderPortrait(FaceImage? portrait)
    {
        if (portrait is null)
        {
            PortraitNote.Text = "No portrait was read.";
            return;
        }

        try
        {
            using MemoryStream stream = new(portrait.Data.ToArray());
            PortraitImage.Source = new Bitmap(stream);
            PortraitNote.Text =
                $"DG2, {portrait.Encoding}, {portrait.Width}x{portrait.Height}.";
        }
        catch (Exception)
        {
            // A portrait that will not decode is not worth failing the inspection over;
            // every check above still stands.
            PortraitNote.Text =
                $"DG2 holds a {portrait.Encoding} image of {portrait.Data.Length:N0} bytes, " +
                "which this device cannot display. Every check above still stands.";
        }
    }
}
