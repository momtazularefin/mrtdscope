using Android.Nfc;
using Avalonia.Controls;
using Avalonia.Markup.Xaml;
using Avalonia.Media.Imaging;
using Avalonia.Threading;
using MRTDScope.Core.Inspection;
using MRTDScope.Core.Lds;
using MRTDScope.Core.Mrz;
using MRTDScope.Core.Transport;
using MRTDScope.Core.Verification;

namespace MRTDScope.Droid;

/// <summary>One check, flattened for display.</summary>
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
        AvaloniaXamlLoader.Load(this);

        ChecksList.ItemsSource = _rows;

        StatusText.Text = MainActivity.NfcAvailable
            ? "Waiting for a document."
            : "NFC is unavailable or switched off. Enable it in system settings.";

        MainActivity.TagDiscovered += OnTagDiscovered;
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
            _rows.Add(new CheckRow(Badge(check.Status), check.Id, check.Detail));
        }

        ChecksList.ItemsSource = null;
        ChecksList.ItemsSource = _rows;

        int failed = outcome.Report.Checks.Count(c => c.Status == CheckStatus.Failed);

        StatusText.Text = failed == 0
            ? $"Read complete in {outcome.Report.ElapsedMilliseconds} ms. " +
              "No check failed. Read each result below rather than treating this as a verdict."
            : $"Read complete in {outcome.Report.ElapsedMilliseconds} ms. " +
              $"{failed} check(s) failed — see below.";

        if (outcome.Portrait is { } portrait && portrait.Encoding == FaceImageEncoding.Jpeg)
        {
            try
            {
                using MemoryStream stream = new(portrait.Data.ToArray());
                PortraitImage.Source = new Bitmap(stream);
            }
            catch (Exception)
            {
                // A portrait that will not decode is not worth failing the inspection over;
                // every check above still stands.
            }
        }
    }

    private static string Badge(CheckStatus status) => status switch
    {
        CheckStatus.Passed => "PASS",
        CheckStatus.Failed => "FAIL",
        CheckStatus.Inconclusive => "????",
        CheckStatus.NotApplicable => "N/A ",
        _ => "N/A ",
    };
}
