using Avalonia.Media;
using MRTDScope.Core.Inspection;
using MRTDScope.Desktop;

namespace MRTDScope.Desktop.Tests;

/// <summary>
/// Holds the status colours to the contrast the badge word needs to be readable.
/// </summary>
/// <remarks>
/// The palette this started from was the Material mid tones, which look decisive against
/// a dark mock and are nearly invisible on the light surface the application actually
/// draws. Measured off a capture, PASS came out at 2.15:1, INCONCL at 1.39:1 and N/A at
/// 2.59:1, so the single word carrying each verdict was the least readable text in the
/// window. Nothing in a headless render catches that, because the colours are perfectly
/// valid; only the ratio against the surface behind them is wrong. Asserting the ratio
/// here is what makes a return to bright palette values fail in CI.
/// </remarks>
public sealed class StatusContrastTests
{
    /// <summary>
    /// The card behind a check row, sampled from a capture of the running window.
    /// </summary>
    /// <remarks>
    /// The row's background is a translucent overlay, so the effective colour cannot be
    /// read off the markup; #E2E2E2 is what it composites to over the light theme. The
    /// left panel composites lighter (#ECECEC), which is a weaker test, so the card is
    /// the one asserted.
    /// </remarks>
    private static readonly Color CardBackground = Color.FromRgb(0xE2, 0xE2, 0xE2);

    /// <summary>WCAG 2.2 success criterion 1.4.3, for text below 18.66px bold.</summary>
    private const double SmallTextMinimum = 4.5;

    [Theory]
    [InlineData(CheckStatus.Passed)]
    [InlineData(CheckStatus.Failed)]
    [InlineData(CheckStatus.Inconclusive)]
    [InlineData(CheckStatus.NotApplicable)]
    [InlineData(CheckStatus.Unavailable)]
    public void EveryStatusColourIsReadableAsText(CheckStatus status)
    {
        double ratio = ContrastRatio(CheckRow.AccentFor(status), CardBackground);

        Assert.True(
            ratio >= SmallTextMinimum,
            $"{status} is drawn at {ratio:N2}:1 against the check card, under the " +
            $"{SmallTextMinimum:N1}:1 its badge needs to be readable.");
    }

    /// <summary>
    /// Every status must still be told apart from every other by colour alone.
    /// </summary>
    /// <remarks>
    /// Darkening a palette far enough collapses it: pushed to the limit every hue lands on
    /// near-black and the rule beside each row stops meaning anything. The badge word is
    /// the real carrier, so this only asks that the colours remain visibly distinct rather
    /// than distinguishable to any particular standard.
    /// </remarks>
    [Fact]
    public void TheStatusColoursRemainDistinctFromOneAnother()
    {
        CheckStatus[] statuses =
        [
            CheckStatus.Passed,
            CheckStatus.Failed,
            CheckStatus.Inconclusive,
            CheckStatus.NotApplicable,
        ];

        foreach (CheckStatus left in statuses)
        {
            foreach (CheckStatus right in statuses)
            {
                if (left >= right)
                {
                    continue;
                }

                Color a = CheckRow.AccentFor(left);
                Color b = CheckRow.AccentFor(right);
                int distance = Math.Abs(a.R - b.R) + Math.Abs(a.G - b.G) + Math.Abs(a.B - b.B);

                Assert.True(
                    distance >= 60,
                    $"{left} and {right} differ by only {distance} across the channels, " +
                    "so the rule beside each row no longer separates them.");
            }
        }
    }

    /// <summary>
    /// Relative luminance and contrast ratio exactly as WCAG 2.2 defines them.
    /// </summary>
    private static double ContrastRatio(Color foreground, Color background)
    {
        double a = RelativeLuminance(foreground);
        double b = RelativeLuminance(background);
        return (Math.Max(a, b) + 0.05) / (Math.Min(a, b) + 0.05);
    }

    private static double RelativeLuminance(Color colour) =>
        (0.2126 * Linear(colour.R)) + (0.7152 * Linear(colour.G)) + (0.0722 * Linear(colour.B));

    private static double Linear(byte channel)
    {
        double value = channel / 255.0;
        return value <= 0.04045 ? value / 12.92 : Math.Pow((value + 0.055) / 1.055, 2.4);
    }
}
