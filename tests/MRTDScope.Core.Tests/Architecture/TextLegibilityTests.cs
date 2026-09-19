using System.Text.RegularExpressions;

namespace MRTDScope.Core.Tests.Architecture;

/// <summary>
/// Legibility rules for the Avalonia heads, asserted against their markup.
/// </summary>
/// <remarks>
/// Nothing here can be checked by rendering: the desktop head needs a display and the
/// Android head needs a device, so both defects below shipped and were only caught by
/// measuring pixels out of a screenshot by hand. Stating them as source rules is what
/// makes them fail in CI instead.
/// </remarks>
public sealed partial class TextLegibilityTests
{
    private static readonly string RepositoryRoot = FindRepositoryRoot();

    /// <summary>
    /// A text box must not use its placeholder as the field's only label.
    /// </summary>
    /// <remarks>
    /// SukiUI 7.0.1 templates the placeholder as a TextBlock named PART_Placeholder with a
    /// hardcoded <c>Opacity="0.5"</c> and no Foreground binding, so the control's own
    /// PlaceholderForeground is never read: setting it to Red on the control changed no
    /// pixel in a capture. The rendered text measured 2.51:1 against the panel, and the
    /// halving caps even pure black at 3.89:1, so no colour reaches the 4.5:1 WCAG AA asks
    /// of small text. A placeholder is also gone once the field is filled, which is exactly
    /// when the user wants to confirm which field held what. ComboBox is not covered: its
    /// placeholder shows only while the list is empty, and the head disables the control in
    /// that state, where dimmed text reads as unavailable rather than as unreadable.
    /// </remarks>
    [Fact]
    public void TextBoxesAreLabelledBySomethingOtherThanTheirPlaceholder()
    {
        List<string> offenders = [];
        int examined = 0;

        foreach (string markup in HeadMarkup())
        {
            foreach (Match element in TextBoxElement().Matches(Strip(File.ReadAllText(markup))))
            {
                examined++;

                if (element.Value.Contains("PlaceholderText", StringComparison.Ordinal))
                {
                    offenders.Add($"{Relative(markup)}: {Condense(element.Value)}");
                }
            }
        }

        // Both heads take an MRZ, so a run that saw nothing means the scan broke, not that
        // the markup is clean.
        Assert.True(examined >= 6, $"Only {examined} text boxes were scanned, so this guard proved nothing.");

        Assert.True(
            offenders.Count == 0,
            "These text boxes label themselves with placeholder text, which the theme draws " +
            "at half opacity and erases on first keystroke: " + string.Join("; ", offenders));
    }

    /// <summary>
    /// Markup must not dim text with an Opacity attribute.
    /// </summary>
    /// <remarks>
    /// The desktop head carried Opacity on seventeen text elements to mark secondary text.
    /// Against the light panel that put the body text under 4.5:1, and the user's report was
    /// simply that the lighter text was too light to read. Weight, size and colour all say
    /// "secondary" without touching legibility; opacity is the one that cannot be reasoned
    /// about, because the result depends on whatever happens to be behind it.
    /// </remarks>
    [Fact]
    public void TextElementsAreNotDimmedByOpacity()
    {
        List<string> offenders = [];
        int examined = 0;

        foreach (string markup in HeadMarkup())
        {
            foreach (Match element in TextElement().Matches(Strip(File.ReadAllText(markup))))
            {
                examined++;

                if (OpacityAttribute().IsMatch(element.Value))
                {
                    offenders.Add($"{Relative(markup)}: {Condense(element.Value)}");
                }
            }
        }

        Assert.True(examined >= 20, $"Only {examined} text elements were scanned, so this guard proved nothing.");

        Assert.True(
            offenders.Count == 0,
            "These text elements are dimmed by opacity, so their contrast depends on what is " +
            "behind them: " + string.Join("; ", offenders));
    }

    private static IEnumerable<string> HeadMarkup() =>
        Directory.EnumerateFiles(Path.Combine(RepositoryRoot, "src"), "*.axaml", SearchOption.AllDirectories)
            .Where(path => !IsBuildOutput(path));

    /// <summary>
    /// Removes comments, so that markup explaining a rule never reads as breaking it.
    /// </summary>
    private static string Strip(string markup) => XmlComment().Replace(markup, string.Empty);

    private static string Condense(string element) =>
        Whitespace().Replace(element, " ").Trim();

    [GeneratedRegex(@"<TextBox\b[^>]*>")]
    private static partial Regex TextBoxElement();

    [GeneratedRegex(@"<(?:TextBlock|TextBox|Run)\b[^>]*>")]
    private static partial Regex TextElement();

    [GeneratedRegex(@"\bOpacity\s*=")]
    private static partial Regex OpacityAttribute();

    [GeneratedRegex("<!--.*?-->", RegexOptions.Singleline)]
    private static partial Regex XmlComment();

    [GeneratedRegex(@"\s+")]
    private static partial Regex Whitespace();

    private static bool IsBuildOutput(string path) =>
        path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal) ||
        path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal);

    private static string Relative(string path) => Path.GetRelativePath(RepositoryRoot, path);

    private static string FindRepositoryRoot()
    {
        for (DirectoryInfo? directory = new(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "MRTDScope.slnx")))
            {
                return directory.FullName;
            }
        }

        throw new InvalidOperationException(
            "Could not find MRTDScope.slnx above the test output, so the head markup cannot be checked.");
    }
}
