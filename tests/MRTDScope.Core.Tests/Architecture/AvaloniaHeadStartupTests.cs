using System.Text.RegularExpressions;

namespace MRTDScope.Core.Tests.Architecture;

/// <summary>
/// Startup invariants for the Avalonia heads, asserted against their source.
/// </summary>
/// <remarks>
/// The Android head cannot be constructed by any test here: it targets
/// <c>net10.0-android</c>, needs a workload the main solution deliberately avoids, and
/// only really starts on a device. CI proves it compiles, and that proved nothing. The
/// first build installed on a phone crashed before drawing a frame, twice over, for two
/// reasons a compiler cannot see. Both are stated here as rules instead, so the next
/// occurrence fails in CI rather than on somebody's handset.
/// </remarks>
public sealed partial class AvaloniaHeadStartupTests
{
    private static readonly string RepositoryRoot = FindRepositoryRoot();

    /// <summary>
    /// A view with named controls must call the generated <c>InitializeComponent</c>.
    /// </summary>
    /// <remarks>
    /// <c>AvaloniaXamlLoader.Load(this)</c> builds the visual tree but never assigns the
    /// fields generated for <c>x:Name</c>, so every named control stays null and the first
    /// one touched throws. It compiles cleanly, because the fields exist. The Android head
    /// shipped this way and died on its first line with a <c>NullReferenceException</c>.
    /// The raw loader remains correct for an <c>Application</c>, which has no named fields.
    /// </remarks>
    [Fact]
    public void ViewsWithNamedControlsUseTheGeneratedInitializer()
    {
        List<string> offenders = [];

        foreach (string markup in Directory.EnumerateFiles(
            Path.Combine(RepositoryRoot, "src"), "*.axaml", SearchOption.AllDirectories))
        {
            if (IsBuildOutput(markup) || !File.ReadAllText(markup).Contains("x:Name=", StringComparison.Ordinal))
            {
                continue;
            }

            string codeBehind = markup + ".cs";
            Assert.True(File.Exists(codeBehind), $"{Relative(markup)} has named controls but no code-behind.");

            // Comments are stripped first: explaining why the raw loader is wrong, which the
            // fixed view does, must not read as using it.
            string code = LineComment().Replace(File.ReadAllText(codeBehind), string.Empty);

            if (code.Contains("AvaloniaXamlLoader.Load(this)", StringComparison.Ordinal) ||
                !code.Contains("InitializeComponent();", StringComparison.Ordinal))
            {
                offenders.Add(Relative(codeBehind));
            }
        }

        Assert.True(
            offenders.Count == 0,
            "These views name controls but do not assign them, so each will throw on first " +
            "use: " + string.Join(", ", offenders));
    }

    /// <summary>
    /// The Android activity must run under an AppCompat theme that actually exists.
    /// </summary>
    /// <remarks>
    /// <c>AvaloniaMainActivity</c> derives from <c>AppCompatActivity</c>, which throws
    /// <c>IllegalStateException</c> from <c>setContentView</c> under any other theme.
    /// Avalonia.Android ships none and the platform default does not qualify, so an
    /// activity declaring no theme cannot start at all. Nothing at build time notices.
    /// </remarks>
    [Fact]
    public void TheAndroidActivityDeclaresAnAppCompatTheme()
    {
        string head = Path.Combine(RepositoryRoot, "src", "MRTDScope.Android");
        string program = File.ReadAllText(Path.Combine(head, "Program.cs"));

        Match activity = ActivityAttribute().Match(program);
        Assert.True(activity.Success, "No [Activity] attribute found on the Android head.");

        Match theme = ThemeReference().Match(activity.Value);
        Assert.True(
            theme.Success,
            "The Android activity declares no Theme, so AppCompatActivity refuses to start.");

        string styleName = theme.Groups["name"].Value;
        string styles = Path.Combine(head, "Resources", "values", "styles.xml");
        Assert.True(File.Exists(styles), $"The activity names @style/{styleName}, but no styles.xml exists.");

        Match style = Regex.Match(
            File.ReadAllText(styles),
            $"<style\\s+name=\"{Regex.Escape(styleName)}\"\\s+parent=\"(?<parent>[^\"]+)\"");

        Assert.True(style.Success, $"@style/{styleName} is referenced but never defined.");
        Assert.StartsWith("Theme.AppCompat", style.Groups["parent"].Value, StringComparison.Ordinal);
    }

    /// <summary>
    /// The Android activity must deliver touch with an unknown tool type as finger touch.
    /// </summary>
    /// <remarks>
    /// Samsung's scroll capture measures a page by injecting a drag into the app, built
    /// without a tool type. Avalonia 12.0.5 sends such events to its touch device but maps
    /// them to mouse-button events, which that device drops, so the drag moved nothing and
    /// scroll capture failed on every attempt. On the device the injected events arrived
    /// with source Touchscreen and tool type Unknown, sixteen of them across four captures,
    /// and the rewrite made all four succeed. Deleting it compiles, passes every other
    /// test, and silently breaks the feature again.
    /// </remarks>
    [Fact]
    public void TheAndroidActivityDeliversUnknownToolTouchAsFinger()
    {
        string program = LineComment().Replace(
            File.ReadAllText(Path.Combine(RepositoryRoot, "src", "MRTDScope.Android", "Program.cs")),
            string.Empty);

        Assert.Contains("override bool DispatchTouchEvent(", program, StringComparison.Ordinal);
        Assert.Contains("== MotionEventToolType.Unknown", program, StringComparison.Ordinal);
        Assert.Matches(@"ToolType\s*=\s*MotionEventToolType\.Finger", program);
    }

    /// <summary>
    /// Every head's markup must at least be well-formed XML.
    /// </summary>
    /// <remarks>
    /// The desktop head is compiled by the ordinary build, so its markup cannot be wrong for
    /// long. The Android head is not: it targets <c>net10.0-android</c>, needs a workload the
    /// main solution avoids, and is built only by CI. A comment written there with a double
    /// hyphen inside it — legal in most languages, illegal in XML — parsed fine to the eye and
    /// would have failed the Android job alone, after the change had already been called done.
    /// </remarks>
    [Fact]
    public void EveryHeadMarkupFileIsWellFormedXml()
    {
        List<string> offenders = [];
        int examined = 0;

        foreach (string markup in Directory.EnumerateFiles(
            Path.Combine(RepositoryRoot, "src"), "*.axaml", SearchOption.AllDirectories))
        {
            if (IsBuildOutput(markup))
            {
                continue;
            }

            examined++;

            try
            {
                System.Xml.Linq.XDocument.Load(markup);
            }
            catch (System.Xml.XmlException error)
            {
                offenders.Add($"{Relative(markup)}: {error.Message}");
            }
        }

        Assert.True(examined >= 4, $"Only {examined} markup files were scanned, so this guard proved nothing.");

        Assert.True(
            offenders.Count == 0,
            "This markup will not parse, and for the Android head nothing local would say so: " +
            string.Join("; ", offenders));
    }

    [GeneratedRegex(@"\[Activity\((?:[^\[\]]|\[[^\]]*\])*?\)\]\s*public\s+sealed\s+class\s+\w+\s*:\s*AvaloniaMainActivity", RegexOptions.Singleline)]
    private static partial Regex ActivityAttribute();

    [GeneratedRegex("Theme\\s*=\\s*\"@style/(?<name>[^\"]+)\"")]
    private static partial Regex ThemeReference();

    [GeneratedRegex(@"//.*$", RegexOptions.Multiline)]
    private static partial Regex LineComment();

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
            "Could not find MRTDScope.slnx above the test output, so the head sources cannot be checked.");
    }
}
