using Avalonia;

namespace MRTDScope.Desktop;

internal static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        if (!StartupOptions.TryParse(args))
        {
            return 2;
        }

        BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
        return 0;
    }

    /// <summary>Used by the Avalonia design-time tooling as well as by <see cref="Main"/>.</summary>
    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>()
            .UsePlatformDetect()
            // Inter is embedded rather than resolved from the host, so the application
            // looks the same on a machine with no suitable system font — and so the
            // published screenshots are reproducible rather than machine-dependent.
            .WithInterFont()
            .LogToTrace();
}
