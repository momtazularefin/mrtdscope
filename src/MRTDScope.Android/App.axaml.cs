using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;

namespace MRTDScope.Droid;

/// <summary>
/// The Avalonia application. Fully qualified base type because
/// <c>Android.App.Application</c> is also in scope on this platform.
/// </summary>
public sealed partial class App : Avalonia.Application
{
    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is ISingleViewApplicationLifetime singleView)
        {
            singleView.MainView = new InspectionView();
        }

        base.OnFrameworkInitializationCompleted();
    }
}
