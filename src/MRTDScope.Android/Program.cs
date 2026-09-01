using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.Nfc;
using Android.OS;
using Android.Runtime;
using Avalonia;
using Avalonia.Android;

namespace MRTDScope.Droid;

/// <summary>
/// The Avalonia host application.
/// </summary>
/// <remarks>
/// Avalonia 12 hosts the app from an <c>Application</c> subclass rather than a generic
/// activity, which is a change from 11.
/// </remarks>
[Application]
public sealed class MrtdScopeApplication : AvaloniaAndroidApplication<App>
{
    public MrtdScopeApplication(IntPtr handle, JniHandleOwnership ownership)
        : base(handle, ownership)
    {
    }

    protected override AppBuilder CustomizeAppBuilder(AppBuilder builder) =>
        base.CustomizeAppBuilder(builder);
}

/// <summary>
/// The single activity, which also owns NFC discovery.
/// </summary>
/// <remarks>
/// Foreground dispatch is what stops Android handing the tag to another app — or to its
/// own "new tag detected" chrome — while MRTDScope is on screen. Without it a document
/// tapped against the phone is frequently claimed by something else, which reads to a user
/// as the app being broken.
/// </remarks>
[Activity(
    Label = "MRTDScope",
    MainLauncher = true,
    LaunchMode = LaunchMode.SingleTop,
    ConfigurationChanges = ConfigChanges.Orientation | ConfigChanges.ScreenSize | ConfigChanges.UiMode)]
public sealed class MainActivity : AvaloniaMainActivity
{
    private NfcAdapter? _adapter;
    private PendingIntent? _pendingIntent;

    /// <summary>Raised when a document is presented to the antenna.</summary>
    public static event Action<Tag>? TagDiscovered;

    /// <summary>Whether this device has NFC hardware that is switched on.</summary>
    public static bool NfcAvailable { get; private set; }

    protected override void OnCreate(Bundle? savedInstanceState)
    {
        base.OnCreate(savedInstanceState);

        _adapter = NfcAdapter.GetDefaultAdapter(this);
        NfcAvailable = _adapter?.IsEnabled ?? false;

        Intent intent = new Intent(this, GetType()).AddFlags(ActivityFlags.SingleTop);

        // From Android 12 a PendingIntent must declare mutability explicitly, and
        // foreground dispatch needs it mutable so the platform can fill in the tag extra.
        // Below 12 the flag does not exist and the default behaviour is already mutable.
        PendingIntentFlags flags = OperatingSystem.IsAndroidVersionAtLeast(31)
            ? PendingIntentFlags.Mutable
            : PendingIntentFlags.UpdateCurrent;

        _pendingIntent = PendingIntent.GetActivity(this, requestCode: 0, intent, flags);
    }

    protected override void OnResume()
    {
        base.OnResume();
        _adapter?.EnableForegroundDispatch(this, _pendingIntent, null, null);
    }

    protected override void OnPause()
    {
        base.OnPause();
        _adapter?.DisableForegroundDispatch(this);
    }

    protected override void OnNewIntent(Intent? intent)
    {
        base.OnNewIntent(intent);

        if (ExtractTag(intent) is { } tag)
        {
            TagDiscovered?.Invoke(tag);
        }
    }

    /// <summary>
    /// Pulls the discovered tag out of the dispatch intent.
    /// </summary>
    /// <remarks>
    /// Android 13 deprecated the untyped extra accessor in favour of a class-qualified
    /// one. Both are kept so the app still works on the older devices that make up much of
    /// the installed base.
    /// </remarks>
    private static Tag? ExtractTag(Intent? intent)
    {
        if (intent is null)
        {
            return null;
        }

        if (OperatingSystem.IsAndroidVersionAtLeast(33))
        {
            return intent.GetParcelableExtra(
                NfcAdapter.ExtraTag,
                Java.Lang.Class.FromType(typeof(Tag))) as Tag;
        }

#pragma warning disable CA1422 // Kept deliberately for devices below Android 13.
        return intent.GetParcelableExtra(NfcAdapter.ExtraTag) as Tag;
#pragma warning restore CA1422
    }
}
