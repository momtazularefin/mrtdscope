using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.Nfc;
using Android.OS;
using Android.Runtime;
using Android.Views;
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
    Theme = "@style/MrtdScopeTheme",
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
    /// <remarks>
    /// False until the activity has resumed at least once. The Avalonia view is built by
    /// the application before any activity exists, so it must not treat this initial
    /// value as a statement about the device; <see cref="NfcStateChanged"/> follows.
    /// </remarks>
    public static bool NfcAvailable { get; private set; }

    /// <summary>Raised on every resume with the current NFC state.</summary>
    public static event Action<bool>? NfcStateChanged;

    protected override void OnCreate(Bundle? savedInstanceState)
    {
        base.OnCreate(savedInstanceState);

        _adapter = NfcAdapter.GetDefaultAdapter(this);

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

        // Read here rather than in OnCreate: a user told NFC is off will switch it on in
        // system settings and return, which resumes this activity without recreating it.
        NfcAvailable = _adapter?.IsEnabled ?? false;
        NfcStateChanged?.Invoke(NfcAvailable);
    }

    protected override void OnPause()
    {
        base.OnPause();
        _adapter?.DisableForegroundDispatch(this);
    }

    /// <summary>
    /// Delivers touch whose tool type was never set as finger touch.
    /// </summary>
    /// <remarks>
    /// Events synthesized in-process — Samsung's scroll capture injects its measuring drag
    /// this way — are built without a tool type, so they arrive as
    /// <c>TOOL_TYPE_UNKNOWN</c>. Avalonia 12.0.5 disagrees with itself about those: it
    /// routes them to the touch device, but maps their actions to mouse-button events,
    /// which the touch device silently drops. The drag never reaches the scroll viewer,
    /// nothing moves, and scroll capture reports that it could not find a scroll area.
    /// Android's own views treat an unknown tool on a touch dispatch as touch; this makes
    /// Avalonia do the same. Real finger, stylus and mouse input passes through untouched.
    /// </remarks>
    public override bool DispatchTouchEvent(MotionEvent? e)
    {
        if (e is null || !HasUnknownToolType(e))
        {
            return base.DispatchTouchEvent(e);
        }

        if (e.ActionMasked == MotionEventActions.Down)
        {
            Android.Util.Log.Info(
                "MRTDScope",
                $"Delivering a touch gesture with an unknown tool type as finger touch (source {e.Source}).");
        }

        MotionEvent finger = AsFingerTouch(e);
        try
        {
            return base.DispatchTouchEvent(finger);
        }
        finally
        {
            finger.Recycle();
        }
    }

    private static bool HasUnknownToolType(MotionEvent e)
    {
        for (int i = 0; i < e.PointerCount; i++)
        {
            if (e.GetToolType(i) == MotionEventToolType.Unknown)
            {
                return true;
            }
        }

        return false;
    }

    private static MotionEvent AsFingerTouch(MotionEvent e)
    {
        int count = e.PointerCount;
        MotionEvent.PointerProperties[] properties = new MotionEvent.PointerProperties[count];
        MotionEvent.PointerCoords[] coordinates = new MotionEvent.PointerCoords[count];

        for (int i = 0; i < count; i++)
        {
            properties[i] = new MotionEvent.PointerProperties();
            e.GetPointerProperties(i, properties[i]);

            if (properties[i].ToolType == MotionEventToolType.Unknown)
            {
                properties[i].ToolType = MotionEventToolType.Finger;
            }

            coordinates[i] = new MotionEvent.PointerCoords();
            e.GetPointerCoords(i, coordinates[i]);
        }

        return MotionEvent.Obtain(
            e.DownTime,
            e.EventTime,
            e.Action,
            count,
            properties,
            coordinates,
            e.MetaState,
            e.ButtonState,
            e.XPrecision,
            e.YPrecision,
            e.DeviceId,
            e.EdgeFlags,
            e.Source,
            e.Flags)!;
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
