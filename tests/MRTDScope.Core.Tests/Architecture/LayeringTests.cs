using System.Reflection;
using MRTDScope.Core.Transport;

namespace MRTDScope.Core.Tests.Architecture;

/// <summary>
/// Structural guards on the transport boundary (FR1).
/// </summary>
public sealed class LayeringTests
{
    /// <summary>
    /// Core must not reference any concrete transport library.
    /// </summary>
    /// <remarks>
    /// This is the same technique used to make "no silent success" unrepresentable: state
    /// the rule as a test rather than a comment. If someone adds a PCSC package reference
    /// to Core for convenience, the Android head silently acquires a desktop-only
    /// dependency and the synthetic chip stops being a true peer of real hardware. That
    /// failure would surface late and confusingly; here it surfaces immediately.
    /// </remarks>
    [Fact]
    public void Core_DoesNotReferenceAnyConcreteTransport()
    {
        Assembly core = typeof(ICardTransport).Assembly;

        string[] forbidden = ["PCSC", "Xamarin", "Mono.Android", "Avalonia"];

        IEnumerable<string> referenced = core
            .GetReferencedAssemblies()
            .Select(name => name.Name ?? string.Empty);

        foreach (string reference in referenced)
        {
            Assert.DoesNotContain(
                forbidden,
                banned => reference.StartsWith(banned, StringComparison.OrdinalIgnoreCase));
        }
    }

    [Fact]
    public void Core_DependsOnlyOnTheFrameworkAndBouncyCastle()
    {
        Assembly core = typeof(ICardTransport).Assembly;

        string[] allowedPrefixes = ["System", "netstandard", "Microsoft", "BouncyCastle", "mscorlib"];

        foreach (AssemblyName reference in core.GetReferencedAssemblies())
        {
            string name = reference.Name ?? string.Empty;

            Assert.True(
                allowedPrefixes.Any(prefix => name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)),
                $"MRTDScope.Core references '{name}', which is outside the framework and " +
                "BouncyCastle. Core stays portable so the Android head and the synthetic " +
                "chip can both build against it.");
        }
    }
}
