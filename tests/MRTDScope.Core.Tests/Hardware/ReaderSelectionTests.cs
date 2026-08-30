using MRTDScope.Pcsc;

namespace MRTDScope.Core.Tests.Hardware;

/// <summary>
/// Reader preference, pinned without hardware.
/// </summary>
/// <remarks>
/// From a real hardware run: one physical OMNIKEY exposes two PC/SC names, the contact
/// interface sorting first. Taking the first reader chose the contact interface for a
/// contactless document, and PC/SC reported "the smart card has been removed" — accurate,
/// and thoroughly misleading, because that slot was empty the whole time.
/// <para>
/// The selection logic is a pure function over a list of names precisely so this cannot
/// regress silently on a machine with only one reader attached.
/// </para>
/// </remarks>
public sealed class ReaderSelectionTests
{
    private static readonly string[] OmnikeyBothInterfaces =
        ["OMNIKEY CardMan 5x21 0", "OMNIKEY CardMan 5x21-CL 0"];

    [Fact]
    public void PrefersTheContactlessInterfaceOverTheContactOne()
    {
        Assert.Equal(
            "OMNIKEY CardMan 5x21-CL 0",
            PcscReaderResolver.SelectPreferred(OmnikeyBothInterfaces));
    }

    [Fact]
    public void PrefersContactlessRegardlessOfEnumerationOrder()
    {
        Assert.Equal(
            "OMNIKEY CardMan 5x21-CL 0",
            PcscReaderResolver.SelectPreferred([.. OmnikeyBothInterfaces.Reverse()]));
    }

    [Theory]
    [InlineData("OMNIKEY CardMan 5x21-CL 0")]
    [InlineData("ACS ACR122U PICC Interface 0")]
    [InlineData("Identiv uTrust 3700 F Contactless Reader 0")]
    [InlineData("Generic NFC Reader 0")]
    public void RecognizesTheCommonContactlessNamingConventions(string reader)
    {
        Assert.True(PcscReaderResolver.LooksContactless(reader), reader);
    }

    [Theory]
    [InlineData("OMNIKEY CardMan 5x21 0")]
    [InlineData("Generic Smart Card Reader Interface 0")]
    [InlineData("Yubico YubiKey OTP+FIDO+CCID 0")]
    public void DoesNotMistakeAContactReaderForContactless(string reader)
    {
        Assert.False(PcscReaderResolver.LooksContactless(reader), reader);
    }

    [Fact]
    public void AnExplicitPreferenceWins()
    {
        Assert.Equal(
            "OMNIKEY CardMan 5x21 0",
            PcscReaderResolver.SelectPreferred(OmnikeyBothInterfaces, "CardMan 5x21 0"));
    }

    /// <summary>
    /// An operator who names a reader wants that reader. Falling back to another one
    /// would read the wrong device while appearing to succeed.
    /// </summary>
    [Fact]
    public void AnUnmatchedPreferenceYieldsNothingRatherThanASubstitute()
    {
        Assert.Null(PcscReaderResolver.SelectPreferred(OmnikeyBothInterfaces, "Nonexistent"));
    }

    [Fact]
    public void WithNoContactlessInterfaceTheFirstReaderIsUsed()
    {
        Assert.Equal(
            "Some Contact Reader 0",
            PcscReaderResolver.SelectPreferred(["Some Contact Reader 0", "Another Reader 1"]));
    }

    [Fact]
    public void NoReadersYieldsNull()
    {
        Assert.Null(PcscReaderResolver.SelectPreferred([]));
    }
}
