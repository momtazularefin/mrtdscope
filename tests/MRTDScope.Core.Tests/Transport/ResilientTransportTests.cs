using MRTDScope.Core.Apdu;
using MRTDScope.Core.Errors;
using MRTDScope.Core.Inspection;
using MRTDScope.Core.Transport;
using MRTDScope.Core.Verification;
using MRTDScope.Synthetic;

namespace MRTDScope.Core.Tests.Transport;

/// <summary>
/// A transport that fails a scheduled number of times before working, modelling a
/// document that briefly leaves the antenna.
/// </summary>
internal sealed class FlakyTransport(ICardTransport inner, int failuresPerCommand) : ICardTransport
{
    private readonly Dictionary<string, int> _remaining = [];

    public int Reconnects { get; private set; }

    public string Name => inner.Name;

    public bool IsConnected => inner.IsConnected;

    public ReadOnlyMemory<byte> AnswerToReset => inner.AnswerToReset;

    public void Connect()
    {
        Reconnects++;
        inner.Connect();
    }

    public ResponseApdu Transmit(CommandApdu command)
    {
        string key = Convert.ToHexString(command.ToBytes());

        if (!_remaining.TryGetValue(key, out int left))
        {
            left = failuresPerCommand;
        }

        if (left > 0)
        {
            _remaining[key] = left - 1;
            throw new CardTransportException("The tag moved out of range.");
        }

        return inner.Transmit(command);
    }

    public void Disconnect() => inner.Disconnect();

    public void Dispose() => inner.Dispose();
}

/// <summary>
/// Retry behaviour for handheld reading, where brief tag loss is routine rather than
/// exceptional.
/// </summary>
public sealed class ResilientTransportTests
{
    private static readonly CommandApdu Select =
        new(0x00, 0xA4, 0x04, 0x0C, MRTDScope.Core.Protocol.MrtdApplication.Lds1ApplicationId.ToArray());

    [Fact]
    public void ATransientFailureIsRetriedAndSucceeds()
    {
        using SyntheticChip chip = SyntheticDocument.Build().CreateChip();
        chip.Connect();

        using FlakyTransport flaky = new(chip, failuresPerCommand: 2);
        using ResilientTransport resilient = new(flaky, TransportResilience.Handheld, _ => { });

        ResponseApdu response = resilient.Transmit(Select);

        Assert.True(response.IsSuccess);
        Assert.Equal(1, resilient.RetriedExchanges);
    }

    [Fact]
    public void RecoveryReconnectsRatherThanRetryingADeadHandle()
    {
        using SyntheticChip chip = SyntheticDocument.Build().CreateChip();
        chip.Connect();

        using FlakyTransport flaky = new(chip, failuresPerCommand: 2);
        int before = flaky.Reconnects;

        using ResilientTransport resilient = new(flaky, TransportResilience.Handheld, _ => { });
        resilient.Transmit(Select);

        // Without reconnecting, a retry would hit the same dead handle every time.
        Assert.True(flaky.Reconnects > before);
    }

    [Fact]
    public void PersistentFailureGivesUpWithAnActionableMessage()
    {
        using SyntheticChip chip = SyntheticDocument.Build().CreateChip();
        chip.Connect();

        using FlakyTransport flaky = new(chip, failuresPerCommand: 99);
        using ResilientTransport resilient = new(flaky, TransportResilience.Handheld, _ => { });

        CardTransportException error =
            Assert.Throws<CardTransportException>(() => resilient.Transmit(Select));

        Assert.Contains("attempt", error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("antenna", error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.NotNull(error.InnerException);
    }

    /// <summary>
    /// A desk reader should fail fast: a failure there is usually real, and retrying
    /// hides it.
    /// </summary>
    [Fact]
    public void TheWiredPolicyDoesNotRetry()
    {
        using SyntheticChip chip = SyntheticDocument.Build().CreateChip();
        chip.Connect();

        using FlakyTransport flaky = new(chip, failuresPerCommand: 1);
        using ResilientTransport resilient = new(flaky, TransportResilience.Wired, _ => { });

        Assert.Throws<CardTransportException>(() => resilient.Transmit(Select));
        Assert.Equal(0, resilient.RetriedExchanges);
    }

    /// <summary>
    /// The decorator must sit below secure messaging. A whole inspection over a flaky
    /// link has to complete unharmed — if retries reached protected commands they would
    /// desynchronise the send sequence counter and every later checksum would fail.
    /// </summary>
    [Fact]
    public void AFullInspectionSurvivesAFlakyLink()
    {
        using SyntheticChip chip = SyntheticDocument.Build()
            .AdvertisingPace()
            .WithChipAuthentication()
            .WithActiveAuthentication()
            .CreateChip();
        chip.Connect();

        using FlakyTransport flaky = new(chip, failuresPerCommand: 1);
        using ResilientTransport resilient = new(flaky, TransportResilience.Handheld, _ => { });

        InspectionOutcome outcome = new InspectionSession(new TrustStore([chip.Document.Csca]))
            .Inspect(resilient, chip.Document.MrzKey);

        Assert.False(outcome.Report.HasFailure);
        Assert.Equal([1, 2, 14, 15], outcome.DataGroupsRead.Keys.Order());
        Assert.True(resilient.RetriedExchanges > 0);
    }
}
