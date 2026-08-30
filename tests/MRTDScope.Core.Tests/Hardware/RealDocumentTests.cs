using MRTDScope.Core.Apdu;
using MRTDScope.Core.Mrz;
using MRTDScope.Core.Protocol;
using MRTDScope.Core.Protocol.Bac;
using MRTDScope.Core.Protocol.SecureMessaging;
using MRTDScope.Core.Transport;
using MRTDScope.Pcsc;

namespace MRTDScope.Core.Tests.Hardware;

/// <summary>
/// End-to-end BAC against a physical document on a PC/SC reader (AC1).
/// </summary>
/// <remarks>
/// Excluded from CI by the <c>Hardware</c> trait, so the suite stays green with no
/// reader and no chip (NFR2). Reads only a document the operator is entitled to read.
/// <para>
/// The MRZ fields come from the environment and are never committed. Nothing this test
/// obtains — MRZ, chip contents, portrait — may enter the repository (NFR3), so it
/// asserts on structure and never prints document content.
/// </para>
/// <para>
/// To run: set the three environment variables below, place the document on the reader,
/// then <c>dotnet test --filter Category=Hardware</c>.
/// </para>
/// </remarks>
[Trait("Category", "Hardware")]
[Collection(HardwareCollection.Name)]
public sealed class RealDocumentTests
{
    private const string DocumentNumberVariable = "MRTDSCOPE_TEST_DOC_NUMBER";
    private const string DateOfBirthVariable = "MRTDSCOPE_TEST_DOB";
    private const string DateOfExpiryVariable = "MRTDSCOPE_TEST_DOE";

    [SkippableFact]
    public void Bac_EstablishesASecureChannelAndReadsEfCom()
    {
        MrzKey key = ResolveKeyOrSkip();
        string reader = PcscReaderResolver.Resolve()
            ?? throw new SkipException("No PC/SC reader is available.");

        ApduTracer tracer = new();
        using PcscCardTransport transport = new(reader, tracer);
        transport.Connect();

        ResponseApdu selected = MrtdApplication.Select(transport);
        Assert.True(selected.IsSuccess, $"SELECT eMRTD application returned {selected.StatusWord}.");

        BacResult result = new BacProtocol(key).Authenticate(transport);
        Assert.True(result.Succeeded, result.Detail);
        Assert.NotNull(result.SecureMessaging);

        using SecureMessagingTransport secure = new(transport, result.SecureMessaging!);

        // EF.COM, file identifier 011E, under the established channel.
        ResponseApdu selectEfCom = secure.Transmit(
            new CommandApdu(0x00, 0xA4, 0x02, 0x0C, Convert.FromHexString("011E")));
        Assert.True(selectEfCom.IsSuccess, $"SELECT EF.COM returned {selectEfCom.StatusWord}.");

        ResponseApdu header = secure.Transmit(
            new CommandApdu(0x00, 0xB0, 0x00, 0x00, expectedLength: 4));
        Assert.True(header.IsSuccess, $"READ BINARY returned {header.StatusWord}.");

        // EF.COM begins with tag 0x60. Structure only; no content is asserted or printed.
        Assert.Equal(4, header.Data.Length);
        Assert.Equal(0x60, header.Data.Span[0]);

        // The rendered trace must be safe to surface: the EXTERNAL AUTHENTICATE payload
        // that would reveal this document's session keys has to be withheld (NFR7).
        Assert.NotEmpty(tracer.Exchanges);
        Assert.Contains("withheld", tracer.ToText(), StringComparison.Ordinal);
    }

    private static MrzKey ResolveKeyOrSkip()
    {
        string? documentNumber = Environment.GetEnvironmentVariable(DocumentNumberVariable);
        string? dateOfBirth = Environment.GetEnvironmentVariable(DateOfBirthVariable);
        string? dateOfExpiry = Environment.GetEnvironmentVariable(DateOfExpiryVariable);

        Skip.If(
            string.IsNullOrWhiteSpace(documentNumber)
            || string.IsNullOrWhiteSpace(dateOfBirth)
            || string.IsNullOrWhiteSpace(dateOfExpiry),
            $"Set {DocumentNumberVariable}, {DateOfBirthVariable}, and {DateOfExpiryVariable} " +
            "to run against a physical document.");

        return MrzKey.Create(documentNumber!, dateOfBirth!, dateOfExpiry!);
    }
}
