using MRTDScope.Core.Tests.Support;
using MRTDScope.Core.Verification;
using Org.BouncyCastle.X509;

namespace MRTDScope.Core.Tests.Verification;

/// <summary>
/// Trust-anchor loading, including the duplicate handling real ICAO PKD exports require.
/// </summary>
public sealed class TrustStoreTests
{
    [Fact]
    public void EmptyStoreIsAValidState()
    {
        TrustStore store = new();

        Assert.True(store.IsEmpty);
        Assert.Empty(store.Anchors);
    }

    /// <summary>
    /// A PKD export ships each certificate as both <c>.pem</c> and <c>.cer</c>, so a
    /// directory of 458 files holds 229 anchors. Counting files instead of certificates
    /// would double the "anchors tried" figure a failed chain reports as evidence.
    /// </summary>
    [Fact]
    public void TheSameCertificateInTwoEncodingsCountsOnce()
    {
        TestPki pki = TestPki.Create();
        TrustStore store = new();

        byte[] der = pki.Csca.GetEncoded();

        Assert.True(store.Add(der));
        Assert.False(store.Add(der));

        Assert.Single(store.Anchors);
    }

    [Fact]
    public void DistinctAuthoritiesAreAllRetained()
    {
        TrustStore store = new();

        store.Add(TestPki.Create(cscaSubject: "CN=Authority One,C=AA").Csca.GetEncoded());
        store.Add(TestPki.Create(cscaSubject: "CN=Authority Two,C=BB").Csca.GetEncoded());

        Assert.Equal(2, store.Anchors.Count);
    }

    [Fact]
    public void ConstructorDeduplicatesToo()
    {
        X509Certificate csca = TestPki.Create().Csca;
        TrustStore store = new([csca, csca]);

        Assert.Single(store.Anchors);
    }

    [Fact]
    public void UnparseableBytesAreRejected()
    {
        TrustStore store = new();

        Assert.ThrowsAny<Exception>(() => store.Add(new byte[] { 0x01, 0x02, 0x03 }));
    }

    [Fact]
    public void LoadDirectory_SkipsNonCertificatesAndCountsDistinctAnchors()
    {
        string directory = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        Directory.CreateDirectory(directory);

        try
        {
            TestPki pki = TestPki.Create();
            byte[] der = pki.Csca.GetEncoded();

            // The same anchor twice, mirroring a .pem/.cer pair, plus a stray file of the
            // kind an operator's anchor directory always accumulates.
            File.WriteAllBytes(Path.Combine(directory, "anchor.cer"), der);
            File.WriteAllBytes(Path.Combine(directory, "anchor.pem"), der);
            File.WriteAllText(Path.Combine(directory, "README.md"), "not a certificate");

            TrustStore store = new();

            Assert.Equal(1, store.LoadDirectory(directory));
            Assert.Single(store.Anchors);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void LoadDirectory_OnAMissingPathIsNotAnError()
    {
        TrustStore store = new();

        Assert.Equal(0, store.LoadDirectory(
            Path.Combine(Path.GetTempPath(), Path.GetRandomFileName())));
    }
}
