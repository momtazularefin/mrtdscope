using Org.BouncyCastle.X509;

namespace MRTDScope.Core.Verification;

/// <summary>
/// The operator-supplied CSCA certificates used as trust anchors (D005).
/// </summary>
/// <remarks>
/// MRTDScope ships no anchors and no master list. Claiming to know which authorities are
/// legitimate would assert an authority this project does not have, and would leave a
/// stale trust set embedded in a released binary.
/// <para>
/// An empty store is a valid state, not an error. It means every chain check reports
/// <c>inconclusive</c> — a statement about the inspector, never about the document.
/// </para>
/// </remarks>
public sealed class TrustStore
{
    private readonly List<X509Certificate> _anchors;

    public TrustStore(IEnumerable<X509Certificate>? anchors = null)
    {
        _anchors = anchors is null ? [] : [.. anchors];
    }

    /// <summary>The configured trust anchors.</summary>
    public IReadOnlyList<X509Certificate> Anchors => _anchors;

    /// <summary>Whether any anchor is configured at all.</summary>
    public bool IsEmpty => _anchors.Count == 0;

    /// <summary>Adds an anchor parsed from DER or PEM bytes.</summary>
    public void Add(ReadOnlySpan<byte> encodedCertificate)
    {
        X509CertificateParser parser = new();
        X509Certificate certificate = parser.ReadCertificate(encodedCertificate.ToArray())
            ?? throw new ArgumentException(
                "The supplied bytes are not a parseable X.509 certificate.",
                nameof(encodedCertificate));

        _anchors.Add(certificate);
    }

    /// <summary>
    /// Loads every certificate file in a directory, skipping anything unparseable.
    /// </summary>
    /// <returns>How many anchors were loaded.</returns>
    /// <remarks>
    /// Unreadable files are skipped rather than fatal: an operator's anchor directory
    /// routinely picks up a README or an editor backup, and one stray file should not
    /// prevent the rest of the trust set from loading.
    /// </remarks>
    public int LoadDirectory(string directory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);

        if (!Directory.Exists(directory))
        {
            return 0;
        }

        int loaded = 0;

        foreach (string path in Directory.EnumerateFiles(directory))
        {
            try
            {
                Add(File.ReadAllBytes(path));
                loaded++;
            }
            catch (Exception exception) when (exception is ArgumentException or IOException
                or Org.BouncyCastle.Security.Certificates.CertificateException)
            {
                // Not a certificate. Skip it.
            }
        }

        return loaded;
    }

    /// <summary>
    /// Finds anchors whose subject matches the given issuer name, falling back to every
    /// anchor when none matches by name.
    /// </summary>
    /// <remarks>
    /// The fallback matters because issuer-name matching is not reliable across all
    /// issuing authorities: encodings differ between the DS's issuer field and the CSCA's
    /// subject field often enough that a strict name match produces false
    /// "no anchor" results. Trying every anchor cryptographically is slower and correct.
    /// </remarks>
    public IReadOnlyList<X509Certificate> CandidatesFor(X509Certificate documentSigner)
    {
        ArgumentNullException.ThrowIfNull(documentSigner);

        List<X509Certificate> byName =
            [.. _anchors.Where(anchor => anchor.SubjectDN.Equivalent(documentSigner.IssuerDN))];

        return byName.Count > 0 ? byName : _anchors;
    }
}
