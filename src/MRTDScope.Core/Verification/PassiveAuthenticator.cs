using System.Security.Cryptography;
using MRTDScope.Core.Inspection;
using MRTDScope.Core.Lds;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace MRTDScope.Core.Verification;

/// <summary>
/// Passive Authentication, reported as three independent checks (D004).
/// </summary>
/// <remarks>
/// The three checks answer genuinely different questions, and collapsing them into one
/// "PA passed" is how a reader stops being auditable:
/// <list type="number">
/// <item>Is the SOD internally consistent — does its signature verify under the
/// Document Signer it carries? A self-signed forgery passes this.</item>
/// <item>Is that Document Signer one a trusted CSCA vouched for? This is what a forged
/// SOD fails, and it is <em>unanswerable</em> without an anchor, hence
/// <see cref="CheckStatus.Inconclusive"/> rather than a failure (D005).</item>
/// <item>Do the data groups actually on the chip still hash to the values the issuer
/// signed? <b>Only this check detects a substituted portrait.</b> The code this project
/// harvests from omitted it entirely, which is why a chip with a replaced DG2 passed its
/// Passive Authentication.</item>
/// </list>
/// </remarks>
public sealed class PassiveAuthenticator
{
    private readonly TrustStore _trustStore;
    private readonly TimeProvider _timeProvider;

    public PassiveAuthenticator(TrustStore trustStore, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(trustStore);

        _trustStore = trustStore;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>
    /// Runs all three checks.
    /// </summary>
    /// <param name="sod">The parsed Document Security Object.</param>
    /// <param name="dataGroupContents">
    /// Data-group number to the <b>complete raw file content</b> as read from the chip,
    /// BER tag and length included. The digest covers the whole file, so passing only the
    /// value would fail every comparison.
    /// </param>
    public IReadOnlyList<InspectionCheck> Verify(
        EfSod sod,
        IReadOnlyDictionary<int, ReadOnlyMemory<byte>> dataGroupContents)
    {
        ArgumentNullException.ThrowIfNull(sod);
        ArgumentNullException.ThrowIfNull(dataGroupContents);

        return
        [
            CheckSodSignature(sod),
            CheckDocumentSignerChain(sod),
            CheckDataGroupHashes(sod, dataGroupContents),
        ];
    }

    private static InspectionCheck CheckSodSignature(EfSod sod)
    {
        if (sod.DocumentSigner is null)
        {
            return InspectionCheck.Inconclusive(
                CheckIds.PassiveAuthSodSignature,
                ReasonCodes.NoTrustAnchor,
                "The SOD carries no Document Signer certificate, so its signature cannot be checked.");
        }

        if (!sod.VerifySignature(out string failureDetail))
        {
            return InspectionCheck.Failed(
                CheckIds.PassiveAuthSodSignature,
                ReasonCodes.SignatureInvalid,
                failureDetail,
                Evidence.Of("signer-subject", sod.DocumentSigner.SubjectDN.ToString()));
        }

        return InspectionCheck.Passed(
            CheckIds.PassiveAuthSodSignature,
            "The security object's signature verifies under the embedded Document Signer.",
            Evidence.Of("signer-subject", sod.DocumentSigner.SubjectDN.ToString()),
            Evidence.Of("signer-serial", sod.DocumentSigner.SerialNumber.ToString()),
            Evidence.Of("signature-algorithm", sod.SignatureAlgorithmOid ?? "unknown"),
            Evidence.Of("digest-algorithm", sod.SecurityObject.DigestAlgorithmOid));
    }

    private InspectionCheck CheckDocumentSignerChain(EfSod sod)
    {
        if (sod.DocumentSigner is null)
        {
            return InspectionCheck.Inconclusive(
                CheckIds.PassiveAuthDocumentSignerChain,
                ReasonCodes.NoTrustAnchor,
                "The SOD carries no Document Signer certificate to chain.");
        }

        X509Certificate signer = sod.DocumentSigner;

        // D005: no anchor means the question is unanswerable. It is never a failure of
        // the document, and reporting it as one would train an operator to ignore the tool.
        if (_trustStore.IsEmpty)
        {
            return InspectionCheck.Inconclusive(
                CheckIds.PassiveAuthDocumentSignerChain,
                ReasonCodes.NoTrustAnchor,
                "No CSCA trust anchor is configured, so the Document Signer cannot be " +
                "chained. This is a limitation of this inspection, not a finding about " +
                "the document.",
                Evidence.Of("signer-issuer", signer.IssuerDN.ToString()));
        }

        DateTime now = _timeProvider.GetUtcNow().UtcDateTime;

        foreach (X509Certificate anchor in _trustStore.CandidatesFor(signer))
        {
            try
            {
                signer.Verify(anchor.GetPublicKey());
            }
            catch (Exception exception) when (exception is InvalidKeyException or SignatureException or SecurityUtilityException)
            {
                continue;
            }

            // The signature chains. Validity is now a separate question about this
            // specific pair, and answering it precisely matters: an expired Document
            // Signer is a real finding, distinct from an untrusted one.
            if (signer.NotAfter < now || signer.NotBefore > now)
            {
                return InspectionCheck.Failed(
                    CheckIds.PassiveAuthDocumentSignerChain,
                    ReasonCodes.CertificateExpired,
                    $"The Document Signer chains to a trusted CSCA but is outside its " +
                    $"validity window ({signer.NotBefore:u} to {signer.NotAfter:u}).",
                    Evidence.Of("anchor-subject", anchor.SubjectDN.ToString()),
                    Evidence.Of("signer-not-after", signer.NotAfter.ToString("u")));
            }

            if (anchor.NotAfter < now || anchor.NotBefore > now)
            {
                return InspectionCheck.Failed(
                    CheckIds.PassiveAuthDocumentSignerChain,
                    ReasonCodes.CertificateExpired,
                    $"The Document Signer chains to a CSCA that is itself outside its " +
                    $"validity window ({anchor.NotBefore:u} to {anchor.NotAfter:u}).",
                    Evidence.Of("anchor-subject", anchor.SubjectDN.ToString()),
                    Evidence.Of("anchor-not-after", anchor.NotAfter.ToString("u")));
            }

            return InspectionCheck.Passed(
                CheckIds.PassiveAuthDocumentSignerChain,
                "The Document Signer chains to a configured CSCA trust anchor and both " +
                "certificates are within validity.",
                Evidence.Of("anchor-subject", anchor.SubjectDN.ToString()),
                Evidence.Of("signer-subject", signer.SubjectDN.ToString()),
                Evidence.Of("signer-serial", signer.SerialNumber.ToString()),
                Evidence.Of("validity", $"{signer.NotBefore:u} to {signer.NotAfter:u}"));
        }

        int anchorCount = _trustStore.Anchors.Count;

        return InspectionCheck.Failed(
            CheckIds.PassiveAuthDocumentSignerChain,
            ReasonCodes.ChainNotTrusted,
            anchorCount == 1
                ? "The Document Signer does not verify under the configured trust anchor."
                : $"The Document Signer does not verify under any of the {anchorCount} " +
                  "configured trust anchors.",
            Evidence.Of("signer-issuer", signer.IssuerDN.ToString()),
            Evidence.Of("anchors-tried", anchorCount.ToString(
                System.Globalization.CultureInfo.InvariantCulture)));
    }

    /// <summary>
    /// Compares every data group read from the chip against the digest the issuer signed.
    /// </summary>
    private static InspectionCheck CheckDataGroupHashes(
        EfSod sod,
        IReadOnlyDictionary<int, ReadOnlyMemory<byte>> dataGroupContents)
    {
        string digestOid = sod.SecurityObject.DigestAlgorithmOid;

        HashAlgorithmName algorithm;
        try
        {
            algorithm = DigestAlgorithms.Resolve(digestOid);
        }
        catch (NotSupportedException)
        {
            return InspectionCheck.Inconclusive(
                CheckIds.PassiveAuthDataGroupHashes,
                ReasonCodes.NotImplemented,
                $"The security object uses digest algorithm {digestOid}, which this build " +
                "cannot compute.");
        }

        List<Evidence> evidence = [];
        List<string> mismatched = [];
        List<int> unreadable = [];
        int compared = 0;

        foreach (int number in sod.SecurityObject.ProtectedDataGroups)
        {
            ReadOnlyMemory<byte> expected = sod.SecurityObject.DataGroupHashes[number];

            if (!dataGroupContents.TryGetValue(number, out ReadOnlyMemory<byte> content))
            {
                unreadable.Add(number);
                continue;
            }

            byte[] actual = DigestAlgorithms.ComputeHash(algorithm, content.Span);
            compared++;

            if (CryptographicOperations.FixedTimeEquals(actual, expected.Span))
            {
                evidence.Add(Evidence.Of($"DG{number}", "matches"));
            }
            else
            {
                mismatched.Add($"DG{number}");
                evidence.Add(Evidence.Of($"DG{number}", "MISMATCH"));
            }
        }

        if (mismatched.Count > 0)
        {
            return InspectionCheck.Failed(
                CheckIds.PassiveAuthDataGroupHashes,
                ReasonCodes.HashMismatch,
                $"{mismatched.Count} of {compared} compared data groups do not match the " +
                $"signed security object: {string.Join(", ", mismatched)}. The chip's " +
                "contents differ from what the issuer signed.",
                [.. evidence]);
        }

        if (compared == 0)
        {
            return InspectionCheck.Inconclusive(
                CheckIds.PassiveAuthDataGroupHashes,
                ReasonCodes.DataGroupAbsent,
                "No protected data group could be read, so nothing could be compared.");
        }

        // Some protected groups being unread is normal — DG3 and DG4 need Extended Access
        // Control, which MRTDScope never has. Say so rather than implying full coverage.
        if (unreadable.Count > 0)
        {
            evidence.Add(Evidence.Of(
                "not-compared",
                string.Join(", ", unreadable.Select(number => $"DG{number}"))));
        }

        return InspectionCheck.Passed(
            CheckIds.PassiveAuthDataGroupHashes,
            unreadable.Count == 0
                ? $"All {compared} protected data groups hash to the values the issuer signed."
                : $"All {compared} readable data groups hash to the values the issuer " +
                  $"signed. {unreadable.Count} protected group(s) were not read and so " +
                  "were not compared.",
            [.. evidence, Evidence.Of("digest-algorithm", digestOid)]);
    }
}
