using MRTDScope.Core.Errors;
using MRTDScope.Core.Tlv;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace MRTDScope.Core.Lds;

/// <summary>
/// EF.SOD — the Document Security Object, a CMS SignedData wrapped in tag 0x77
/// (ICAO Doc 9303 Part 10 §4.6.2).
/// </summary>
public sealed class EfSod
{
    private readonly CmsSignedData _signedData;

    private EfSod(
        CmsSignedData signedData,
        LdsSecurityObject securityObject,
        IReadOnlyList<X509Certificate> certificates)
    {
        _signedData = signedData;
        SecurityObject = securityObject;
        Certificates = certificates;
    }

    /// <summary>The signed list of data-group digests.</summary>
    public LdsSecurityObject SecurityObject { get; }

    /// <summary>Every certificate carried in the SignedData, usually just the Document Signer.</summary>
    public IReadOnlyList<X509Certificate> Certificates { get; }

    /// <summary>
    /// The Document Signer certificate, or <c>null</c> when the SOD carries none.
    /// </summary>
    /// <remarks>
    /// Doc 9303 requires States to include it. When more than one certificate is present,
    /// the one matching the signer identifier is chosen rather than simply taking the
    /// first — the harvested code took the first unconditionally, which picks arbitrarily
    /// on any SOD carrying a chain.
    /// </remarks>
    public X509Certificate? DocumentSigner { get; private init; }

    /// <summary>Parses the raw EF.SOD file content, tag 0x77 included.</summary>
    public static EfSod Parse(ReadOnlySpan<byte> fileContent)
    {
        IReadOnlyList<BerTlv> outer = BerTlv.Parse(fileContent);
        BerTlv root = BerTlv.Find(outer, DataGroup.Sod.Tag)
            ?? throw new MrtdEncodingException(
                $"EF.SOD must be wrapped in tag 0x{DataGroup.Sod.Tag:X2}.");

        CmsSignedData signedData;
        try
        {
            signedData = new CmsSignedData(
                ContentInfo.GetInstance(Asn1Object.FromByteArray(root.Value.ToArray())));
        }
        catch (Exception exception) when (exception is IOException or ArgumentException or CmsException)
        {
            throw new MrtdEncodingException(
                "EF.SOD does not contain a well-formed CMS SignedData structure.", exception);
        }

        if (signedData.SignedContent is null)
        {
            throw new MrtdEncodingException(
                "EF.SOD carries no encapsulated content, so there is no security object to verify.");
        }

        using MemoryStream buffer = new();
        signedData.SignedContent.Write(buffer);
        LdsSecurityObject securityObject = LdsSecurityObject.Parse(buffer.ToArray());

        List<X509Certificate> certificates =
            [.. signedData.GetCertificates().EnumerateMatches(null)];

        return new EfSod(signedData, securityObject, certificates)
        {
            DocumentSigner = SelectDocumentSigner(signedData, certificates),
        };
    }

    /// <summary>
    /// Verifies the CMS signature over the security object using the Document Signer.
    /// </summary>
    /// <param name="failureDetail">Why verification failed, when it did.</param>
    /// <returns><c>true</c> when a signer verified.</returns>
    /// <remarks>
    /// Returns a boolean with detail rather than throwing: an invalid SOD signature is a
    /// verdict about the document and belongs in the report as a failed check (NFR5).
    /// </remarks>
    public bool VerifySignature(out string failureDetail)
    {
        if (DocumentSigner is null)
        {
            failureDetail = "The SOD carries no Document Signer certificate to verify against.";
            return false;
        }

        SignerInformationStore signers = _signedData.GetSignerInfos();

        if (signers.Count == 0)
        {
            failureDetail = "The SOD carries no SignerInfo.";
            return false;
        }

        foreach (SignerInformation signer in signers.GetSigners())
        {
            try
            {
                // Verify against the public key, not the certificate.
                //
                // The certificate overload also checks the certificate's validity window
                // and throws when it has lapsed. That would conflate two independent
                // questions: whether this signature is mathematically valid, and whether
                // the certificate that made it is currently in date. They belong to
                // different checks — the second is the chain check's job (D004), which
                // reports an expired signer with its own reason code.
                //
                // The distinction is not academic. Passports routinely outlive the
                // Document Signer that issued them, so a genuine document presented after
                // its signer expired must still report a valid SOD signature and a failed
                // chain, rather than a misleading "signature invalid" or an exception
                // that aborts the whole inspection.
                if (signer.Verify(DocumentSigner.GetPublicKey()))
                {
                    failureDetail = string.Empty;
                    return true;
                }
            }
            catch (Exception exception) when (exception
                is CmsException
                or SecurityUtilityException
                or ArgumentException
                or Org.BouncyCastle.Security.Certificates.CertificateException)
            {
                failureDetail = $"Signature verification could not complete: {exception.Message}";
                return false;
            }
        }

        failureDetail = "No SignerInfo verified under the Document Signer certificate.";
        return false;
    }

    /// <summary>The signature algorithm OID of the first signer, for reporting evidence.</summary>
    public string? SignatureAlgorithmOid =>
        _signedData.GetSignerInfos().GetSigners().FirstOrDefault()?.SignatureAlgorithm.Algorithm.Id;

    /// <summary>The digest algorithm OID of the first signer.</summary>
    public string? SignerDigestAlgorithmOid =>
        _signedData.GetSignerInfos().GetSigners().FirstOrDefault()?.DigestAlgorithmID.Algorithm.Id;

    private static X509Certificate? SelectDocumentSigner(
        CmsSignedData signedData,
        IReadOnlyList<X509Certificate> certificates)
    {
        if (certificates.Count == 0)
        {
            return null;
        }

        if (certificates.Count == 1)
        {
            return certificates[0];
        }

        foreach (SignerInformation signer in signedData.GetSignerInfos().GetSigners())
        {
            X509Certificate? match = certificates.FirstOrDefault(signer.SignerID.Match);

            if (match is not null)
            {
                return match;
            }
        }

        return certificates[0];
    }
}
