using System.Security.Cryptography;
using MRTDScope.Core.Lds;
using MRTDScope.Core.Tlv;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Utilities.Collections;

namespace MRTDScope.Core.Tests.Support;

/// <summary>
/// Builds a complete country-signing hierarchy and a real, signed EF.SOD at run time.
/// </summary>
/// <remarks>
/// Everything here is generated per test and never committed (NFR3, D006). That is what
/// lets the suite exercise Passive Authentication end to end — including the failure
/// modes that matter — with no real document, no captured chip dump, and no key material
/// in history.
/// <para>
/// This is deliberately a real CMS SignedData over a real LDSSecurityObject, not a stub.
/// A verifier tested against a mock of itself proves nothing; the point is that
/// <c>EfSod.Parse</c> and <c>PassiveAuthenticator</c> see exactly the structures a chip
/// would present. It grows into the M3 synthetic chip.
/// </para>
/// </remarks>
public sealed class TestPki
{
    /// <summary>id-icao-mrtd-security-ldsSecurityObject.</summary>
    public const string LdsSecurityObjectOid = "2.23.136.1.1.1";

    private static readonly SecureRandom Random = new();

    private TestPki(
        X509Certificate cscaCertificate,
        X509Certificate documentSignerCertificate,
        AsymmetricKeyParameter documentSignerPrivateKey)
    {
        Csca = cscaCertificate;
        DocumentSigner = documentSignerCertificate;
        _documentSignerKey = documentSignerPrivateKey;
    }

    private readonly AsymmetricKeyParameter _documentSignerKey;

    public X509Certificate Csca { get; }

    public X509Certificate DocumentSigner { get; }

    /// <summary>
    /// Creates a CSCA and a Document Signer it has signed.
    /// </summary>
    /// <param name="documentSignerNotBefore">Override to build an expired signer.</param>
    /// <param name="documentSignerNotAfter">Override to build an expired signer.</param>
    /// <param name="cscaSubject">Override to build a second, unrelated authority.</param>
    /// <param name="cscaNotBefore">Override the anchor's validity start.</param>
    /// <param name="cscaNotAfter">Override the anchor's validity end.</param>
    public static TestPki Create(
        DateTime? documentSignerNotBefore = null,
        DateTime? documentSignerNotAfter = null,
        string cscaSubject = "CN=Test CSCA,C=XX",
        DateTime? cscaNotBefore = null,
        DateTime? cscaNotAfter = null)
    {
        DateTime now = DateTime.UtcNow;

        AsymmetricCipherKeyPair cscaKeys = GenerateRsaKeyPair();
        X509Certificate csca = BuildCertificate(
            subject: cscaSubject,
            issuer: cscaSubject,
            subjectPublicKey: cscaKeys.Public,
            issuerPrivateKey: cscaKeys.Private,
            notBefore: cscaNotBefore ?? now.AddYears(-1),
            notAfter: cscaNotAfter ?? now.AddYears(10),
            isCertificateAuthority: true);

        AsymmetricCipherKeyPair signerKeys = GenerateRsaKeyPair();
        X509Certificate signer = BuildCertificate(
            subject: "CN=Test Document Signer,C=XX",
            issuer: cscaSubject,
            subjectPublicKey: signerKeys.Public,
            issuerPrivateKey: cscaKeys.Private,
            notBefore: documentSignerNotBefore ?? now.AddMonths(-6),
            notAfter: documentSignerNotAfter ?? now.AddYears(3),
            isCertificateAuthority: false);

        return new TestPki(csca, signer, signerKeys.Private);
    }

    /// <summary>
    /// Builds a signed EF.SOD covering the given data groups, wrapped in tag 0x77.
    /// </summary>
    /// <param name="dataGroupContents">
    /// Data-group number to complete raw file content. The digest covers the whole file.
    /// </param>
    /// <param name="digestOid">The digest algorithm to record and use.</param>
    public byte[] BuildSod(
        IReadOnlyDictionary<int, byte[]> dataGroupContents,
        string digestOid = MRTDScope.Core.Verification.DigestAlgorithms.Sha256)
    {
        byte[] securityObject = BuildLdsSecurityObject(dataGroupContents, digestOid);

        CmsSignedDataGenerator generator = new();

        ISignatureFactory signatureFactory = new Asn1SignatureFactory(
            "SHA256WITHRSA", _documentSignerKey, Random);

        generator.AddSignerInfoGenerator(
            new SignerInfoGeneratorBuilder().Build(signatureFactory, DocumentSigner));

        generator.AddCertificates(
            CollectionUtilities.CreateStore<X509Certificate>([DocumentSigner]));

        CmsSignedData signed = generator.Generate(
            LdsSecurityObjectOid,
            new CmsProcessableByteArray(securityObject),
            encapsulate: true);

        return BerTlv.Encode(DataGroup.Sod.Tag, signed.GetEncoded());
    }

    /// <summary>
    /// Encodes an LDSSecurityObject over the given data groups.
    /// </summary>
    public static byte[] BuildLdsSecurityObject(
        IReadOnlyDictionary<int, byte[]> dataGroupContents,
        string digestOid)
    {
        HashAlgorithmName algorithm =
            MRTDScope.Core.Verification.DigestAlgorithms.Resolve(digestOid);

        Asn1EncodableVector hashes = [];

        foreach ((int number, byte[] content) in dataGroupContents.OrderBy(pair => pair.Key))
        {
            byte[] digest = MRTDScope.Core.Verification.DigestAlgorithms.ComputeHash(
                algorithm, content);

            hashes.Add(new DerSequence(
                new DerInteger(number),
                new DerOctetString(digest)));
        }

        DerSequence securityObject = new(
            new DerInteger(0),
            new AlgorithmIdentifier(new DerObjectIdentifier(digestOid), DerNull.Instance),
            new DerSequence(hashes));

        return securityObject.GetEncoded("DER");
    }

    private static AsymmetricCipherKeyPair GenerateRsaKeyPair()
    {
        RsaKeyPairGenerator generator = new();

        // 2048 bits keeps the suite fast while staying realistic. Test material only.
        generator.Init(new RsaKeyGenerationParameters(
            BigInteger.ValueOf(0x10001), Random, 2048, 100));

        return generator.GenerateKeyPair();
    }

    private static X509Certificate BuildCertificate(
        string subject,
        string issuer,
        AsymmetricKeyParameter subjectPublicKey,
        AsymmetricKeyParameter issuerPrivateKey,
        DateTime notBefore,
        DateTime notAfter,
        bool isCertificateAuthority)
    {
        X509V3CertificateGenerator generator = new();

        generator.SetSerialNumber(new BigInteger(64, Random).Abs().Add(BigInteger.One));
        generator.SetIssuerDN(new X509Name(issuer));
        generator.SetSubjectDN(new X509Name(subject));
        generator.SetNotBefore(notBefore);
        generator.SetNotAfter(notAfter);
        generator.SetPublicKey(subjectPublicKey);

        generator.AddExtension(
            X509Extensions.BasicConstraints,
            critical: true,
            new BasicConstraints(isCertificateAuthority));

        return generator.Generate(
            new Asn1SignatureFactory("SHA256WITHRSA", issuerPrivateKey, Random));
    }
}
