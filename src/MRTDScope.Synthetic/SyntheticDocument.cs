using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using MRTDScope.Core.Lds;
using MRTDScope.Core.Mrz;
using MRTDScope.Core.Tlv;
using MRTDScope.Core.Verification;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.X509;

namespace MRTDScope.Synthetic;

/// <summary>
/// A complete synthetic eMRTD: its files, its MRZ key, and the signing hierarchy that
/// vouches for it.
/// </summary>
/// <remarks>
/// <b>This is not forgery tooling and cannot be used as such.</b> Every document
/// generates its own throwaway CSCA, so nothing it produces can chain to any real
/// issuing authority — a genuine inspection system rejects it at the trust anchor, which
/// is exactly the behaviour MRTDScope's own tests assert. Its purpose is the opposite of
/// forgery: to prove, on every commit, that the verification chain rejects what it should.
/// <para>
/// Nothing here is committed. The hierarchy is generated per document at run time
/// (NFR3, D006).
/// </para>
/// </remarks>
public sealed class SyntheticDocument
{
    /// <summary>id-icao-mrtd-security-ldsSecurityObject.</summary>
    private const string LdsSecurityObjectOid = "2.23.136.1.1.1";

    private static readonly SecureRandom Random = new();

    internal SyntheticDocument(
        MrzKey mrzKey,
        IReadOnlyDictionary<int, byte[]> dataGroups,
        byte[] efCom,
        byte[] efSod,
        X509Certificate csca,
        X509Certificate documentSigner,
        byte[]? efCardAccess = null)
    {
        MrzKey = mrzKey;
        DataGroups = dataGroups;
        EfCom = efCom;
        EfSod = efSod;
        Csca = csca;
        DocumentSigner = documentSigner;
        EfCardAccess = efCardAccess;
    }

    /// <summary>
    /// Raw EF.CardAccess, or <c>null</c> for a BAC-only document.
    /// </summary>
    /// <remarks>
    /// Its absence is how a chip says it predates Supplemental Access Control, so leaving
    /// it null models a real and still-common document rather than a broken one.
    /// </remarks>
    public byte[]? EfCardAccess { get; }

    /// <summary>The PACE protocol OID this document advertises, when it advertises one.</summary>
    public string? PaceProtocolOid { get; init; }

    /// <summary>The standardized domain parameter identifier for that variant.</summary>
    public int? PaceParameterId { get; init; }

    /// <summary>The Active Authentication private key, when the document supports it.</summary>
    public AsymmetricKeyParameter? ActiveAuthPrivateKey { get; init; }

    /// <summary>The Chip Authentication static private key, when supported.</summary>
    public AsymmetricKeyParameter? ChipAuthPrivateKey { get; init; }

    /// <summary>The curve the Chip Authentication key lives on.</summary>
    public string? ChipAuthCurve { get; init; }

    /// <summary>
    /// Builds DG15: the Active Authentication public key as a SubjectPublicKeyInfo.
    /// </summary>
    internal static byte[] BuildDg15(AsymmetricKeyParameter publicKey) =>
        BerTlv.Encode(
            DataGroup.Dg15.Tag,
            SubjectPublicKeyInfoFactory
                .CreateSubjectPublicKeyInfo(publicKey)
                .GetEncoded("DER"));

    /// <summary>Generates an RSA key pair for Active Authentication.</summary>
    internal static AsymmetricCipherKeyPair GenerateActiveAuthKeys() => GenerateKeyPair();

    /// <summary>Generates an EC key pair for Chip Authentication on a named curve.</summary>
    internal static AsymmetricCipherKeyPair GenerateChipAuthKeys(string curveName)
    {
        Org.BouncyCastle.Asn1.X9.X9ECParameters curve = ECNamedCurveTable.GetByName(curveName)!;
        ECDomainParameters domain = new(curve.Curve, curve.G, curve.N, curve.H);

        ECKeyPairGenerator generator = new();
        generator.Init(new ECKeyGenerationParameters(domain, Random));

        return generator.GenerateKeyPair();
    }

    /// <summary>
    /// Builds an EF.CardAccess advertising one PACE variant.
    /// </summary>
    /// <remarks>
    /// <c>SecurityInfos ::= SET OF SecurityInfo</c>, and a PACEInfo is
    /// <c>SEQUENCE { protocol OID, version INTEGER, parameterId INTEGER OPTIONAL }</c>
    /// (Doc 9303 Part 11 §9.2.1).
    /// </remarks>
    public static byte[] BuildEfCardAccess(
        string protocolOid = "0.4.0.127.0.7.2.2.4.2.4",
        int version = 2,
        int parameterId = 13)
    {
        DerSequence paceInfo = new(
            new DerObjectIdentifier(protocolOid),
            new DerInteger(version),
            new DerInteger(parameterId));

        Asn1EncodableVector infos = [paceInfo];

        return new DerSet(infos).GetEncoded("DER");
    }

    /// <summary>The key a terminal derives from this document's printed MRZ.</summary>
    public MrzKey MrzKey { get; }

    /// <summary>Data-group number to complete raw file content, tag and length included.</summary>
    public IReadOnlyDictionary<int, byte[]> DataGroups { get; }

    /// <summary>Raw EF.COM content.</summary>
    public byte[] EfCom { get; }

    /// <summary>Raw EF.SOD content.</summary>
    public byte[] EfSod { get; }

    /// <summary>
    /// The throwaway country-signing certificate. Supply it as a trust anchor to
    /// inspect this document successfully; withhold it to exercise the
    /// inconclusive path.
    /// </summary>
    public X509Certificate Csca { get; }

    /// <summary>The document signer that signed this document's security object.</summary>
    public X509Certificate DocumentSigner { get; }

    /// <summary>Starts building a document. See <see cref="SyntheticDocumentBuilder"/>.</summary>
    public static SyntheticDocumentBuilder Build() => new();

    /// <summary>A genuine, internally consistent document with no faults.</summary>
    public static SyntheticDocument Genuine() => Build().Create();

    // ---- Construction helpers used by the builder ---------------------------

    internal static (X509Certificate Certificate, AsymmetricKeyParameter PrivateKey) CreateAuthority(
        string subject,
        DateTime notBefore,
        DateTime notAfter)
    {
        AsymmetricCipherKeyPair keys = GenerateKeyPair();

        X509Certificate certificate = IssueCertificate(
            subject, subject, keys.Public, keys.Private, notBefore, notAfter, isAuthority: true);

        return (certificate, keys.Private);
    }

    internal static (X509Certificate Certificate, AsymmetricKeyParameter PrivateKey) CreateSigner(
        string subject,
        string issuerSubject,
        AsymmetricKeyParameter issuerPrivateKey,
        DateTime notBefore,
        DateTime notAfter)
    {
        AsymmetricCipherKeyPair keys = GenerateKeyPair();

        X509Certificate certificate = IssueCertificate(
            subject, issuerSubject, keys.Public, issuerPrivateKey, notBefore, notAfter, isAuthority: false);

        return (certificate, keys.Private);
    }

    internal static byte[] BuildEfCom(IEnumerable<int> dataGroupNumbers)
    {
        byte[] tags = [.. dataGroupNumbers
            .Select(number => DataGroup.FromNumber(number))
            .Where(group => group is not null)
            .Select(group => (byte)group!.Tag)];

        return BerTlv.Encode(
            DataGroup.Com.Tag,
            [
                .. BerTlv.Encode(0x5F01, Encoding.ASCII.GetBytes("0107")),
                .. BerTlv.Encode(0x5F36, Encoding.ASCII.GetBytes("040000")),
                .. BerTlv.Encode(0x5C, tags),
            ]);
    }

    internal static byte[] BuildEfSod(
        IReadOnlyDictionary<int, byte[]> dataGroups,
        string digestOid,
        X509Certificate signerCertificate,
        AsymmetricKeyParameter signerPrivateKey)
    {
        HashAlgorithmName algorithm = DigestAlgorithms.Resolve(digestOid);
        Asn1EncodableVector hashes = [];

        foreach ((int number, byte[] content) in dataGroups.OrderBy(pair => pair.Key))
        {
            hashes.Add(new DerSequence(
                new DerInteger(number),
                new DerOctetString(DigestAlgorithms.ComputeHash(algorithm, content))));
        }

        byte[] securityObject = new DerSequence(
            new DerInteger(0),
            new AlgorithmIdentifier(new DerObjectIdentifier(digestOid), DerNull.Instance),
            new DerSequence(hashes)).GetEncoded("DER");

        CmsSignedDataGenerator generator = new();

        generator.AddSignerInfoGenerator(new SignerInfoGeneratorBuilder().Build(
            new Asn1SignatureFactory("SHA256WITHRSA", signerPrivateKey, Random),
            signerCertificate));

        generator.AddCertificates(
            CollectionUtilities.CreateStore<X509Certificate>([signerCertificate]));

        CmsSignedData signed = generator.Generate(
            LdsSecurityObjectOid,
            new CmsProcessableByteArray(securityObject),
            encapsulate: true);

        return BerTlv.Encode(DataGroup.Sod.Tag, signed.GetEncoded());
    }

    /// <summary>
    /// Builds DG14: the SecurityInfos the issuer signs, wrapped in tag 0x6E.
    /// </summary>
    /// <remarks>
    /// DG14 carries the same protocol offers as EF.CardAccess but is covered by the
    /// Document Security Object, which is what makes it the authority when the two
    /// disagree.
    /// </remarks>
    internal static byte[] BuildDg14(string protocolOid, int parameterId, int version = 2)
    {
        Asn1EncodableVector infos =
        [
            new DerSequence(
                new DerObjectIdentifier(protocolOid),
                new DerInteger(version),
                new DerInteger(parameterId)),
        ];

        return BerTlv.Encode(DataGroup.Dg14.Tag, new DerSet(infos).GetEncoded("DER"));
    }

    /// <summary>
    /// Builds DG14 carrying both the Chip Authentication protocol and its public key,
    /// alongside the PACE variant.
    /// </summary>
    internal static byte[] BuildDg14WithChipAuth(
        string paceOid,
        int paceParameterId,
        string chipAuthOid,
        AsymmetricKeyParameter chipAuthPublicKey)
    {
        Asn1EncodableVector infos =
        [
            new DerSequence(
                new DerObjectIdentifier(paceOid),
                new DerInteger(2),
                new DerInteger(paceParameterId)),

            // ChipAuthenticationInfo: protocol and version.
            new DerSequence(
                new DerObjectIdentifier(chipAuthOid),
                new DerInteger(1)),

            // ChipAuthenticationPublicKeyInfo: id-PK-ECDH and the static key.
            new DerSequence(
                new DerObjectIdentifier("0.4.0.127.0.7.2.2.1.2"),
                SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(chipAuthPublicKey)),
        ];

        return BerTlv.Encode(DataGroup.Dg14.Tag, new DerSet(infos).GetEncoded("DER"));
    }

    /// <summary>Builds a DG1 file around an MRZ string.</summary>
    internal static byte[] BuildDg1(string mrz) =>
        BerTlv.Encode(DataGroup.Dg1.Tag, BerTlv.Encode(0x5F1F, Encoding.ASCII.GetBytes(mrz)));

    /// <summary>
    /// Builds a DG2 file: the CBEFF wrapper around an ISO/IEC 19794-5 facial record.
    /// </summary>
    internal static byte[] BuildDg2(byte[] imageBytes, byte imageDataType = 0)
    {
        int recordDataLength = 20 + 12 + imageBytes.Length;

        byte[] facialInformation = new byte[20];
        BinaryPrimitives.WriteUInt32BigEndian(facialInformation.AsSpan(0, 4), (uint)recordDataLength);

        byte[] imageInformation = new byte[12];
        imageInformation[0] = 0x01;
        imageInformation[1] = imageDataType;
        BinaryPrimitives.WriteUInt16BigEndian(imageInformation.AsSpan(2, 2), 420);
        BinaryPrimitives.WriteUInt16BigEndian(imageInformation.AsSpan(4, 2), 540);

        byte[] header = new byte[14];
        "FAC\0"u8.CopyTo(header);
        "010\0"u8.CopyTo(header.AsSpan(4));
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(8, 4), (uint)(14 + recordDataLength));
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(12, 2), 1);

        byte[] biometricData = [.. header, .. facialInformation, .. imageInformation, .. imageBytes];

        return BerTlv.Encode(
            DataGroup.Dg2.Tag,
            BerTlv.Encode(
                0x7F61,
                [
                    .. BerTlv.Encode(0x02, [0x01]),
                    .. BerTlv.Encode(
                        0x7F60,
                        [
                            .. BerTlv.Encode(0xA1, [0x81, 0x01, 0x02]),
                            .. BerTlv.Encode(0x5F2E, biometricData),
                        ]),
                ]));
    }

    private static AsymmetricCipherKeyPair GenerateKeyPair()
    {
        RsaKeyPairGenerator generator = new();
        generator.Init(new RsaKeyGenerationParameters(
            BigInteger.ValueOf(0x10001), Random, 2048, 100));
        return generator.GenerateKeyPair();
    }

    private static X509Certificate IssueCertificate(
        string subject,
        string issuer,
        AsymmetricKeyParameter subjectPublicKey,
        AsymmetricKeyParameter issuerPrivateKey,
        DateTime notBefore,
        DateTime notAfter,
        bool isAuthority)
    {
        X509V3CertificateGenerator generator = new();

        generator.SetSerialNumber(new BigInteger(64, Random).Abs().Add(BigInteger.One));
        generator.SetIssuerDN(new X509Name(issuer));
        generator.SetSubjectDN(new X509Name(subject));
        generator.SetNotBefore(notBefore);
        generator.SetNotAfter(notAfter);
        generator.SetPublicKey(subjectPublicKey);
        generator.AddExtension(
            X509Extensions.BasicConstraints, critical: true, new BasicConstraints(isAuthority));

        return generator.Generate(
            new Asn1SignatureFactory("SHA256WITHRSA", issuerPrivateKey, Random));
    }
}
