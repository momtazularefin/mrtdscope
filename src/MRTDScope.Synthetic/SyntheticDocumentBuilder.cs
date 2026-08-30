using MRTDScope.Core.Mrz;
using MRTDScope.Core.Verification;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;

namespace MRTDScope.Synthetic;

/// <summary>
/// The named faults a synthetic document can be built with.
/// </summary>
/// <remarks>
/// Each fault exists to make one specific check fail, and the corpus asserts that the
/// check which fails is the one named here — not merely that something went wrong. A
/// verifier that rejects every bad document for the same reason is barely better than
/// one that accepts them all, because an operator cannot act on it.
/// </remarks>
public enum DocumentFault
{
    /// <summary>Nothing wrong. The control case.</summary>
    None,

    /// <summary>
    /// A data group is altered after the security object was signed — the substituted
    /// portrait. Signature and chain stay valid; only the hashes betray it.
    /// </summary>
    TamperedDataGroup,

    /// <summary>
    /// The security object is signed by a document signer from an unrelated authority.
    /// Internally consistent, vouched for by nobody.
    /// </summary>
    SubstitutedDocumentSigner,

    /// <summary>The document signer is outside its validity window.</summary>
    ExpiredDocumentSigner,

    /// <summary>
    /// Bytes inside the security object's signature are corrupted, leaving the structure
    /// parseable but the signature invalid.
    /// </summary>
    CorruptedSodSignature,

    /// <summary>
    /// The chip returns a response whose secure-messaging checksum does not verify,
    /// as an active attacker on the contactless interface would produce.
    /// </summary>
    CorruptedSecureMessagingMac,

    /// <summary>
    /// The security object omits a data group the chip actually carries, so content is
    /// present that no issuer ever signed.
    /// </summary>
    UnsignedDataGroup,

    /// <summary>
    /// EF.CardAccess has been rewritten to advertise a weaker PACE variant than the one
    /// the issuer signed into DG14 — a protocol downgrade.
    /// </summary>
    /// <remarks>
    /// This is the attack the EF.CardAccess/DG14 cross-check exists to catch, and it is
    /// invisible from inside the session: the terminal negotiates the weaker variant in
    /// good faith and the resulting channel is cryptographically sound. Only the signed
    /// copy reveals that a stronger option was withheld.
    /// </remarks>
    DowngradedCardAccess,
}

/// <summary>
/// Builds synthetic documents, optionally with a named fault injected.
/// </summary>
public sealed class SyntheticDocumentBuilder
{
    private const string DefaultMrz =
        "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<" +
        "L898902C<3UTO6908061F9406236ZE184226B<<<<<14";

    private static readonly byte[] DefaultPortrait =
        [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01];

    private string _mrz = DefaultMrz;
    private byte[] _portrait = DefaultPortrait;
    private string _digestOid = DigestAlgorithms.Sha256;
    private DocumentFault _fault = DocumentFault.None;
    private int _tamperedDataGroup = 2;
    private bool _advertisePace;
    private string _paceOid = "0.4.0.127.0.7.2.2.4.2.4";
    private int _paceParameterId = 13;

    /// <summary>ECDH Generic Mapping with AES-256 on BrainpoolP256r1.</summary>
    private const string StrongVariantOid = "0.4.0.127.0.7.2.2.4.2.4";
    private const int StrongVariantParameterId = 13;

    /// <summary>ECDH Generic Mapping with AES-128 on NIST P-256.</summary>
    private const string WeakVariantOid = "0.4.0.127.0.7.2.2.4.2.2";
    private const int WeakVariantParameterId = 12;

    /// <summary>Overrides the MRZ, which also changes the BAC key.</summary>
    public SyntheticDocumentBuilder WithMrz(string mrz)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(mrz);
        _mrz = mrz;
        return this;
    }

    /// <summary>Overrides the portrait payload carried in DG2.</summary>
    public SyntheticDocumentBuilder WithPortrait(byte[] portrait)
    {
        ArgumentNullException.ThrowIfNull(portrait);
        _portrait = portrait;
        return this;
    }

    /// <summary>Selects the digest algorithm the security object records.</summary>
    public SyntheticDocumentBuilder WithDigest(string digestOid)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(digestOid);
        _digestOid = digestOid;
        return this;
    }

    /// <summary>
    /// Gives the document an EF.CardAccess advertising a PACE variant.
    /// </summary>
    /// <param name="protocolOid">Defaults to ECDH Generic Mapping with AES-256.</param>
    /// <param name="parameterId">Standardized domain parameters; 13 is BrainpoolP256r1.</param>
    public SyntheticDocumentBuilder AdvertisingPace(
        string protocolOid = "0.4.0.127.0.7.2.2.4.2.4",
        int parameterId = 13)
    {
        _advertisePace = true;
        _paceOid = protocolOid;
        _paceParameterId = parameterId;
        return this;
    }

    /// <summary>Injects a named fault.</summary>
    /// <param name="dataGroup">Which group to alter, for the tampering faults.</param>
    public SyntheticDocumentBuilder WithFault(DocumentFault fault, int dataGroup = 2)
    {
        _fault = fault;
        _tamperedDataGroup = dataGroup;

        // The downgrade fault rewrites the unsigned file to the weaker variant while
        // DG14 keeps the strong one the issuer signed.
        if (fault == DocumentFault.DowngradedCardAccess)
        {
            _advertisePace = true;
            _paceOid = WeakVariantOid;
            _paceParameterId = WeakVariantParameterId;
        }

        return this;
    }

    /// <summary>The fault this builder will inject.</summary>
    public DocumentFault Fault => _fault;

    /// <summary>Builds the document.</summary>
    public SyntheticDocument Create()
    {
        DateTime now = DateTime.UtcNow;

        (X509Certificate csca, AsymmetricKeyParameter cscaKey) =
            SyntheticDocument.CreateAuthority(
                "CN=Synthetic CSCA,C=XX", now.AddYears(-2), now.AddYears(10));

        bool expired = _fault == DocumentFault.ExpiredDocumentSigner;

        (X509Certificate signer, AsymmetricKeyParameter signerKey) =
            SyntheticDocument.CreateSigner(
                "CN=Synthetic Document Signer,C=XX",
                "CN=Synthetic CSCA,C=XX",
                cscaKey,
                expired ? now.AddYears(-5) : now.AddMonths(-6),
                expired ? now.AddYears(-1) : now.AddYears(3));

        // A signer from an unrelated authority: correctly formed, simply not ours.
        if (_fault == DocumentFault.SubstitutedDocumentSigner)
        {
            (X509Certificate otherCsca, AsymmetricKeyParameter otherCscaKey) =
                SyntheticDocument.CreateAuthority(
                    "CN=Unrelated Authority,C=ZZ", now.AddYears(-2), now.AddYears(10));

            (signer, signerKey) = SyntheticDocument.CreateSigner(
                "CN=Unrelated Document Signer,C=ZZ",
                "CN=Unrelated Authority,C=ZZ",
                otherCscaKey,
                now.AddMonths(-6),
                now.AddYears(3));

            _ = otherCsca;
        }

        Dictionary<int, byte[]> dataGroups = new()
        {
            [1] = SyntheticDocument.BuildDg1(_mrz),
            [2] = SyntheticDocument.BuildDg2(_portrait),
        };

        bool downgrade = _fault == DocumentFault.DowngradedCardAccess;

        // A downgrade needs PACE to exist at all, so the fault implies it.
        if (_advertisePace || downgrade)
        {
            // DG14 records what the issuer actually provisioned. Under the downgrade
            // fault that is the strong variant, while EF.CardAccess below is rewritten
            // to offer only the weak one.
            dataGroups[14] = SyntheticDocument.BuildDg14(
                downgrade ? StrongVariantOid : _paceOid,
                downgrade ? StrongVariantParameterId : _paceParameterId);
        }

        // The security object is signed over the genuine content. Tampering happens
        // afterwards, exactly as a chip-substitution attack would: the signature stays
        // untouched and valid, and only the recomputed digests disagree.
        Dictionary<int, byte[]> signedContent = _fault == DocumentFault.UnsignedDataGroup
            ? new Dictionary<int, byte[]> { [1] = dataGroups[1] }
            : new Dictionary<int, byte[]>(dataGroups);

        byte[] sod = SyntheticDocument.BuildEfSod(signedContent, _digestOid, signer, signerKey);

        if (_fault == DocumentFault.CorruptedSodSignature)
        {
            // Deep inside the signature blob, so the CMS structure still parses.
            sod[^20] ^= 0xFF;
        }

        if (_fault == DocumentFault.TamperedDataGroup)
        {
            byte[] original = dataGroups[_tamperedDataGroup];
            byte[] altered = [.. original];
            altered[^1] ^= 0xFF;
            dataGroups[_tamperedDataGroup] = altered;
        }

        byte[] com = SyntheticDocument.BuildEfCom(dataGroups.Keys);

        MrzKey key = MrzKey.Create(
            _mrz.Substring(44, 9).TrimEnd(MrzKey.Filler),
            _mrz.Substring(57, 6),
            _mrz.Substring(65, 6));

        byte[]? cardAccess = _advertisePace || downgrade
            ? SyntheticDocument.BuildEfCardAccess(_paceOid, parameterId: _paceParameterId)
            : null;

        return new SyntheticDocument(key, dataGroups, com, sod, csca, signer, cardAccess)
        {
            PaceProtocolOid = _advertisePace ? _paceOid : null,
            PaceParameterId = _advertisePace ? _paceParameterId : null,
        };
    }

    /// <summary>Builds the document and the chip that serves it.</summary>
    public SyntheticChip CreateChip() => new(Create(), _fault);
}
