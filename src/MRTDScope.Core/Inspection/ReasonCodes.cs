namespace MRTDScope.Core.Inspection;

/// <summary>
/// Stable machine-readable reasons accompanying a non-passing check.
/// </summary>
/// <remarks>
/// A reason code explains <em>why</em> a check did not pass, so that a consumer can
/// react differently to "this document is bad" and "I was not equipped to judge it".
/// Like <see cref="CheckIds"/>, these strings are part of the report contract.
/// </remarks>
public static class ReasonCodes
{
    // --- Inconclusive: MRTDScope could not reach a verdict. -------------------

    /// <summary>No CSCA trust anchor was configured for the document's issuer.</summary>
    public const string NoTrustAnchor = "no-trust-anchor";

    /// <summary>Revocation status could not be determined.</summary>
    public const string RevocationUnknown = "revocation-unknown";

    // --- NotApplicable: the document does not offer this. --------------------

    /// <summary>The document does not carry the data group this check requires.</summary>
    public const string DataGroupAbsent = "data-group-absent";

    /// <summary>The chip does not advertise support for this protocol.</summary>
    public const string ProtocolNotOffered = "protocol-not-offered";

    // --- Unavailable: this build cannot perform the check. -------------------

    /// <summary>The protocol is not implemented in this build.</summary>
    public const string NotImplemented = "not-implemented";

    /// <summary>
    /// The check requires credentials MRTDScope does not hold, such as an Inspection
    /// System certificate chain for Terminal Authentication.
    /// </summary>
    public const string CredentialsNotHeld = "credentials-not-held";

    // --- Failed: the document did not satisfy the check. ---------------------

    /// <summary>A cryptographic signature did not verify.</summary>
    public const string SignatureInvalid = "signature-invalid";

    /// <summary>A data group's hash did not match the LDS Security Object.</summary>
    public const string HashMismatch = "hash-mismatch";

    /// <summary>The certificate chain did not build to a trusted anchor.</summary>
    public const string ChainNotTrusted = "chain-not-trusted";

    /// <summary>A certificate was outside its validity window.</summary>
    public const string CertificateExpired = "certificate-expired";

    /// <summary>A certificate is known to be revoked.</summary>
    public const string CertificateRevoked = "certificate-revoked";

    /// <summary>Access control did not complete; the supplied password was rejected.</summary>
    public const string AccessDenied = "access-denied";

    /// <summary>A secure-messaging MAC did not verify.</summary>
    public const string SecureMessagingIntegrity = "secure-messaging-integrity";

    /// <summary>A challenge-response answer did not bind to the challenge sent.</summary>
    public const string ChallengeMismatch = "challenge-mismatch";

    /// <summary>Encoded data could not be parsed.</summary>
    public const string MalformedData = "malformed-data";

    /// <summary>The transport failed before the check could complete.</summary>
    public const string TransportFailure = "transport-failure";
}
