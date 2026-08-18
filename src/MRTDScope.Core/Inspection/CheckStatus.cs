namespace MRTDScope.Core.Inspection;

/// <summary>
/// The outcome of a single inspection check.
/// </summary>
/// <remarks>
/// The distinction between <see cref="Failed"/>, <see cref="Inconclusive"/> and
/// <see cref="Unavailable"/> is deliberate and load-bearing. Collapsing them into a
/// boolean is the defect this project exists to avoid: "could not verify" is not
/// "verification failed", and neither is "verified successfully".
/// </remarks>
public enum CheckStatus
{
    /// <summary>
    /// The check ran and the verification succeeded. Never reachable without evidence.
    /// </summary>
    Passed,

    /// <summary>
    /// The check ran and the verification failed. The document did not satisfy it.
    /// </summary>
    Failed,

    /// <summary>
    /// The check could not reach a verdict because required material was absent —
    /// most commonly a trust anchor for the document's issuer. This is not a failure
    /// of the document and must never be reported as one.
    /// </summary>
    Inconclusive,

    /// <summary>
    /// The check does not apply to this document. A document that does not offer
    /// Active Authentication has no DG15, and that is not a defect.
    /// </summary>
    NotApplicable,

    /// <summary>
    /// The check is not supported by this build, or the protocol path could not be
    /// exercised. Extended Access Control reports this because MRTDScope holds no
    /// terminal certificate chain. It is never reported as success.
    /// </summary>
    Unavailable,
}
