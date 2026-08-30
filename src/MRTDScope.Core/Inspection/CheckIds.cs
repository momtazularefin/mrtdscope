namespace MRTDScope.Core.Inspection;

/// <summary>
/// Stable identifiers for every check MRTDScope can report.
/// </summary>
/// <remarks>
/// These strings appear in the serialized report and are part of its contract.
/// Consumers match on them, so they are renamed only with a report version change.
/// </remarks>
public static class CheckIds
{
    /// <summary>Basic Access Control completed and established a secure channel.</summary>
    public const string AccessControlBac = "access-control.bac";

    /// <summary>PACE completed and established a secure channel.</summary>
    public const string AccessControlPace = "access-control.pace";

    /// <summary>Secure messaging remained intact for the whole session.</summary>
    public const string SecureMessaging = "secure-messaging.integrity";

    /// <summary>
    /// EF.COM's advertised data groups agree with what the security object protects.
    /// </summary>
    public const string LdsComSodConsistency = "lds.com-sod-consistency";

    /// <summary>
    /// EF.CardAccess agrees with the signed copy of the same information in DG14.
    /// </summary>
    public const string LdsCardAccessAuthenticity = "lds.card-access-authenticity";

    /// <summary>The SOD's CMS signature verifies under the embedded Document Signer.</summary>
    public const string PassiveAuthSodSignature = "passive-auth.sod-signature";

    /// <summary>The Document Signer chains to a trusted CSCA and is within validity.</summary>
    public const string PassiveAuthDocumentSignerChain = "passive-auth.document-signer-chain";

    /// <summary>
    /// Every data group read from the chip hashes to the value recorded in the LDS
    /// Security Object. Without this check, Passive Authentication does not detect a
    /// substituted portrait.
    /// </summary>
    public const string PassiveAuthDataGroupHashes = "passive-auth.data-group-hashes";

    /// <summary>The chip proved possession of the DG15 private key.</summary>
    public const string ActiveAuth = "active-auth.challenge-response";

    /// <summary>Chip Authentication established a new secure channel from DG14 material.</summary>
    public const string ChipAuth = "chip-auth.key-agreement";

    /// <summary>
    /// Terminal Authentication. Always <see cref="CheckStatus.Unavailable"/> in this
    /// build; MRTDScope holds no Inspection System certificate chain.
    /// </summary>
    public const string TerminalAuth = "terminal-auth.certificate-chain";
}
