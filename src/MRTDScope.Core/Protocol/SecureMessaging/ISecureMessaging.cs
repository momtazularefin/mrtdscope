using MRTDScope.Core.Apdu;

namespace MRTDScope.Core.Protocol.SecureMessaging;

/// <summary>
/// A established secure-messaging channel: it protects outgoing commands and verifies
/// and decrypts incoming responses.
/// </summary>
/// <remarks>
/// BAC produces a 3DES/Retail-MAC channel and PACE produces an AES/CMAC one (M4). Both
/// sit behind this interface so that the LDS reading code, Passive Authentication, and
/// everything above never branch on which access-control protocol was used.
/// </remarks>
public interface ISecureMessaging
{
    /// <summary>A short name for the algorithm suite, for reporting evidence.</summary>
    string Algorithm { get; }

    /// <summary>Wraps a plain command into its protected form, advancing the SSC.</summary>
    CommandApdu Protect(CommandApdu command);

    /// <summary>
    /// Verifies and unwraps a protected response, advancing the SSC.
    /// </summary>
    /// <exception cref="Errors.SecureMessagingException">
    /// The response MAC did not verify or the response was not well-formed. Once this
    /// happens the channel is no longer trustworthy and the session must end.
    /// </exception>
    ResponseApdu Unprotect(ResponseApdu response);
}
