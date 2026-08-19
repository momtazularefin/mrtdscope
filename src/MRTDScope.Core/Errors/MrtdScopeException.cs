namespace MRTDScope.Core.Errors;

/// <summary>
/// Root of every exception this library raises deliberately.
/// </summary>
/// <remarks>
/// Exceptions are for programming errors and genuinely unusable input. A document
/// that fails a security check is not an exception — it is a reported check status
/// (NFR5). Nothing in the verification layer should throw to signal "this passport
/// is bad".
/// </remarks>
public class MrtdScopeException : Exception
{
    public MrtdScopeException()
    {
    }

    public MrtdScopeException(string message)
        : base(message)
    {
    }

    public MrtdScopeException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>The card could not be reached, or the exchange failed at the transport level.</summary>
public sealed class CardTransportException : MrtdScopeException
{
    public CardTransportException()
    {
    }

    public CardTransportException(string message)
        : base(message)
    {
    }

    public CardTransportException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>Encoded data could not be parsed: malformed TLV, a truncated APDU, a bad MRZ.</summary>
public sealed class MrtdEncodingException : MrtdScopeException
{
    public MrtdEncodingException()
    {
    }

    public MrtdEncodingException(string message)
        : base(message)
    {
    }

    public MrtdEncodingException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// A secure-messaging invariant broke mid-session — a MAC did not verify, or the
/// response was not a well-formed protected response.
/// </summary>
/// <remarks>
/// This one is genuinely exceptional rather than a check result: once the channel's
/// integrity is in doubt, no further exchange on it means anything, so the session
/// cannot continue. The inspection layer catches it and records a failed
/// secure-messaging check.
/// </remarks>
public sealed class SecureMessagingException : MrtdScopeException
{
    public SecureMessagingException()
    {
    }

    public SecureMessagingException(string message)
        : base(message)
    {
    }

    public SecureMessagingException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
