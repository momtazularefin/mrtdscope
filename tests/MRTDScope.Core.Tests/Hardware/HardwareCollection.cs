namespace MRTDScope.Core.Tests.Hardware;

/// <summary>
/// Serializes every test that touches a physical reader.
/// </summary>
/// <remarks>
/// xUnit runs test classes in parallel by default, which is right for the 150-odd tests
/// that touch nothing outside the process — and wrong the moment two of them reach for
/// the same passport. A contactless card holds one secure-messaging session: when a
/// second BAC handshake runs against the same chip, it replaces the session keys the
/// first one established, and the first session's next command comes back 6985,
/// "conditions of use not satisfied".
/// <para>
/// That failure looks exactly like a protocol defect and is nothing of the sort. Marking
/// the hardware classes as one non-parallel collection makes the card the exclusive
/// resource it physically is, without slowing the rest of the suite.
/// </para>
/// </remarks>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class HardwareCollection
{
    public const string Name = "Hardware (exclusive card access)";
}
