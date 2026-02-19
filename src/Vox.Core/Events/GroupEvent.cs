using Vox.Core.Groups;
using Vox.Core.Identity;

namespace Vox.Core.Events;

/// <summary>
/// Base type for all group events in the event-sourced log.
/// Each event is signed by its author and references parent events for causal ordering.
/// </summary>
public sealed class GroupEvent
{
    public required Guid EventId { get; init; }
    public required GroupId GroupId { get; init; }
    public required PeerId Author { get; init; }
    public required ulong LamportClock { get; init; }
    public required GroupEventType EventType { get; init; }

    /// <summary>Parent event IDs for causal ordering.</summary>
    public List<Guid> ParentIds { get; init; } = [];

    /// <summary>Serialized event payload (type-specific).</summary>
    public required byte[] Payload { get; init; }

    /// <summary>Ed25519 signature over all fields except itself.</summary>
    public required byte[] Signature { get; init; }
}

public enum GroupEventType : byte
{
    MemberJoined = 0x01,
    MemberLeft = 0x02,
    ChatMessage = 0x03,
    PresenceChanged = 0x04,
    GroupMetadataChanged = 0x05,
}
