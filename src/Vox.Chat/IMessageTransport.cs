using Vox.Core.Groups;

namespace Vox.Chat;

/// <summary>
/// Abstraction for sending serialized chat packets to group members.
/// Implementations bridge to the actual transport layer (WebRTC DataChannels).
/// </summary>
public interface IMessageTransport
{
    /// <summary>
    /// Broadcast a serialized packet to all online members of a group.
    /// </summary>
    Task BroadcastAsync(GroupId groupId, byte[] packet);
}
