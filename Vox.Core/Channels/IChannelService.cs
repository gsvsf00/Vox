using Vox.Core.Groups;

namespace Vox.Core.Channels;

/// <summary>
/// Manages text/voice channels within a group.
/// Channel mutations emit GroupEvents for state sync.
/// </summary>
public interface IChannelService
{
    /// <summary>Get all channels for a group.</summary>
    IReadOnlyList<ChannelInfo> GetChannels(GroupId groupId);

    /// <summary>Create a new text channel. Returns the created channel.</summary>
    Task<ChannelInfo> CreateChannelAsync(GroupId groupId, string name, ChannelType type = ChannelType.Text);

    /// <summary>Rename a channel.</summary>
    Task RenameChannelAsync(GroupId groupId, Guid channelId, string newName);

    /// <summary>Delete a channel (admin only).</summary>
    Task DeleteChannelAsync(GroupId groupId, Guid channelId);

    /// <summary>Fires when channels change.</summary>
    IObservable<ChannelEvent> ChannelEvents { get; }
}

public sealed record ChannelEvent(GroupId GroupId, Guid ChannelId, ChannelEventType Type);

public enum ChannelEventType : byte
{
    Created = 0,
    Renamed = 1,
    Deleted = 2,
}
