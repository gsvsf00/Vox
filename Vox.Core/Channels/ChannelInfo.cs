using Vox.Core.Groups;

namespace Vox.Core.Channels;

/// <summary>
/// Represents a text or voice channel within a group.
/// MVP supports text channels only; voice channels deferred.
/// </summary>
public sealed class ChannelInfo
{
    public required Guid Id { get; init; }
    public required GroupId GroupId { get; init; }
    public required string Name { get; set; }
    public required ChannelType Type { get; init; }
    public int SortOrder { get; set; }
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;
}

public enum ChannelType : byte
{
    Text = 0,
    Voice = 1,
}
