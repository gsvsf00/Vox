using Vox.Core.Identity;

namespace Vox.Core.Groups;

public sealed class GroupInfo
{
    public required GroupId Id { get; init; }
    public required string Name { get; set; }
    public required byte[] SymmetricKey { get; init; }
    public required PeerId Creator { get; init; }
    public required DateTimeOffset CreatedAt { get; init; }
    public List<PeerInfo> Members { get; init; } = [];
}
