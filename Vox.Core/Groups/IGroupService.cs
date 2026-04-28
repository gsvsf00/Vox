namespace Vox.Core.Groups;

public interface IGroupService
{
    Task<GroupInfo> CreateGroupAsync(string name);
    Task<string> CreateInviteAsync(GroupId groupId, InviteOptions? options = null);
    Task<JoinResult> JoinViaInviteAsync(string inviteUrl, string? password = null);
    Task LeaveGroupAsync(GroupId groupId);
    IReadOnlyList<GroupInfo> GetJoinedGroups();
    IObservable<Events.GroupEvent> GroupEvents { get; }
}

public sealed record InviteOptions(
    TimeSpan? Expiry = null,
    bool SingleUse = false,
    string? Password = null
);

public sealed record JoinResult(bool Success, string? Error, GroupInfo? Group);
