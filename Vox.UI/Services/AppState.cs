using Vox.Chat;
using Vox.Core.Channels;
using Vox.Core.Contacts;
using Vox.Core.Groups;
using Vox.Core.Identity;
using Vox.Network.Presence;

namespace Vox.Services;

/// <summary>
/// Application facade: the single entry-point the Blazor UI uses.
/// Wraps all service interfaces. UI never talks to transport/crypto directly.
/// </summary>
public sealed class AppState : IDisposable
{
    private readonly IGroupService _groups;
    private readonly IChatService _chat;
    private readonly IPresenceService _presence;
    private readonly IIdentityService _identity;
    private readonly IContactService _contacts;
    private readonly IChannelService _channels;
    private readonly List<IDisposable> _subscriptions = [];

    public AppState(
        IGroupService groups,
        IChatService chat,
        IPresenceService presence,
        IIdentityService identity,
        IContactService contacts,
        IChannelService channels,
        LocalIdentity localIdentity)
    {
        _groups = groups;
        _chat = chat;
        _presence = presence;
        _identity = identity;
        _contacts = contacts;
        _channels = channels;
        CurrentIdentity = localIdentity;
        LocalStatus = PeerStatus.Online;

        _subscriptions.Add(_chat.IncomingMessages.Subscribe(new Observer<ChatMessageReceived>(OnChatMessage)));
        _subscriptions.Add(_groups.GroupEvents.Subscribe(new Observer<Core.Events.GroupEvent>(OnGroupEvent)));
        _subscriptions.Add(_presence.PresenceChanges.Subscribe(new Observer<PresenceChanged>(OnPresenceChanged)));
        _subscriptions.Add(_contacts.ContactEvents.Subscribe(new Observer<ContactEvent>(OnContactEvent)));
        _subscriptions.Add(_channels.ChannelEvents.Subscribe(new Observer<ChannelEvent>(OnChannelEvent)));
    }

    // ── Identity ────────────────────────────────────
    public LocalIdentity? CurrentIdentity { get; private set; }
    public PeerStatus LocalStatus { get; private set; }

    public void ChangeDisplayName(string newName)
    {
        if (CurrentIdentity is null) return;
        // LocalIdentity is immutable by design; create a new one with the updated name
        CurrentIdentity = new LocalIdentity
        {
            Username = newName,
            Discriminator = CurrentIdentity.Discriminator,
            SigningPublicKey = CurrentIdentity.SigningPublicKey,
            SigningPrivateKey = CurrentIdentity.SigningPrivateKey,
            EncryptionPublicKey = CurrentIdentity.EncryptionPublicKey,
            EncryptionPrivateKey = CurrentIdentity.EncryptionPrivateKey,
            CreatedAt = CurrentIdentity.CreatedAt,
        };
        StateChanged?.Invoke();
    }

    public async Task SetLocalStatusAsync(PeerStatus status)
    {
        LocalStatus = status;
        await _presence.SetLocalStatusAsync(status);
        StateChanged?.Invoke();
    }

    public string GetContactLink() => _contacts.CreateContactLink();

    // ── Groups ──────────────────────────────────────
    public GroupInfo? SelectedGroup { get; private set; }
    public IReadOnlyList<GroupInfo> Groups => _groups.GetJoinedGroups();

    public void SelectGroup(GroupInfo? group)
    {
        SelectedGroup = group;
        SelectedChannel = null;

        if (group is not null)
        {
            // Auto-select first text channel
            var channels = _channels.GetChannels(group.Id);
            SelectedChannel = channels.FirstOrDefault(c => c.Type == ChannelType.Text);
        }

        StateChanged?.Invoke();

        if (SelectedChannel is not null)
            _ = LoadHistoryAsync(SelectedGroup!.Id);
    }

    public void RenameGroupAsync(string newName)
    {
        if (SelectedGroup is null || string.IsNullOrWhiteSpace(newName)) return;
        SelectedGroup.Name = newName.Trim();
        StateChanged?.Invoke();
    }

    public async Task<GroupInfo> CreateGroupAsync(string name)
    {
        var group = await _groups.CreateGroupAsync(name);
        SelectGroup(group);
        return group;
    }

    public async Task<string> CreateInviteAsync(GroupId groupId, InviteOptions? options = null)
        => await _groups.CreateInviteAsync(groupId, options);

    public async Task<JoinResult> JoinViaInviteAsync(string inviteUrl, string? password = null)
    {
        var result = await _groups.JoinViaInviteAsync(inviteUrl, password);
        StateChanged?.Invoke();
        return result;
    }

    public async Task LeaveGroupAsync(GroupId groupId)
    {
        await _groups.LeaveGroupAsync(groupId);
        if (SelectedGroup?.Id == groupId)
            SelectGroup(null);
        StateChanged?.Invoke();
    }

    public async Task DeleteGroupAsync(GroupId groupId)
    {
        // Owner-only: for MVP, leave = delete since groups are ephemeral
        await _groups.LeaveGroupAsync(groupId);
        if (SelectedGroup?.Id == groupId)
            SelectGroup(null);
        StateChanged?.Invoke();
    }

    // ── Channels ────────────────────────────────────
    public ChannelInfo? SelectedChannel { get; private set; }

    public IReadOnlyList<ChannelInfo> GetChannels()
    {
        if (SelectedGroup is null) return [];
        return _channels.GetChannels(SelectedGroup.Id);
    }

    public void SelectChannel(ChannelInfo channel)
    {
        SelectedChannel = channel;
        StateChanged?.Invoke();

        if (SelectedGroup is not null)
            _ = LoadHistoryAsync(SelectedGroup.Id);
    }

    public async Task CreateChannelAsync(string name)
    {
        if (SelectedGroup is null) return;
        var ch = await _channels.CreateChannelAsync(SelectedGroup.Id, name);
        SelectChannel(ch);
    }

    public async Task RenameChannelAsync(Guid channelId, string newName)
    {
        if (SelectedGroup is null) return;
        await _channels.RenameChannelAsync(SelectedGroup.Id, channelId, newName);
        StateChanged?.Invoke();
    }

    public async Task DeleteChannelAsync(Guid channelId)
    {
        if (SelectedGroup is null) return;
        await _channels.DeleteChannelAsync(SelectedGroup.Id, channelId);
        if (SelectedChannel?.Id == channelId)
            SelectedChannel = GetChannels().FirstOrDefault();
        StateChanged?.Invoke();
    }

    // ── Chat ────────────────────────────────────────
    private readonly Dictionary<Guid, List<ChatMessageRecord>> _channelMessages = [];
    public IReadOnlyList<ChatMessageRecord> Messages =>
        SelectedChannel is not null && _channelMessages.TryGetValue(SelectedChannel.Id, out var list)
            ? list
            : [];

    public async Task SendMessageAsync(string content)
    {
        if (SelectedGroup is null || SelectedChannel is null) return;
        await _chat.SendMessageAsync(SelectedGroup.Id, content);
    }

    private async Task LoadHistoryAsync(GroupId groupId)
    {
        var history = await _chat.GetHistoryAsync(groupId);
        if (SelectedChannel is not null)
        {
            var list = GetOrCreateChannelList(SelectedChannel.Id);
            // Only load if empty (first load for this channel)
            if (list.Count == 0)
            {
                list.AddRange(history);
            }
        }
        StateChanged?.Invoke();
    }

    private List<ChatMessageRecord> GetOrCreateChannelList(Guid channelId)
    {
        if (!_channelMessages.TryGetValue(channelId, out var list))
        {
            list = [];
            _channelMessages[channelId] = list;
        }
        return list;
    }

    // ── Contacts ────────────────────────────────────
    public IReadOnlyList<ContactInfo> Contacts => _contacts.GetContacts();
    public IReadOnlyList<ContactInfo> PendingContactRequests => _contacts.GetPendingRequests();

    public async Task<ContactRequestResult> SendContactRequestAsync(string contactLink)
        => await _contacts.SendContactRequestAsync(contactLink);

    public async Task AcceptContactAsync(PeerId requester)
    {
        await _contacts.AcceptContactAsync(requester);
        StateChanged?.Invoke();
    }

    public async Task RejectContactAsync(PeerId requester)
    {
        await _contacts.RejectContactAsync(requester);
        StateChanged?.Invoke();
    }

    public async Task RemoveContactAsync(PeerId peerId)
    {
        await _contacts.RemoveContactAsync(peerId);
        StateChanged?.Invoke();
    }

    // ── Presence ────────────────────────────────────
    public IReadOnlyDictionary<PeerId, PeerStatus> PeerStatuses => _presence.GetAllStatuses();
    public PeerStatus GetPeerStatus(PeerId peer) => _presence.GetStatus(peer);

    // ── Change Notification ─────────────────────────
    public event Action? StateChanged;

    private void OnChatMessage(ChatMessageReceived msg)
    {
        if (SelectedGroup is not null && msg.Message.GroupId == SelectedGroup.Id
            && SelectedChannel is not null)
        {
            var list = GetOrCreateChannelList(SelectedChannel.Id);
            list.Add(msg.Message);
            StateChanged?.Invoke();
        }
    }

    private void OnGroupEvent(Core.Events.GroupEvent _) => StateChanged?.Invoke();
    private void OnPresenceChanged(PresenceChanged _) => StateChanged?.Invoke();
    private void OnContactEvent(ContactEvent _) => StateChanged?.Invoke();
    private void OnChannelEvent(ChannelEvent _) => StateChanged?.Invoke();

    public void Dispose()
    {
        foreach (var sub in _subscriptions)
            sub.Dispose();
        _subscriptions.Clear();
    }

    private sealed class Observer<T>(Action<T> onNext) : IObserver<T>
    {
        public void OnNext(T value) => onNext(value);
        public void OnError(Exception error) { }
        public void OnCompleted() { }
    }
}
