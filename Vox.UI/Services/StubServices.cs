using Vox.Chat;
using Vox.Core.Channels;
using Vox.Core.Contacts;
using Vox.Core.Crypto;
using Vox.Core.Events;
using Vox.Core.Groups;
using Vox.Core.Identity;
using Vox.Core.Observable;
using Vox.Network.Presence;

namespace Vox.Services;

/// <summary>
/// In-memory service stubs for Phase 5 MVP.
/// These let the UI shell run without the full transport stack (WebRTC, WireGuard).
/// Replaced with real implementations once transport is wired (Phase 6+).
/// </summary>
internal static class StubServices
{
    public static void Register(IServiceCollection services)
    {
        services.AddSingleton<ICryptoService, LibsodiumCryptoService>();
        services.AddSingleton<IIdentityStore, InMemoryIdentityStore>();
        services.AddSingleton<IIdentityService, IdentityService>();

        // Provide LocalIdentity eagerly so GroupService/ChatService can use it
        services.AddSingleton(sp =>
        {
            var identityService = sp.GetRequiredService<IIdentityService>();
            return identityService.GetOrCreateIdentity("User");
        });

        services.AddSingleton<IGroupStore, InMemoryGroupStore>();
        services.AddSingleton<IGroupService, GroupService>();
        services.AddSingleton<IMessageStore, InMemoryMessageStore>();
        services.AddSingleton<IMessageTransport, NullMessageTransport>();
        services.AddSingleton<IChatService, ChatService>();
        services.AddSingleton<IPresenceService>(sp =>
        {
            var presence = new InMemoryPresenceService();
            var identity = sp.GetRequiredService<LocalIdentity>();
            presence.SetLocalPeerId(identity.PeerId);
            return presence;
        });
        services.AddSingleton<IContactService>(sp =>
        {
            var identity = sp.GetRequiredService<LocalIdentity>();
            var crypto = sp.GetRequiredService<ICryptoService>();
            return new InMemoryContactService(identity, crypto);
        });
        services.AddSingleton<IChannelService, InMemoryChannelService>();
    }

    /// <summary>Identity store that never persists (fresh identity each launch).</summary>
    private sealed class InMemoryIdentityStore : IIdentityStore
    {
        public LocalIdentity? Load(ICryptoService crypto, string? password) => null;
        public void Save(LocalIdentity identity, ICryptoService crypto, string? password) { }
    }

    /// <summary>Group store backed by in-memory dictionary.</summary>
    private sealed class InMemoryGroupStore : IGroupStore
    {
        private readonly List<GroupInfo> _groups = [];

        public Task SaveGroupAsync(GroupInfo group)
        {
            _groups.RemoveAll(g => g.Id == group.Id);
            _groups.Add(group);
            return Task.CompletedTask;
        }

        public Task RemoveGroupAsync(GroupId id)
        {
            _groups.RemoveAll(g => g.Id == id);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<GroupInfo>> LoadAllGroupsAsync() =>
            Task.FromResult<IReadOnlyList<GroupInfo>>(_groups.ToList());
    }

    /// <summary>Message store backed by in-memory list.</summary>
    private sealed class InMemoryMessageStore : IMessageStore
    {
        private readonly List<ChatMessageRecord> _records = [];

        public Task SaveAsync(ChatMessageRecord record)
        {
            _records.Add(record);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<ChatMessageRecord>> GetHistoryAsync(
            GroupId groupId, int limit, Guid? beforeMessageId = null)
        {
            var query = _records
                .Where(r => r.GroupId == groupId)
                .OrderByDescending(r => r.LamportClock)
                .AsEnumerable();

            if (beforeMessageId.HasValue)
                query = query.SkipWhile(r => r.MessageId != beforeMessageId.Value).Skip(1);

            var result = query.Take(limit).Reverse().ToList();
            return Task.FromResult<IReadOnlyList<ChatMessageRecord>>(result);
        }

        public void Dispose() { }
    }

    /// <summary>Transport that does nothing (no peers to send to).</summary>
    private sealed class NullMessageTransport : IMessageTransport
    {
        public Task BroadcastAsync(GroupId groupId, byte[] packet) => Task.CompletedTask;
    }

    /// <summary>Presence service backed by in-memory dictionary.</summary>
    private sealed class InMemoryPresenceService : IPresenceService
    {
        private readonly EventSubject<PresenceChanged> _changes = new();
        private readonly Dictionary<PeerId, PeerStatus> _statuses = [];
        private PeerId? _localPeerId;

        public IObservable<PresenceChanged> PresenceChanges => _changes;

        public PeerStatus GetStatus(PeerId peer) =>
            _statuses.TryGetValue(peer, out var s) ? s : PeerStatus.Offline;

        public IReadOnlyDictionary<PeerId, PeerStatus> GetAllStatuses() => _statuses;

        public Task SetLocalStatusAsync(PeerStatus status)
        {
            if (_localPeerId is not null)
                _statuses[_localPeerId.Value] = status;
            return Task.CompletedTask;
        }

        public void SetLocalPeerId(PeerId peerId)
        {
            _localPeerId = peerId;
            _statuses[peerId] = PeerStatus.Online;
        }
    }

    /// <summary>Contact service backed by in-memory list.</summary>
    private sealed class InMemoryContactService : IContactService
    {
        private readonly LocalIdentity _identity;
        private readonly ICryptoService _crypto;
        private readonly List<ContactInfo> _contacts = [];
        private readonly EventSubject<ContactEvent> _events = new();

        public InMemoryContactService(LocalIdentity identity, ICryptoService crypto)
        {
            _identity = identity;
            _crypto = crypto;
        }

        public IObservable<ContactEvent> ContactEvents => _events;

        public string CreateContactLink()
        {
            var capsule = new ContactCapsule
            {
                PeerId = _identity.PeerId,
                DisplayName = _identity.Username,
                Endpoints = [],
                CreatedAt = DateTimeOffset.UtcNow,
                Signature = new byte[ContactCapsuleSerializer.SignatureSize],
            };

            var serialized = ContactCapsuleSerializer.Serialize(capsule);
            var signable = ContactCapsuleSerializer.GetSignableSpan(serialized);
            var signature = _crypto.Sign(signable, _identity.SigningPrivateKey);
            capsule.Signature = signature;

            var payload = ContactCapsuleSerializer.Serialize(capsule);
            var token = CapsuleCodec.Encode(
                CapsuleType.ContactInvite, payload, CapsuleCodec.ContactCapsuleKey, _crypto);

            return $"vox://contact/{token}";
        }

        public Task<ContactRequestResult> SendContactRequestAsync(string contactLink) =>
            Task.FromResult(new ContactRequestResult(false, "Transport not connected (stub)."));

        public Task AcceptContactAsync(PeerId requester)
        {
            var contact = _contacts.FirstOrDefault(c => c.PeerId == requester);
            if (contact is not null)
            {
                contact.Status = ContactStatus.Accepted;
                _events.OnNext(new ContactEvent(requester, ContactEventType.Accepted));
            }
            return Task.CompletedTask;
        }

        public Task RejectContactAsync(PeerId requester)
        {
            _contacts.RemoveAll(c => c.PeerId == requester && c.Status == ContactStatus.Pending);
            _events.OnNext(new ContactEvent(requester, ContactEventType.Rejected));
            return Task.CompletedTask;
        }

        public Task RemoveContactAsync(PeerId peerId)
        {
            _contacts.RemoveAll(c => c.PeerId == peerId);
            _events.OnNext(new ContactEvent(peerId, ContactEventType.Removed));
            return Task.CompletedTask;
        }

        public IReadOnlyList<ContactInfo> GetContacts() =>
            _contacts.Where(c => c.Status == ContactStatus.Accepted).ToList();

        public IReadOnlyList<ContactInfo> GetPendingRequests() =>
            _contacts.Where(c => c.Status == ContactStatus.Pending).ToList();
    }

    /// <summary>Channel service backed by in-memory dictionary keyed by group.</summary>
    private sealed class InMemoryChannelService : IChannelService
    {
        private readonly Dictionary<string, List<ChannelInfo>> _channels = [];
        private readonly EventSubject<ChannelEvent> _events = new();

        public IObservable<ChannelEvent> ChannelEvents => _events;

        public IReadOnlyList<ChannelInfo> GetChannels(GroupId groupId)
        {
            var key = groupId.ToHex();
            if (!_channels.TryGetValue(key, out var list))
            {
                list = [new ChannelInfo
                {
                    Id = Guid.NewGuid(),
                    GroupId = groupId,
                    Name = "general",
                    Type = ChannelType.Text,
                    SortOrder = 0,
                }];
                _channels[key] = list;
            }
            return list;
        }

        public Task<ChannelInfo> CreateChannelAsync(GroupId groupId, string name, ChannelType type = ChannelType.Text)
        {
            var key = groupId.ToHex();
            if (!_channels.TryGetValue(key, out var list))
            {
                list = [];
                _channels[key] = list;
            }

            var channel = new ChannelInfo
            {
                Id = Guid.NewGuid(),
                GroupId = groupId,
                Name = name,
                Type = type,
                SortOrder = list.Count,
            };
            list.Add(channel);
            _events.OnNext(new ChannelEvent(groupId, channel.Id, ChannelEventType.Created));
            return Task.FromResult(channel);
        }

        public Task RenameChannelAsync(GroupId groupId, Guid channelId, string newName)
        {
            var key = groupId.ToHex();
            if (_channels.TryGetValue(key, out var list))
            {
                var ch = list.FirstOrDefault(c => c.Id == channelId);
                if (ch is not null)
                {
                    ch.Name = newName;
                    _events.OnNext(new ChannelEvent(groupId, channelId, ChannelEventType.Renamed));
                }
            }
            return Task.CompletedTask;
        }

        public Task DeleteChannelAsync(GroupId groupId, Guid channelId)
        {
            var key = groupId.ToHex();
            if (_channels.TryGetValue(key, out var list))
            {
                list.RemoveAll(c => c.Id == channelId);
                _events.OnNext(new ChannelEvent(groupId, channelId, ChannelEventType.Deleted));
            }
            return Task.CompletedTask;
        }
    }
}
