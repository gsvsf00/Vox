using Vox.Core.Crypto;
using Vox.Core.Events;
using Vox.Core.Identity;
using Vox.Core.Observable;

namespace Vox.Core.Groups;

/// <summary>
/// Maintains group state by storing and replaying an event-sourced log.
/// Enforces causal ordering via parent event IDs and Lamport clocks.
/// Thread-safe for concurrent event application.
/// </summary>
public sealed class GroupStateManager : IDisposable
{
    private readonly GroupId _groupId;
    private readonly ICryptoService _crypto;
    private readonly LamportClock _clock = new();
    private readonly EventSubject<GroupEvent> _eventSubject = new();

    private readonly object _lock = new();
    private readonly Dictionary<Guid, GroupEvent> _eventLog = new();
    private readonly Dictionary<PeerId, MemberEntry> _members = new(PeerIdEqualityComparer.Instance);
    private readonly HashSet<Guid> _usedInviteIds = [];

    /// <summary>Observable stream of newly applied events.</summary>
    public IObservable<GroupEvent> Events => _eventSubject;

    /// <summary>Current Lamport clock value.</summary>
    public ulong CurrentLamport => _clock.Value;

    public GroupStateManager(GroupId groupId, ICryptoService crypto)
    {
        _groupId = groupId;
        _crypto = crypto;
    }

    /// <summary>
    /// Returns the current member list snapshot.
    /// </summary>
    public IReadOnlyList<MemberEntry> GetMembers()
    {
        lock (_lock)
            return [.. _members.Values];
    }

    /// <summary>
    /// Returns all event IDs currently in the log (for anti-entropy sync).
    /// </summary>
    public IReadOnlyList<Guid> GetAllEventIds()
    {
        lock (_lock)
            return [.. _eventLog.Keys];
    }

    /// <summary>
    /// Returns the full event log sorted by Lamport clock then EventId.
    /// </summary>
    public IReadOnlyList<GroupEvent> GetAllEvents()
    {
        lock (_lock)
            return [.. _eventLog.Values.OrderBy(e => e.LamportClock).ThenBy(e => e.EventId)];
    }

    /// <summary>
    /// Checks if an invite ID has already been used (for single-use invites).
    /// </summary>
    public bool IsInviteUsed(Guid inviteId)
    {
        lock (_lock)
            return _usedInviteIds.Contains(inviteId);
    }

    /// <summary>
    /// Marks an invite ID as used.
    /// </summary>
    public void MarkInviteUsed(Guid inviteId)
    {
        lock (_lock)
            _usedInviteIds.Add(inviteId);
    }

    /// <summary>
    /// Creates, signs, and applies a new MemberJoined event.
    /// </summary>
    public GroupEvent AddMember(
        PeerId peerId,
        string username,
        ushort discriminator,
        MembershipCertificate cert,
        LocalIdentity author)
    {
        var payload = MemberJoinedPayload.Serialize(peerId, username, discriminator, cert);
        return CreateAndApplyEvent(GroupEventType.MemberJoined, payload, author);
    }

    /// <summary>
    /// Creates, signs, and applies a new MemberLeft event.
    /// </summary>
    public GroupEvent RemoveMember(PeerId peerId, string reason, LocalIdentity author)
    {
        var payload = MemberLeftPayload.Serialize(peerId, reason);
        return CreateAndApplyEvent(GroupEventType.MemberLeft, payload, author);
    }

    /// <summary>
    /// Tries to apply an externally received event. Verifies signature and causal order.
    /// Returns true if the event was applied (or already known).
    /// </summary>
    public bool TryApplyEvent(GroupEvent evt)
    {
        lock (_lock)
        {
            if (_eventLog.ContainsKey(evt.EventId))
                return true; // already applied

            if (!evt.GroupId.Equals(_groupId))
                return false;

            // Verify all parents are present (causal ordering)
            foreach (var parentId in evt.ParentIds)
            {
                if (!_eventLog.ContainsKey(parentId))
                    return false;
            }

            // Verify signature
            var serialized = GroupEventSerializer.Serialize(evt);
            var signable = GroupEventSerializer.GetSignableSpan(serialized);
            if (!_crypto.Verify(signable, evt.Signature, evt.Author.PublicKey))
                return false;

            ApplyEventInternal(evt);
            return true;
        }
    }

    /// <summary>
    /// Returns event IDs that the remote is missing, given the remote's known event IDs.
    /// </summary>
    public IReadOnlyList<GroupEvent> GetMissingEvents(IReadOnlyCollection<Guid> remoteKnownIds)
    {
        lock (_lock)
        {
            var remoteSet = new HashSet<Guid>(remoteKnownIds);
            return _eventLog
                .Where(kvp => !remoteSet.Contains(kvp.Key))
                .Select(kvp => kvp.Value)
                .OrderBy(e => e.LamportClock)
                .ThenBy(e => e.EventId)
                .ToList();
        }
    }

    private GroupEvent CreateAndApplyEvent(GroupEventType type, byte[] payload, LocalIdentity author)
    {
        lock (_lock)
        {
            var lamport = _clock.Tick();

            // Parent IDs = latest known event IDs (tip of the DAG)
            var parentIds = GetTipEventIds();

            var evt = new GroupEvent
            {
                EventId = Guid.NewGuid(),
                GroupId = _groupId,
                Author = author.PeerId,
                LamportClock = lamport,
                EventType = type,
                ParentIds = parentIds,
                Payload = payload,
                Signature = Array.Empty<byte>(), // placeholder
            };

            // Serialize, sign, reconstruct with real signature
            var serialized = GroupEventSerializer.Serialize(evt);
            var signable = GroupEventSerializer.GetSignableSpan(serialized);
            var signature = _crypto.Sign(signable, author.SigningPrivateKey);

            evt = new GroupEvent
            {
                EventId = evt.EventId,
                GroupId = evt.GroupId,
                Author = evt.Author,
                LamportClock = evt.LamportClock,
                EventType = evt.EventType,
                ParentIds = evt.ParentIds,
                Payload = evt.Payload,
                Signature = signature,
            };

            ApplyEventInternal(evt);
            return evt;
        }
    }

    // Must be called under _lock
    private void ApplyEventInternal(GroupEvent evt)
    {
        _eventLog[evt.EventId] = evt;
        _clock.Receive(evt.LamportClock);

        switch (evt.EventType)
        {
            case GroupEventType.MemberJoined:
                var joined = MemberJoinedPayload.Deserialize(evt.Payload);
                _members[joined.PeerId] = new MemberEntry(
                    joined.PeerId, joined.Username, joined.Discriminator,
                    joined.Certificate, evt.LamportClock);
                break;

            case GroupEventType.MemberLeft:
                var left = MemberLeftPayload.Deserialize(evt.Payload);
                _members.Remove(left.PeerId);
                break;
        }

        _eventSubject.OnNext(evt);
    }

    // Returns event IDs that are not referenced as parents by any other event
    private List<Guid> GetTipEventIds()
    {
        if (_eventLog.Count == 0)
            return [];

        var referenced = new HashSet<Guid>();
        foreach (var evt in _eventLog.Values)
            foreach (var pid in evt.ParentIds)
                referenced.Add(pid);

        var tips = _eventLog.Keys.Where(id => !referenced.Contains(id)).ToList();
        if (tips.Count > 0)
            return tips;

        // Fallback: pick the event with the highest Lamport clock for deterministic behavior
        // (Dictionary key ordering is not guaranteed).
        var latest = _eventLog.Values.OrderByDescending(e => e.LamportClock).ThenByDescending(e => e.EventId).First();
        return [latest.EventId];
    }

    public void Dispose()
    {
        _eventSubject.Dispose();
    }
}

/// <summary>
/// A member entry in the group state.
/// </summary>
public sealed record MemberEntry(
    PeerId PeerId,
    string Username,
    ushort Discriminator,
    MembershipCertificate Certificate,
    ulong JoinedAtLamport);

/// <summary>
/// Equality comparer for PeerId (value-based on 32-byte public key).
/// </summary>
internal sealed class PeerIdEqualityComparer : IEqualityComparer<PeerId>
{
    public static readonly PeerIdEqualityComparer Instance = new();

    public bool Equals(PeerId x, PeerId y) => x.Equals(y);
    public int GetHashCode(PeerId obj) => obj.GetHashCode();
}
