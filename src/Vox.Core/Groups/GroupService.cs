using System.Net;
using Vox.Core.Crypto;
using Vox.Core.Events;
using Vox.Core.Identity;
using Vox.Core.Observable;

namespace Vox.Core.Groups;

/// <summary>
/// Full IGroupService implementation. Manages group lifecycle:
/// create, invite generation, join flow, leave, and state sync.
/// </summary>
public sealed class GroupService : IGroupService, IDisposable
{
    private readonly LocalIdentity _localIdentity;
    private readonly ICryptoService _cryptoService;
    private readonly IGroupStore _groupStore;
    private readonly EventSubject<GroupEvent> _groupEventSubject = new();

    private readonly object _lock = new();
    private readonly Dictionary<GroupId, ManagedGroup> _groups = new(GroupIdComparer.Instance);

    public IObservable<GroupEvent> GroupEvents => _groupEventSubject;

    public GroupService(
        LocalIdentity localIdentity,
        ICryptoService cryptoService,
        IGroupStore groupStore)
    {
        _localIdentity = localIdentity;
        _cryptoService = cryptoService;
        _groupStore = groupStore;
    }

    public async Task<GroupInfo> CreateGroupAsync(string name)
    {
        var symmetricKey = _cryptoService.GenerateSymmetricKey();
        var groupId = new GroupId(_cryptoService.Hash(symmetricKey));

        var info = new GroupInfo
        {
            Id = groupId,
            Name = name,
            SymmetricKey = symmetricKey,
            Creator = _localIdentity.PeerId,
            CreatedAt = DateTimeOffset.UtcNow,
        };

        // Create membership certificate for the creator (self-admitted)
        var cert = CreateMembershipCertificate(groupId, _localIdentity.PeerId, _localIdentity.PeerId);
        info.Members.Add(CreateLocalPeerInfo());

        var stateManager = new GroupStateManager(groupId, _cryptoService);

        // Subscribe to forward events before adding the first member
        stateManager.Events.Subscribe(new EventForwarder(_groupEventSubject));

        stateManager.AddMember(
            _localIdentity.PeerId,
            _localIdentity.Username,
            _localIdentity.Discriminator,
            cert,
            _localIdentity);

        // Subscribe was already set up before AddMember

        lock (_lock)
            _groups[groupId] = new ManagedGroup(info, stateManager);

        await _groupStore.SaveGroupAsync(info);

        return info;
    }

    public Task<string> CreateInviteAsync(GroupId groupId, InviteOptions? options = null)
    {
        ManagedGroup managed;
        lock (_lock)
        {
            if (!_groups.TryGetValue(groupId, out managed!))
                throw new InvalidOperationException("Not a member of this group.");
        }

        options ??= new InviteOptions();
        var expiry = options.Expiry ?? TimeSpan.FromHours(24);

        byte[]? passwordHash = null;
        var flags = InviteFlags.None;

        if (options.Password is not null)
        {
            passwordHash = _cryptoService.Hash(
                System.Text.Encoding.UTF8.GetBytes(options.Password));
            flags |= InviteFlags.PasswordRequired;
        }

        if (options.SingleUse)
            flags |= InviteFlags.SingleUse;

        // We need a bootstrap peer. For MVP, the creator is the bootstrap peer.
        // WG public key and endpoint must be provided externally; use a placeholder here.
        var bootstrapPeers = new List<BootstrapPeer>();

        var capsule = new InviteCapsule
        {
            InviteId = Guid.NewGuid(),
            GroupId = groupId,
            Creator = _localIdentity.PeerId,
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.Add(expiry),
            Flags = flags,
            PasswordHash = passwordHash,
            BootstrapPeers = bootstrapPeers,
            CreatorSignature = new byte[InviteCapsuleSerializer.SignatureSize],
        };

        // Serialize with placeholder sig, sign, then rebuild
        var serialized = InviteCapsuleSerializer.Serialize(capsule);
        var signable = InviteCapsuleSerializer.GetSignableSpan(serialized);
        var signature = _cryptoService.Sign(signable, _localIdentity.SigningPrivateKey);
        capsule.CreatorSignature = signature;

        // Re-serialize with real signature
        var capsuleBytes = InviteCapsuleSerializer.Serialize(capsule);

        // Encrypt capsule with group symmetric key
        var encryptedCapsule = _cryptoService.Encrypt(capsuleBytes, managed.Info.SymmetricKey);

        // TODO: Replace placeholder bootstrap peer with real WireGuardService endpoint data.
        // Currently uses a dummy key and loopback address because the local peer's WG public key
        // and externally-reachable endpoint are not yet available at this layer.
        // Production flow: query IWireGuardService for the local public key and NAT-mapped endpoint.
        var url = InviteUrl.Create(encryptedCapsule, [
            new BootstrapPeer(new byte[32], new IPEndPoint(IPAddress.Loopback, 1))
        ]);

        return Task.FromResult(url);
    }

    /// <summary>
    /// Validates a decrypted invite capsule on the bootstrap side.
    /// Returns null if invalid, otherwise the validated capsule.
    /// </summary>
    public InviteCapsule? ValidateCapsule(byte[] decryptedCapsuleBytes)
    {
        InviteCapsule capsule;
        try
        {
            capsule = InviteCapsuleSerializer.Deserialize(decryptedCapsuleBytes);
        }
        catch
        {
            return null;
        }

        // Check group exists locally
        ManagedGroup? managed;
        lock (_lock)
        {
            if (!_groups.TryGetValue(capsule.GroupId, out managed))
                return null;
        }

        // Check expiration
        if (DateTimeOffset.UtcNow > capsule.ExpiresAt)
            return null;

        // Check single-use
        if (capsule.Flags.HasFlag(InviteFlags.SingleUse))
        {
            if (managed.StateManager.IsInviteUsed(capsule.InviteId))
                return null;
        }

        // Verify creator signature
        var serialized = InviteCapsuleSerializer.Serialize(capsule);
        var signable = InviteCapsuleSerializer.GetSignableSpan(serialized);
        if (!_cryptoService.Verify(signable, capsule.CreatorSignature!, capsule.Creator.PublicKey))
            return null;

        return capsule;
    }

    /// <summary>
    /// Validates password against the capsule's hash.
    /// </summary>
    public bool ValidatePassword(InviteCapsule capsule, string? password)
    {
        if (!capsule.Flags.HasFlag(InviteFlags.PasswordRequired))
            return true;

        if (password is null)
            return false;

        var hash = _cryptoService.Hash(System.Text.Encoding.UTF8.GetBytes(password));
        return hash.AsSpan().SequenceEqual(capsule.PasswordHash);
    }

    /// <summary>
    /// Admits a new peer (called on the bootstrap side after knock validation).
    /// Creates a membership certificate, records the MemberJoined event, and returns admission data.
    /// </summary>
    public AdmissionData AdmitPeer(
        GroupId groupId,
        PeerId joinerPeerId,
        string joinerUsername,
        ushort joinerDiscriminator)
    {
        ManagedGroup managed;
        lock (_lock)
        {
            if (!_groups.TryGetValue(groupId, out managed!))
                throw new InvalidOperationException("Not a member of this group.");
        }

        var cert = CreateMembershipCertificate(groupId, joinerPeerId, _localIdentity.PeerId);

        managed.StateManager.AddMember(
            joinerPeerId, joinerUsername, joinerDiscriminator, cert, _localIdentity);

        // The group key is sent directly in the admission packet.
        // The WireGuard tunnel already provides authenticated encryption.
        var groupKeyForTransport = managed.Info.SymmetricKey;

        // Build peer list from current members
        var members = managed.StateManager.GetMembers();
        // WG public keys are not tracked in GroupStateManager (it manages membership only).
        // Real WG keys will be resolved via IWireGuardService when network integration is added.
        var peerList = members.Select(m => new PeerInfo(
            m.PeerId, m.Username, m.Discriminator,
            new byte[32],
            [], PeerStatus.Online, PeerCapabilities.None
        )).ToList();

        return new AdmissionData(cert, groupKeyForTransport, peerList, managed.StateManager.CurrentLamport);
    }

    /// <summary>
    /// Processes received admission data (called on the joiner side).
    /// Decrypts the group key, stores the group, and initializes state.
    /// </summary>
    public GroupInfo ProcessAdmission(AdmissionData admission, string groupName)
    {
        // The group key arrives as-is since the WireGuard tunnel provides encryption.
        // In the binary protocol, AdmissionData.EncryptedGroupKey carries the raw key
        // (the name reflects the on-wire perspective where the tunnel encrypts it).
        var symmetricKey = admission.EncryptedGroupKey;

        var groupId = admission.Certificate.GroupId;

        var info = new GroupInfo
        {
            Id = groupId,
            Name = groupName,
            SymmetricKey = symmetricKey,
            Creator = admission.Certificate.AdmittedByPeerId, // approximation for MVP
            CreatedAt = admission.Certificate.AdmittedAt,
            Members = admission.PeerList.ToList(),
        };

        var stateManager = new GroupStateManager(groupId, _cryptoService);
        stateManager.Events.Subscribe(new EventForwarder(_groupEventSubject));

        lock (_lock)
            _groups[groupId] = new ManagedGroup(info, stateManager);

        return info;
    }

    public async Task<JoinResult> JoinViaInviteAsync(string inviteUrl, string? password = null)
    {
        // Parse the invite URL
        ParsedInvite parsed;
        try
        {
            parsed = InviteUrl.Parse(inviteUrl);
        }
        catch (FormatException ex)
        {
            return new JoinResult(false, ex.Message, null);
        }

        // The actual join flow (knock → accept → WG → admission) requires network integration.
        // This method provides the parsing and validation infrastructure.
        // The full flow is orchestrated at a higher level with IWireGuardService.
        return new JoinResult(false, "Network join requires IWireGuardService integration.", null);
    }

    public Task LeaveGroupAsync(GroupId groupId)
    {
        ManagedGroup? managed;
        lock (_lock)
        {
            if (!_groups.TryGetValue(groupId, out managed))
                return Task.CompletedTask; // not in group, nothing to do

            managed.StateManager.RemoveMember(_localIdentity.PeerId, "left", _localIdentity);
            _groups.Remove(groupId);
        }

        managed.StateManager.Dispose();
        return _groupStore.RemoveGroupAsync(groupId);
    }

    public IReadOnlyList<GroupInfo> GetJoinedGroups()
    {
        lock (_lock)
            return _groups.Values.Select(m => m.Info).ToList();
    }

    /// <summary>
    /// Gets the state manager for a group (for direct event manipulation and sync).
    /// </summary>
    public GroupStateManager? GetStateManager(GroupId groupId)
    {
        lock (_lock)
            return _groups.TryGetValue(groupId, out var managed) ? managed.StateManager : null;
    }

    private MembershipCertificate CreateMembershipCertificate(
        GroupId groupId, PeerId admittedPeerId, PeerId admittedByPeerId)
    {
        var cert = new MembershipCertificate
        {
            GroupId = groupId,
            AdmittedPeerId = admittedPeerId,
            AdmittedByPeerId = admittedByPeerId,
            AdmittedAt = DateTimeOffset.UtcNow,
            Signature = new byte[MembershipCertificateSerializer.SignatureSize],
        };

        var serialized = MembershipCertificateSerializer.Serialize(cert);
        var signable = MembershipCertificateSerializer.GetSignableSpan(serialized);
        var signature = _cryptoService.Sign(signable, _localIdentity.SigningPrivateKey);

        return new MembershipCertificate
        {
            GroupId = cert.GroupId,
            AdmittedPeerId = cert.AdmittedPeerId,
            AdmittedByPeerId = cert.AdmittedByPeerId,
            AdmittedAt = cert.AdmittedAt,
            Signature = signature,
        };
    }

    private PeerInfo CreateLocalPeerInfo()
    {
        // TODO: Resolve actual WG public key from IWireGuardService once integrated.
        // Placeholder zero-filled key is used until the WireGuard layer is wired in.
        return new PeerInfo(
            _localIdentity.PeerId,
            _localIdentity.Username,
            _localIdentity.Discriminator,
            new byte[32],
            [],
            PeerStatus.Online,
            PeerCapabilities.None);
    }

    public void Dispose()
    {
        lock (_lock)
        {
            foreach (var managed in _groups.Values)
                managed.StateManager.Dispose();
            _groups.Clear();
        }

        _groupEventSubject.Dispose();
    }

    private sealed record ManagedGroup(GroupInfo Info, GroupStateManager StateManager);

    /// <summary>Forwards events from a GroupStateManager to the service-level observable.</summary>
    private sealed class EventForwarder(EventSubject<GroupEvent> target) : IObserver<GroupEvent>
    {
        public void OnNext(GroupEvent value) => target.OnNext(value);
        public void OnError(Exception error) { }
        public void OnCompleted() { }
    }
}

/// <summary>
/// Persistence interface for joined groups.
/// </summary>
public interface IGroupStore
{
    Task SaveGroupAsync(GroupInfo group);
    Task RemoveGroupAsync(GroupId groupId);
    Task<IReadOnlyList<GroupInfo>> LoadAllGroupsAsync();
}

/// <summary>
/// Comparer for GroupId to use as dictionary key.
/// </summary>
internal sealed class GroupIdComparer : IEqualityComparer<GroupId>
{
    public static readonly GroupIdComparer Instance = new();

    public bool Equals(GroupId x, GroupId y) => x.Equals(y);
    public int GetHashCode(GroupId obj) => obj.GetHashCode();
}
