using Vox.Core.Crypto;
using Vox.Core.Events;
using Vox.Core.Groups;
using Vox.Core.Identity;

namespace Vox.Core.Tests;

public class GroupServiceTests
{
    private readonly ICryptoService _crypto = new LibsodiumCryptoService();

    private LocalIdentity CreateIdentity(string username = "TestUser", ushort disc = 1000)
    {
        var (signPub, signPriv) = _crypto.GenerateEd25519Keypair();
        var (encPub, encPriv) = _crypto.GenerateX25519Keypair();
        return new LocalIdentity
        {
            Username = username,
            Discriminator = disc,
            SigningPublicKey = signPub,
            SigningPrivateKey = signPriv,
            EncryptionPublicKey = encPub,
            EncryptionPrivateKey = encPriv,
        };
    }

    private GroupService CreateService(LocalIdentity? identity = null)
    {
        identity ??= CreateIdentity();
        return new GroupService(identity, _crypto, new InMemoryGroupStore());
    }

    [Fact]
    public async Task CreateGroup_ReturnsGroupInfo()
    {
        var identity = CreateIdentity("Alice", 1234);
        using var service = CreateService(identity);

        var group = await service.CreateGroupAsync("Test Group");

        Assert.Equal("Test Group", group.Name);
        Assert.Equal(identity.PeerId, group.Creator);
        Assert.NotNull(group.SymmetricKey);
        Assert.Equal(32, group.SymmetricKey.Length);
        Assert.Single(group.Members);
    }

    [Fact]
    public async Task CreateGroup_AppearsInJoinedGroups()
    {
        using var service = CreateService();

        var group = await service.CreateGroupAsync("My Group");

        var joined = service.GetJoinedGroups();
        Assert.Single(joined);
        Assert.Equal(group.Id, joined[0].Id);
    }

    [Fact]
    public async Task CreateGroup_HasStateManager()
    {
        using var service = CreateService();

        var group = await service.CreateGroupAsync("My Group");

        var stateManager = service.GetStateManager(group.Id);
        Assert.NotNull(stateManager);
        Assert.Single(stateManager!.GetMembers());
    }

    [Fact]
    public async Task CreateInvite_ReturnsValidUrl()
    {
        using var service = CreateService();
        var group = await service.CreateGroupAsync("Test Group");

        var url = await service.CreateInviteAsync(group.Id);

        Assert.StartsWith("vox://join/", url);
        Assert.Contains("ep=", url);
        Assert.Contains("bpk=", url);
    }

    [Fact]
    public async Task CreateInvite_WithPassword_SetsFlag()
    {
        var identity = CreateIdentity();
        using var service = CreateService(identity);
        var group = await service.CreateGroupAsync("Test");

        var url = await service.CreateInviteAsync(group.Id,
            new InviteOptions(Password: "secret"));

        // Verify the URL is parseable
        var parsed = InviteUrl.Parse(url);
        Assert.NotNull(parsed.CapsuleToken);

        // Decode capsule via CapsuleCodec pipeline
        var (type, capsuleBytes) = CapsuleCodec.Decode(parsed.CapsuleToken, group.SymmetricKey, _crypto);
        Assert.Equal(CapsuleType.GroupInvite, type);
        var capsule = InviteCapsuleSerializer.Deserialize(capsuleBytes);
        Assert.True(capsule.Flags.HasFlag(InviteFlags.PasswordRequired));
        Assert.NotNull(capsule.PasswordHash);
    }

    [Fact]
    public async Task CreateInvite_UnknownGroup_Throws()
    {
        using var service = CreateService();
        var fakeGroupId = new GroupId(_crypto.GenerateRandomBytes(32));

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => service.CreateInviteAsync(fakeGroupId));
    }

    [Fact]
    public async Task ValidateCapsule_ValidCapsule_ReturnsIt()
    {
        var identity = CreateIdentity();
        using var service = CreateService(identity);
        var group = await service.CreateGroupAsync("Test");

        var url = await service.CreateInviteAsync(group.Id);
        var parsed = InviteUrl.Parse(url);
        var (_, capsuleBytes) = CapsuleCodec.Decode(parsed.CapsuleToken, group.SymmetricKey, _crypto);

        var capsule = service.ValidateCapsule(capsuleBytes);
        Assert.NotNull(capsule);
        Assert.Equal(group.Id, capsule!.GroupId);
    }

    [Fact]
    public async Task ValidatePassword_CorrectPassword_ReturnsTrue()
    {
        var identity = CreateIdentity();
        using var service = CreateService(identity);
        var group = await service.CreateGroupAsync("Test");

        var url = await service.CreateInviteAsync(group.Id,
            new InviteOptions(Password: "mypassword"));

        var parsed = InviteUrl.Parse(url);
        var (_, capsuleBytes) = CapsuleCodec.Decode(parsed.CapsuleToken, group.SymmetricKey, _crypto);
        var capsule = InviteCapsuleSerializer.Deserialize(capsuleBytes);

        Assert.True(service.ValidatePassword(capsule, "mypassword"));
        Assert.False(service.ValidatePassword(capsule, "wrongpassword"));
        Assert.False(service.ValidatePassword(capsule, null));
    }

    [Fact]
    public async Task ValidatePassword_NoPasswordRequired_ReturnsTrue()
    {
        var identity = CreateIdentity();
        using var service = CreateService(identity);
        var group = await service.CreateGroupAsync("Test");

        var url = await service.CreateInviteAsync(group.Id);
        var parsed = InviteUrl.Parse(url);
        var (_, capsuleBytes) = CapsuleCodec.Decode(parsed.CapsuleToken, group.SymmetricKey, _crypto);
        var capsule = InviteCapsuleSerializer.Deserialize(capsuleBytes);

        Assert.True(service.ValidatePassword(capsule, null));
    }

    [Fact]
    public async Task AdmitPeer_CreatesValidAdmission()
    {
        var bootstrap = CreateIdentity("Bootstrap", 1);
        using var service = CreateService(bootstrap);
        var group = await service.CreateGroupAsync("Test");

        var joiner = CreateIdentity("Joiner", 2);
        var admission = service.AdmitPeer(group.Id, joiner.PeerId, "Joiner", 2);

        Assert.Equal(group.Id, admission.Certificate.GroupId);
        Assert.Equal(joiner.PeerId, admission.Certificate.AdmittedPeerId);
        Assert.Equal(bootstrap.PeerId, admission.Certificate.AdmittedByPeerId);
        Assert.NotEmpty(admission.EncryptedGroupKey);
        Assert.Equal(2, admission.PeerList.Count); // bootstrap + joiner
    }

    [Fact]
    public async Task ProcessAdmission_DecryptsGroupKey()
    {
        var bootstrap = CreateIdentity("Bootstrap", 1);
        using var bootstrapService = CreateService(bootstrap);
        var group = await bootstrapService.CreateGroupAsync("Test");

        var joiner = CreateIdentity("Joiner", 2);
        var admission = bootstrapService.AdmitPeer(group.Id, joiner.PeerId, "Joiner", 2);

        // Joiner processes admission
        using var joinerService = CreateService(joiner);
        var joinedGroup = joinerService.ProcessAdmission(admission, "Test");

        Assert.Equal(group.Id, joinedGroup.Id);
        Assert.Equal(group.SymmetricKey, joinedGroup.SymmetricKey);
    }

    [Fact]
    public async Task LeaveGroup_RemovesFromJoinedList()
    {
        using var service = CreateService();
        var group = await service.CreateGroupAsync("Test");
        Assert.Single(service.GetJoinedGroups());

        await service.LeaveGroupAsync(group.Id);

        Assert.Empty(service.GetJoinedGroups());
    }

    [Fact]
    public async Task LeaveGroup_UnknownGroup_NoOp()
    {
        using var service = CreateService();
        var fakeGroupId = new GroupId(_crypto.GenerateRandomBytes(32));

        // Should not throw
        await service.LeaveGroupAsync(fakeGroupId);
    }

    [Fact]
    public async Task GroupEvents_EmitsOnCreate()
    {
        using var service = CreateService();
        var received = new List<GroupEvent>();
        service.GroupEvents.Subscribe(new TestObserver<GroupEvent>(received));

        await service.CreateGroupAsync("Test");

        Assert.Single(received);
        Assert.Equal(GroupEventType.MemberJoined, received[0].EventType);
    }

    [Fact]
    public async Task MultipleGroups_TrackSeparately()
    {
        using var service = CreateService();

        var g1 = await service.CreateGroupAsync("Group 1");
        var g2 = await service.CreateGroupAsync("Group 2");

        Assert.Equal(2, service.GetJoinedGroups().Count);
        Assert.NotEqual(g1.Id, g2.Id);

        var sm1 = service.GetStateManager(g1.Id);
        var sm2 = service.GetStateManager(g2.Id);
        Assert.NotNull(sm1);
        Assert.NotNull(sm2);
    }

    private sealed class TestObserver<T>(List<T> list) : IObserver<T>
    {
        public void OnNext(T value) => list.Add(value);
        public void OnError(Exception error) { }
        public void OnCompleted() { }
    }
}

/// <summary>
/// In-memory IGroupStore for testing.
/// </summary>
internal sealed class InMemoryGroupStore : IGroupStore
{
    private readonly Dictionary<string, GroupInfo> _groups = new();

    public Task SaveGroupAsync(GroupInfo group)
    {
        _groups[group.Id.ToHex()] = group;
        return Task.CompletedTask;
    }

    public Task RemoveGroupAsync(GroupId groupId)
    {
        _groups.Remove(groupId.ToHex());
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<GroupInfo>> LoadAllGroupsAsync()
    {
        return Task.FromResult<IReadOnlyList<GroupInfo>>([.. _groups.Values]);
    }
}
