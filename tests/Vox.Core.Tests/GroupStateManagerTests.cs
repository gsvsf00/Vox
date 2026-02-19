using Vox.Core.Crypto;
using Vox.Core.Events;
using Vox.Core.Groups;
using Vox.Core.Identity;

namespace Vox.Core.Tests;

public class GroupStateManagerTests
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

    private MembershipCertificate CreateCert(GroupId groupId, PeerId admitted, PeerId admitter, byte[] admitterPriv)
    {
        var cert = new MembershipCertificate
        {
            GroupId = groupId,
            AdmittedPeerId = admitted,
            AdmittedByPeerId = admitter,
            AdmittedAt = DateTimeOffset.UtcNow,
            Signature = new byte[64],
        };

        var serialized = MembershipCertificateSerializer.Serialize(cert);
        var signable = MembershipCertificateSerializer.GetSignableSpan(serialized);
        var signature = _crypto.Sign(signable, admitterPriv);

        return new MembershipCertificate
        {
            GroupId = cert.GroupId,
            AdmittedPeerId = cert.AdmittedPeerId,
            AdmittedByPeerId = cert.AdmittedByPeerId,
            AdmittedAt = cert.AdmittedAt,
            Signature = signature,
        };
    }

    [Fact]
    public void AddMember_IncreasesLamportClock()
    {
        var groupId = new GroupId(_crypto.GenerateRandomBytes(32));
        var identity = CreateIdentity();
        using var manager = new GroupStateManager(groupId, _crypto);

        var cert = CreateCert(groupId, identity.PeerId, identity.PeerId, identity.SigningPrivateKey);
        manager.AddMember(identity.PeerId, "TestUser", 1000, cert, identity);

        Assert.True(manager.CurrentLamport > 0);
    }

    [Fact]
    public void AddMember_AppearsInMemberList()
    {
        var groupId = new GroupId(_crypto.GenerateRandomBytes(32));
        var identity = CreateIdentity();
        using var manager = new GroupStateManager(groupId, _crypto);

        var cert = CreateCert(groupId, identity.PeerId, identity.PeerId, identity.SigningPrivateKey);
        manager.AddMember(identity.PeerId, "Alice", 1234, cert, identity);

        var members = manager.GetMembers();
        Assert.Single(members);
        Assert.Equal("Alice", members[0].Username);
        Assert.Equal(1234, members[0].Discriminator);
    }

    [Fact]
    public void RemoveMember_RemovesFromList()
    {
        var groupId = new GroupId(_crypto.GenerateRandomBytes(32));
        var identity = CreateIdentity();
        using var manager = new GroupStateManager(groupId, _crypto);

        var cert = CreateCert(groupId, identity.PeerId, identity.PeerId, identity.SigningPrivateKey);
        manager.AddMember(identity.PeerId, "Alice", 1000, cert, identity);
        Assert.Single(manager.GetMembers());

        manager.RemoveMember(identity.PeerId, "left voluntarily", identity);
        Assert.Empty(manager.GetMembers());
    }

    [Fact]
    public void Events_AreRecordedInLog()
    {
        var groupId = new GroupId(_crypto.GenerateRandomBytes(32));
        var identity = CreateIdentity();
        using var manager = new GroupStateManager(groupId, _crypto);

        var cert = CreateCert(groupId, identity.PeerId, identity.PeerId, identity.SigningPrivateKey);
        manager.AddMember(identity.PeerId, "Alice", 1000, cert, identity);
        manager.RemoveMember(identity.PeerId, "bye", identity);

        var events = manager.GetAllEvents();
        Assert.Equal(2, events.Count);
        Assert.Equal(GroupEventType.MemberJoined, events[0].EventType);
        Assert.Equal(GroupEventType.MemberLeft, events[1].EventType);
    }

    [Fact]
    public void Events_HaveCausalParentIds()
    {
        var groupId = new GroupId(_crypto.GenerateRandomBytes(32));
        var identity = CreateIdentity();
        using var manager = new GroupStateManager(groupId, _crypto);

        var cert = CreateCert(groupId, identity.PeerId, identity.PeerId, identity.SigningPrivateKey);
        var evt1 = manager.AddMember(identity.PeerId, "Alice", 1000, cert, identity);
        var evt2 = manager.RemoveMember(identity.PeerId, "bye", identity);

        // Second event should reference first as parent
        Assert.Empty(evt1.ParentIds); // first event has no parents
        Assert.Contains(evt1.EventId, evt2.ParentIds);
    }

    [Fact]
    public void TryApplyEvent_AcceptsValidEvent()
    {
        var groupId = new GroupId(_crypto.GenerateRandomBytes(32));
        var identity = CreateIdentity();
        using var manager1 = new GroupStateManager(groupId, _crypto);
        using var manager2 = new GroupStateManager(groupId, _crypto);

        var cert = CreateCert(groupId, identity.PeerId, identity.PeerId, identity.SigningPrivateKey);
        var evt = manager1.AddMember(identity.PeerId, "Alice", 1000, cert, identity);

        // Apply to second manager
        Assert.True(manager2.TryApplyEvent(evt));
        Assert.Single(manager2.GetMembers());
    }

    [Fact]
    public void TryApplyEvent_RejectsDuplicateEvent()
    {
        var groupId = new GroupId(_crypto.GenerateRandomBytes(32));
        var identity = CreateIdentity();
        using var manager = new GroupStateManager(groupId, _crypto);

        var cert = CreateCert(groupId, identity.PeerId, identity.PeerId, identity.SigningPrivateKey);
        var evt = manager.AddMember(identity.PeerId, "Alice", 1000, cert, identity);

        // Already applied, returns true (idempotent)
        Assert.True(manager.TryApplyEvent(evt));
        Assert.Single(manager.GetMembers());
    }

    [Fact]
    public void TryApplyEvent_RejectsWrongGroup()
    {
        var groupId1 = new GroupId(_crypto.GenerateRandomBytes(32));
        var groupId2 = new GroupId(_crypto.GenerateRandomBytes(32));
        var identity = CreateIdentity();
        using var manager1 = new GroupStateManager(groupId1, _crypto);
        using var manager2 = new GroupStateManager(groupId2, _crypto);

        var cert = CreateCert(groupId1, identity.PeerId, identity.PeerId, identity.SigningPrivateKey);
        var evt = manager1.AddMember(identity.PeerId, "Alice", 1000, cert, identity);

        // Wrong group
        Assert.False(manager2.TryApplyEvent(evt));
    }

    [Fact]
    public void TryApplyEvent_RejectsMissingParent()
    {
        var groupId = new GroupId(_crypto.GenerateRandomBytes(32));
        var identity = CreateIdentity();
        using var manager1 = new GroupStateManager(groupId, _crypto);
        using var manager2 = new GroupStateManager(groupId, _crypto);

        var cert = CreateCert(groupId, identity.PeerId, identity.PeerId, identity.SigningPrivateKey);
        manager1.AddMember(identity.PeerId, "Alice", 1000, cert, identity);
        var evt2 = manager1.RemoveMember(identity.PeerId, "bye", identity);

        // evt2 has parent evt1, which manager2 doesn't have → reject
        Assert.False(manager2.TryApplyEvent(evt2));
    }

    [Fact]
    public void GetMissingEvents_ReturnsCorrectDelta()
    {
        var groupId = new GroupId(_crypto.GenerateRandomBytes(32));
        var identity = CreateIdentity();
        using var manager = new GroupStateManager(groupId, _crypto);

        var cert = CreateCert(groupId, identity.PeerId, identity.PeerId, identity.SigningPrivateKey);
        var evt1 = manager.AddMember(identity.PeerId, "Alice", 1000, cert, identity);
        var evt2 = manager.RemoveMember(identity.PeerId, "bye", identity);

        // Remote knows only evt1
        var missing = manager.GetMissingEvents([evt1.EventId]);
        Assert.Single(missing);
        Assert.Equal(evt2.EventId, missing[0].EventId);
    }

    [Fact]
    public void GetMissingEvents_EmptyRemote_ReturnsAll()
    {
        var groupId = new GroupId(_crypto.GenerateRandomBytes(32));
        var identity = CreateIdentity();
        using var manager = new GroupStateManager(groupId, _crypto);

        var cert = CreateCert(groupId, identity.PeerId, identity.PeerId, identity.SigningPrivateKey);
        manager.AddMember(identity.PeerId, "Alice", 1000, cert, identity);

        var missing = manager.GetMissingEvents([]);
        Assert.Single(missing);
    }

    [Fact]
    public void InviteTracking_MarkAndCheck()
    {
        var groupId = new GroupId(_crypto.GenerateRandomBytes(32));
        using var manager = new GroupStateManager(groupId, _crypto);

        var inviteId = Guid.NewGuid();
        Assert.False(manager.IsInviteUsed(inviteId));

        manager.MarkInviteUsed(inviteId);
        Assert.True(manager.IsInviteUsed(inviteId));
    }

    [Fact]
    public void EventObservable_EmitsOnAddMember()
    {
        var groupId = new GroupId(_crypto.GenerateRandomBytes(32));
        var identity = CreateIdentity();
        using var manager = new GroupStateManager(groupId, _crypto);

        var received = new List<GroupEvent>();
        manager.Events.Subscribe(new TestObserver<GroupEvent>(received));

        var cert = CreateCert(groupId, identity.PeerId, identity.PeerId, identity.SigningPrivateKey);
        manager.AddMember(identity.PeerId, "Alice", 1000, cert, identity);

        Assert.Single(received);
        Assert.Equal(GroupEventType.MemberJoined, received[0].EventType);
    }

    [Fact]
    public void MultipleMembers_CoexistCorrectly()
    {
        var groupId = new GroupId(_crypto.GenerateRandomBytes(32));
        var admin = CreateIdentity("Admin", 1);
        var user1 = CreateIdentity("User1", 2);
        var user2 = CreateIdentity("User2", 3);
        using var manager = new GroupStateManager(groupId, _crypto);

        var adminCert = CreateCert(groupId, admin.PeerId, admin.PeerId, admin.SigningPrivateKey);
        manager.AddMember(admin.PeerId, "Admin", 1, adminCert, admin);

        var cert1 = CreateCert(groupId, user1.PeerId, admin.PeerId, admin.SigningPrivateKey);
        manager.AddMember(user1.PeerId, "User1", 2, cert1, admin);

        var cert2 = CreateCert(groupId, user2.PeerId, admin.PeerId, admin.SigningPrivateKey);
        manager.AddMember(user2.PeerId, "User2", 3, cert2, admin);

        Assert.Equal(3, manager.GetMembers().Count);
        Assert.Equal(3, manager.GetAllEvents().Count);
    }

    private sealed class TestObserver<T>(List<T> list) : IObserver<T>
    {
        public void OnNext(T value) => list.Add(value);
        public void OnError(Exception error) { }
        public void OnCompleted() { }
    }
}
