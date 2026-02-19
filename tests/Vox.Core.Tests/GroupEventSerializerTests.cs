using Vox.Core.Crypto;
using Vox.Core.Events;
using Vox.Core.Groups;
using Vox.Core.Identity;

namespace Vox.Core.Tests;

public class GroupEventSerializerTests
{
    private readonly ICryptoService _crypto = new LibsodiumCryptoService();

    private GroupEvent CreateTestEvent(
        GroupEventType type = GroupEventType.MemberJoined,
        int parentCount = 0)
    {
        return new GroupEvent
        {
            EventId = Guid.NewGuid(),
            GroupId = new GroupId(_crypto.GenerateRandomBytes(32)),
            Author = new PeerId(_crypto.GenerateRandomBytes(32)),
            LamportClock = 42,
            EventType = type,
            ParentIds = Enumerable.Range(0, parentCount).Select(_ => Guid.NewGuid()).ToList(),
            Payload = _crypto.GenerateRandomBytes(100),
            Signature = _crypto.GenerateRandomBytes(64),
        };
    }

    [Fact]
    public void Roundtrip_PreservesAllFields()
    {
        var evt = CreateTestEvent();

        var bytes = GroupEventSerializer.Serialize(evt);
        var result = GroupEventSerializer.Deserialize(bytes);

        Assert.Equal(evt.EventId, result.EventId);
        Assert.Equal(evt.GroupId, result.GroupId);
        Assert.Equal(evt.Author, result.Author);
        Assert.Equal(evt.LamportClock, result.LamportClock);
        Assert.Equal(evt.EventType, result.EventType);
        Assert.Empty(result.ParentIds);
        Assert.Equal(evt.Payload, result.Payload);
        Assert.Equal(evt.Signature, result.Signature);
    }

    [Fact]
    public void Roundtrip_WithParents_PreservesOrder()
    {
        var evt = CreateTestEvent(parentCount: 3);

        var bytes = GroupEventSerializer.Serialize(evt);
        var result = GroupEventSerializer.Deserialize(bytes);

        Assert.Equal(3, result.ParentIds.Count);
        for (int i = 0; i < 3; i++)
            Assert.Equal(evt.ParentIds[i], result.ParentIds[i]);
    }

    [Fact]
    public void GetSignableSpan_ExcludesSignature()
    {
        var evt = CreateTestEvent();
        var bytes = GroupEventSerializer.Serialize(evt);
        var signable = GroupEventSerializer.GetSignableSpan(bytes);

        Assert.Equal(bytes.Length - GroupEventSerializer.SignatureSize, signable.Length);
    }

    [Fact]
    public void SignAndVerify_FullFlow()
    {
        var (pub, priv) = _crypto.GenerateEd25519Keypair();

        var evt = new GroupEvent
        {
            EventId = Guid.NewGuid(),
            GroupId = new GroupId(_crypto.GenerateRandomBytes(32)),
            Author = new PeerId(pub),
            LamportClock = 1,
            EventType = GroupEventType.MemberLeft,
            ParentIds = [Guid.NewGuid()],
            Payload = new byte[] { 1, 2, 3 },
            Signature = new byte[64],
        };

        var serialized = GroupEventSerializer.Serialize(evt);
        var signable = GroupEventSerializer.GetSignableSpan(serialized);
        var signature = _crypto.Sign(signable, priv);

        var signedEvt = new GroupEvent
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

        var finalBytes = GroupEventSerializer.Serialize(signedEvt);
        var verifySpan = GroupEventSerializer.GetSignableSpan(finalBytes);
        Assert.True(_crypto.Verify(verifySpan, signature, pub));
    }

    [Theory]
    [InlineData(GroupEventType.MemberJoined)]
    [InlineData(GroupEventType.MemberLeft)]
    [InlineData(GroupEventType.ChatMessage)]
    [InlineData(GroupEventType.PresenceChanged)]
    [InlineData(GroupEventType.GroupMetadataChanged)]
    public void Roundtrip_AllEventTypes(GroupEventType type)
    {
        var evt = CreateTestEvent(type);

        var bytes = GroupEventSerializer.Serialize(evt);
        var result = GroupEventSerializer.Deserialize(bytes);

        Assert.Equal(type, result.EventType);
    }

    [Fact]
    public void Roundtrip_EmptyPayload()
    {
        var evt = new GroupEvent
        {
            EventId = Guid.NewGuid(),
            GroupId = new GroupId(_crypto.GenerateRandomBytes(32)),
            Author = new PeerId(_crypto.GenerateRandomBytes(32)),
            LamportClock = 0,
            EventType = GroupEventType.MemberLeft,
            Payload = [],
            Signature = _crypto.GenerateRandomBytes(64),
        };

        var bytes = GroupEventSerializer.Serialize(evt);
        var result = GroupEventSerializer.Deserialize(bytes);

        Assert.Empty(result.Payload);
    }
}
