using System.Net;
using Vox.Core.Crypto;
using Vox.Core.Groups;
using Vox.Core.Identity;

namespace Vox.Core.Tests;

public class InviteCapsuleSerializerTests
{
    private readonly ICryptoService _crypto = new LibsodiumCryptoService();

    private InviteCapsule CreateTestCapsule(
        InviteFlags flags = InviteFlags.None,
        byte[]? passwordHash = null,
        int bootstrapCount = 1)
    {
        var (creatorPub, _) = _crypto.GenerateEd25519Keypair();
        var bootstraps = Enumerable.Range(0, bootstrapCount).Select(i =>
            new BootstrapPeer(
                _crypto.GenerateRandomBytes(32),
                new IPEndPoint(IPAddress.Parse($"192.168.1.{i + 1}"), 5000 + i)))
            .ToList();

        return new InviteCapsule
        {
            InviteId = Guid.NewGuid(),
            GroupId = new GroupId(_crypto.GenerateRandomBytes(32)),
            Creator = new PeerId(creatorPub),
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(24),
            Flags = flags,
            PasswordHash = passwordHash,
            BootstrapPeers = bootstraps,
            CreatorSignature = _crypto.GenerateRandomBytes(64),
        };
    }

    [Fact]
    public void Roundtrip_BasicCapsule_PreservesAllFields()
    {
        var capsule = CreateTestCapsule();
        var bytes = InviteCapsuleSerializer.Serialize(capsule);
        var result = InviteCapsuleSerializer.Deserialize(bytes);

        Assert.Equal(capsule.InviteId, result.InviteId);
        Assert.Equal(capsule.GroupId, result.GroupId);
        Assert.Equal(capsule.Creator, result.Creator);
        Assert.Equal(capsule.Flags, result.Flags);
        Assert.Null(result.PasswordHash);
        Assert.Single(result.BootstrapPeers);
        Assert.Equal(capsule.BootstrapPeers[0].Endpoint, result.BootstrapPeers[0].Endpoint);
        Assert.Equal(capsule.BootstrapPeers[0].WireGuardPublicKey, result.BootstrapPeers[0].WireGuardPublicKey);
        Assert.Equal(capsule.CreatorSignature, result.CreatorSignature);
    }

    [Fact]
    public void Roundtrip_WithPasswordHash_PreservesHash()
    {
        var pwHash = _crypto.Hash(System.Text.Encoding.UTF8.GetBytes("secret123"));
        var capsule = CreateTestCapsule(InviteFlags.PasswordRequired, pwHash);

        var bytes = InviteCapsuleSerializer.Serialize(capsule);
        var result = InviteCapsuleSerializer.Deserialize(bytes);

        Assert.Equal(InviteFlags.PasswordRequired, result.Flags);
        Assert.NotNull(result.PasswordHash);
        Assert.Equal(pwHash, result.PasswordHash);
    }

    [Fact]
    public void Roundtrip_SingleUseFlag_Preserved()
    {
        var capsule = CreateTestCapsule(InviteFlags.SingleUse | InviteFlags.PasswordRequired,
            _crypto.GenerateRandomBytes(32));

        var bytes = InviteCapsuleSerializer.Serialize(capsule);
        var result = InviteCapsuleSerializer.Deserialize(bytes);

        Assert.True(result.Flags.HasFlag(InviteFlags.SingleUse));
        Assert.True(result.Flags.HasFlag(InviteFlags.PasswordRequired));
    }

    [Fact]
    public void Roundtrip_MultipleBootstrapPeers_PreservesAll()
    {
        var capsule = CreateTestCapsule(bootstrapCount: 3);

        var bytes = InviteCapsuleSerializer.Serialize(capsule);
        var result = InviteCapsuleSerializer.Deserialize(bytes);

        Assert.Equal(3, result.BootstrapPeers.Count);
        for (int i = 0; i < 3; i++)
        {
            Assert.Equal(capsule.BootstrapPeers[i].Endpoint, result.BootstrapPeers[i].Endpoint);
            Assert.Equal(capsule.BootstrapPeers[i].WireGuardPublicKey,
                result.BootstrapPeers[i].WireGuardPublicKey);
        }
    }

    [Fact]
    public void Roundtrip_IPv6Endpoint_PreservesAddress()
    {
        var (creatorPub, _) = _crypto.GenerateEd25519Keypair();
        var capsule = new InviteCapsule
        {
            InviteId = Guid.NewGuid(),
            GroupId = new GroupId(_crypto.GenerateRandomBytes(32)),
            Creator = new PeerId(creatorPub),
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            Flags = InviteFlags.None,
            BootstrapPeers =
            [
                new BootstrapPeer(_crypto.GenerateRandomBytes(32),
                    new IPEndPoint(IPAddress.IPv6Loopback, 9000))
            ],
            CreatorSignature = _crypto.GenerateRandomBytes(64),
        };

        var bytes = InviteCapsuleSerializer.Serialize(capsule);
        var result = InviteCapsuleSerializer.Deserialize(bytes);

        Assert.Equal(IPAddress.IPv6Loopback, result.BootstrapPeers[0].Endpoint.Address);
        Assert.Equal(9000, result.BootstrapPeers[0].Endpoint.Port);
    }

    [Fact]
    public void GetSignableSpan_ExcludesSignature()
    {
        var capsule = CreateTestCapsule();
        var bytes = InviteCapsuleSerializer.Serialize(capsule);

        var signable = InviteCapsuleSerializer.GetSignableSpan(bytes);

        Assert.Equal(bytes.Length - InviteCapsuleSerializer.SignatureSize, signable.Length);
    }

    [Fact]
    public void Timestamps_PreservedWithMillisecondPrecision()
    {
        var capsule = CreateTestCapsule();

        var bytes = InviteCapsuleSerializer.Serialize(capsule);
        var result = InviteCapsuleSerializer.Deserialize(bytes);

        // Millisecond precision preserved
        Assert.Equal(
            capsule.CreatedAt.ToUnixTimeMilliseconds(),
            result.CreatedAt.ToUnixTimeMilliseconds());
        Assert.Equal(
            capsule.ExpiresAt.ToUnixTimeMilliseconds(),
            result.ExpiresAt.ToUnixTimeMilliseconds());
    }

    [Fact]
    public void SignAndVerify_FullFlow()
    {
        var (creatorPub, creatorPriv) = _crypto.GenerateEd25519Keypair();

        var capsule = new InviteCapsule
        {
            InviteId = Guid.NewGuid(),
            GroupId = new GroupId(_crypto.GenerateRandomBytes(32)),
            Creator = new PeerId(creatorPub),
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(24),
            Flags = InviteFlags.None,
            BootstrapPeers = [new BootstrapPeer(_crypto.GenerateRandomBytes(32),
                new IPEndPoint(IPAddress.Loopback, 5000))],
            CreatorSignature = new byte[64], // placeholder
        };

        // Serialize with placeholder, sign, re-serialize
        var serialized = InviteCapsuleSerializer.Serialize(capsule);
        var signable = InviteCapsuleSerializer.GetSignableSpan(serialized);
        var signature = _crypto.Sign(signable, creatorPriv);
        capsule.CreatorSignature = signature;
        var finalBytes = InviteCapsuleSerializer.Serialize(capsule);

        // Verify
        var verifySig = InviteCapsuleSerializer.GetSignableSpan(finalBytes);
        Assert.True(_crypto.Verify(verifySig, signature, creatorPub));
    }

    [Fact]
    public void EncryptAndDecrypt_WithGroupKey()
    {
        var groupKey = _crypto.GenerateSymmetricKey();
        var capsule = CreateTestCapsule();

        var capsuleBytes = InviteCapsuleSerializer.Serialize(capsule);
        var encrypted = _crypto.Encrypt(capsuleBytes, groupKey);
        var decrypted = _crypto.Decrypt(encrypted, groupKey);

        var result = InviteCapsuleSerializer.Deserialize(decrypted);
        Assert.Equal(capsule.InviteId, result.InviteId);
    }
}
