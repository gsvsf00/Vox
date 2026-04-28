using System.Net;
using Vox.Core.Contacts;
using Vox.Core.Crypto;
using Vox.Core.Groups;
using Vox.Core.Identity;

namespace Vox.Core.Tests;

public class CapsuleCodecTests
{
    private readonly ICryptoService _crypto = new LibsodiumCryptoService();

    // ── GroupInvite round-trip ────────────────────────────

    [Fact]
    public void GroupInvite_Roundtrip_SerializeCompressEncryptEncodeDecodeDecryptDecompressDeserialize()
    {
        var (creatorPub, creatorPriv) = _crypto.GenerateEd25519Keypair();
        var groupKey = _crypto.GenerateSymmetricKey();

        var capsule = new InviteCapsule
        {
            InviteId = Guid.NewGuid(),
            GroupId = new GroupId(_crypto.GenerateRandomBytes(32)),
            Creator = new PeerId(creatorPub),
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(24),
            Flags = InviteFlags.None,
            BootstrapPeers =
            [
                new BootstrapPeer(_crypto.GenerateRandomBytes(32),
                    new IPEndPoint(IPAddress.Parse("192.168.1.1"), 51820))
            ],
            CreatorSignature = new byte[64],
        };

        // Serialize
        var serialized = InviteCapsuleSerializer.Serialize(capsule);
        var signable = InviteCapsuleSerializer.GetSignableSpan(serialized);
        capsule.CreatorSignature = _crypto.Sign(signable, creatorPriv);
        var payload = InviteCapsuleSerializer.Serialize(capsule);

        // Encode: version+type → GZIP → Encrypt → Base64URL
        var token = CapsuleCodec.Encode(CapsuleType.GroupInvite, payload, groupKey, _crypto);

        // Verify token is valid Base64URL (no padding, no +/)
        Assert.DoesNotContain("=", token);
        Assert.DoesNotContain("+", token);
        Assert.DoesNotContain("/", token);

        // Decode: Base64URL → Decrypt → Decompress → version+type
        var (type, decoded) = CapsuleCodec.Decode(token, groupKey, _crypto);

        Assert.Equal(CapsuleType.GroupInvite, type);

        // Deserialize
        var result = InviteCapsuleSerializer.Deserialize(decoded);

        Assert.Equal(capsule.InviteId, result.InviteId);
        Assert.Equal(capsule.GroupId, result.GroupId);
        Assert.Equal(capsule.Creator, result.Creator);
        Assert.Equal(capsule.Flags, result.Flags);
        Assert.Single(result.BootstrapPeers);
        Assert.Equal(capsule.BootstrapPeers[0].Endpoint, result.BootstrapPeers[0].Endpoint);
        Assert.Equal(capsule.CreatorSignature, result.CreatorSignature);

        // Verify signature survives round-trip
        var finalBytes = InviteCapsuleSerializer.Serialize(result);
        var verifySig = InviteCapsuleSerializer.GetSignableSpan(finalBytes);
        Assert.True(_crypto.Verify(verifySig, result.CreatorSignature!, creatorPub));
    }

    [Fact]
    public void GroupInvite_WithPassword_Roundtrip()
    {
        var (creatorPub, creatorPriv) = _crypto.GenerateEd25519Keypair();
        var groupKey = _crypto.GenerateSymmetricKey();
        var pwHash = _crypto.Hash(System.Text.Encoding.UTF8.GetBytes("secret123"));

        var capsule = new InviteCapsule
        {
            InviteId = Guid.NewGuid(),
            GroupId = new GroupId(_crypto.GenerateRandomBytes(32)),
            Creator = new PeerId(creatorPub),
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            Flags = InviteFlags.PasswordRequired | InviteFlags.SingleUse,
            PasswordHash = pwHash,
            BootstrapPeers = [],
            CreatorSignature = _crypto.GenerateRandomBytes(64),
        };

        var payload = InviteCapsuleSerializer.Serialize(capsule);
        var token = CapsuleCodec.Encode(CapsuleType.GroupInvite, payload, groupKey, _crypto);
        var (type, decoded) = CapsuleCodec.Decode(token, groupKey, _crypto);

        Assert.Equal(CapsuleType.GroupInvite, type);

        var result = InviteCapsuleSerializer.Deserialize(decoded);
        Assert.True(result.Flags.HasFlag(InviteFlags.PasswordRequired));
        Assert.True(result.Flags.HasFlag(InviteFlags.SingleUse));
        Assert.Equal(pwHash, result.PasswordHash);
    }

    // ── ContactInvite round-trip ─────────────────────────

    [Fact]
    public void ContactInvite_Roundtrip_SerializeCompressEncryptEncodeDecodeDecryptDecompressDeserialize()
    {
        var (peerPub, peerPriv) = _crypto.GenerateEd25519Keypair();
        var peerId = new PeerId(peerPub);

        var capsule = new ContactCapsule
        {
            PeerId = peerId,
            DisplayName = "Alice",
            Endpoints = [new IPEndPoint(IPAddress.Parse("10.0.0.1"), 9000)],
            CreatedAt = DateTimeOffset.UtcNow,
            Signature = new byte[64],
        };

        // Serialize + sign
        var serialized = ContactCapsuleSerializer.Serialize(capsule);
        var signable = ContactCapsuleSerializer.GetSignableSpan(serialized);
        capsule.Signature = _crypto.Sign(signable, peerPriv);
        var payload = ContactCapsuleSerializer.Serialize(capsule);

        // Encode with well-known contact key
        var token = CapsuleCodec.Encode(
            CapsuleType.ContactInvite, payload, CapsuleCodec.ContactCapsuleKey, _crypto);

        // Verify token format
        Assert.DoesNotContain("=", token);
        Assert.DoesNotContain("+", token);
        Assert.DoesNotContain("/", token);

        // Decode
        var (type, decoded) = CapsuleCodec.Decode(
            token, CapsuleCodec.ContactCapsuleKey, _crypto);

        Assert.Equal(CapsuleType.ContactInvite, type);

        // Deserialize
        var result = ContactCapsuleSerializer.Deserialize(decoded);

        Assert.Equal(peerId, result.PeerId);
        Assert.Equal("Alice", result.DisplayName);
        Assert.Single(result.Endpoints);
        Assert.Equal("10.0.0.1", result.Endpoints[0].Address.ToString());
        Assert.Equal(9000, result.Endpoints[0].Port);

        // Verify signature survives round-trip
        var finalBytes = ContactCapsuleSerializer.Serialize(result);
        var verifySig = ContactCapsuleSerializer.GetSignableSpan(finalBytes);
        Assert.True(_crypto.Verify(verifySig, result.Signature!, peerPub));
    }

    [Fact]
    public void ContactInvite_NoEndpoints_Roundtrip()
    {
        var (peerPub, _) = _crypto.GenerateEd25519Keypair();

        var capsule = new ContactCapsule
        {
            PeerId = new PeerId(peerPub),
            DisplayName = "Bob",
            Endpoints = [],
            CreatedAt = DateTimeOffset.UtcNow,
            Signature = _crypto.GenerateRandomBytes(64),
        };

        var payload = ContactCapsuleSerializer.Serialize(capsule);
        var token = CapsuleCodec.Encode(
            CapsuleType.ContactInvite, payload, CapsuleCodec.ContactCapsuleKey, _crypto);
        var (type, decoded) = CapsuleCodec.Decode(
            token, CapsuleCodec.ContactCapsuleKey, _crypto);

        Assert.Equal(CapsuleType.ContactInvite, type);

        var result = ContactCapsuleSerializer.Deserialize(decoded);
        Assert.Equal("Bob", result.DisplayName);
        Assert.Empty(result.Endpoints);
    }

    [Fact]
    public void ContactInvite_IPv6_Roundtrip()
    {
        var (peerPub, _) = _crypto.GenerateEd25519Keypair();

        var capsule = new ContactCapsule
        {
            PeerId = new PeerId(peerPub),
            DisplayName = "Charlie",
            Endpoints = [new IPEndPoint(IPAddress.IPv6Loopback, 8080)],
            CreatedAt = DateTimeOffset.UtcNow,
            Signature = _crypto.GenerateRandomBytes(64),
        };

        var payload = ContactCapsuleSerializer.Serialize(capsule);
        var token = CapsuleCodec.Encode(
            CapsuleType.ContactInvite, payload, CapsuleCodec.ContactCapsuleKey, _crypto);
        var (type, decoded) = CapsuleCodec.Decode(
            token, CapsuleCodec.ContactCapsuleKey, _crypto);

        var result = ContactCapsuleSerializer.Deserialize(decoded);
        Assert.Equal(IPAddress.IPv6Loopback, result.Endpoints[0].Address);
        Assert.Equal(8080, result.Endpoints[0].Port);
    }

    // ── CapsuleCodec edge cases ──────────────────────────

    [Fact]
    public void Decode_WrongKey_ThrowsFormatException()
    {
        var key = _crypto.GenerateSymmetricKey();
        var wrongKey = _crypto.GenerateSymmetricKey();

        var token = CapsuleCodec.Encode(CapsuleType.GroupInvite, [1, 2, 3], key, _crypto);

        Assert.Throws<FormatException>(() => CapsuleCodec.Decode(token, wrongKey, _crypto));
    }

    [Fact]
    public void Token_IsBase64Url_NoPadding()
    {
        var key = _crypto.GenerateSymmetricKey();
        // Test with various payload sizes to ensure no padding appears
        for (int size = 1; size <= 50; size++)
        {
            var payload = _crypto.GenerateRandomBytes(size);
            var token = CapsuleCodec.Encode(CapsuleType.GroupInvite, payload, key, _crypto);

            Assert.DoesNotContain("=", token);
            Assert.DoesNotContain("+", token);
            Assert.DoesNotContain("/", token);
            Assert.DoesNotContain("\n", token);
            Assert.DoesNotContain("\r", token);
        }
    }

    [Fact]
    public void Version_IsPreserved()
    {
        var key = _crypto.GenerateSymmetricKey();
        var token = CapsuleCodec.Encode(CapsuleType.GroupInvite, [0xAA, 0xBB], key, _crypto);
        var (type, payload) = CapsuleCodec.Decode(token, key, _crypto);

        Assert.Equal(CapsuleType.GroupInvite, type);
        Assert.Equal(new byte[] { 0xAA, 0xBB }, payload);
    }

    [Fact]
    public void Base64UrlEncode_Decode_Roundtrip()
    {
        var data = _crypto.GenerateRandomBytes(100);
        var encoded = CapsuleCodec.Base64UrlEncode(data);
        var decoded = CapsuleCodec.Base64UrlDecode(encoded);

        Assert.Equal(data, decoded);
        Assert.DoesNotContain("=", encoded);
        Assert.DoesNotContain("+", encoded);
        Assert.DoesNotContain("/", encoded);
    }

    // ── Full URL round-trip (GroupInvite via InviteUrl) ───

    [Fact]
    public void GroupInvite_FullUrlRoundtrip()
    {
        var (creatorPub, creatorPriv) = _crypto.GenerateEd25519Keypair();
        var groupKey = _crypto.GenerateSymmetricKey();
        var wgKey = _crypto.GenerateRandomBytes(32);

        var capsule = new InviteCapsule
        {
            InviteId = Guid.NewGuid(),
            GroupId = new GroupId(_crypto.GenerateRandomBytes(32)),
            Creator = new PeerId(creatorPub),
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(24),
            Flags = InviteFlags.None,
            BootstrapPeers =
            [
                new BootstrapPeer(wgKey, new IPEndPoint(IPAddress.Parse("1.2.3.4"), 51820))
            ],
            CreatorSignature = _crypto.GenerateRandomBytes(64),
        };

        var payload = InviteCapsuleSerializer.Serialize(capsule);
        var token = CapsuleCodec.Encode(CapsuleType.GroupInvite, payload, groupKey, _crypto);

        // Build full URL
        var url = InviteUrl.Create(token, capsule.BootstrapPeers);
        Assert.StartsWith("vox://join/", url);

        // Parse URL
        var parsed = InviteUrl.Parse(url);
        Assert.Equal(wgKey, parsed.BootstrapWireGuardPublicKey);

        // Decode capsule from URL
        var (type, decoded) = CapsuleCodec.Decode(parsed.CapsuleToken, groupKey, _crypto);
        Assert.Equal(CapsuleType.GroupInvite, type);

        var result = InviteCapsuleSerializer.Deserialize(decoded);
        Assert.Equal(capsule.InviteId, result.InviteId);
        Assert.Equal(capsule.GroupId, result.GroupId);
    }

    // ── Full URL round-trip (ContactInvite) ──────────────

    [Fact]
    public void ContactInvite_FullUrlRoundtrip()
    {
        var (peerPub, peerPriv) = _crypto.GenerateEd25519Keypair();

        var capsule = new ContactCapsule
        {
            PeerId = new PeerId(peerPub),
            DisplayName = "TestUser",
            Endpoints = [new IPEndPoint(IPAddress.Loopback, 5000)],
            CreatedAt = DateTimeOffset.UtcNow,
            Signature = new byte[64],
        };

        var serialized = ContactCapsuleSerializer.Serialize(capsule);
        var signable = ContactCapsuleSerializer.GetSignableSpan(serialized);
        capsule.Signature = _crypto.Sign(signable, peerPriv);
        var payload = ContactCapsuleSerializer.Serialize(capsule);

        var token = CapsuleCodec.Encode(
            CapsuleType.ContactInvite, payload, CapsuleCodec.ContactCapsuleKey, _crypto);

        // Build contact URL
        var url = $"vox://contact/{token}";
        Assert.StartsWith("vox://contact/", url);

        // Extract token from URL
        var extractedToken = url["vox://contact/".Length..];

        // Decode
        var (type, decoded) = CapsuleCodec.Decode(
            extractedToken, CapsuleCodec.ContactCapsuleKey, _crypto);
        Assert.Equal(CapsuleType.ContactInvite, type);

        var result = ContactCapsuleSerializer.Deserialize(decoded);
        Assert.Equal(capsule.PeerId, result.PeerId);
        Assert.Equal("TestUser", result.DisplayName);

        // Verify signature
        var finalBytes = ContactCapsuleSerializer.Serialize(result);
        var verifySig = ContactCapsuleSerializer.GetSignableSpan(finalBytes);
        Assert.True(_crypto.Verify(verifySig, result.Signature!, peerPub));
    }
}
