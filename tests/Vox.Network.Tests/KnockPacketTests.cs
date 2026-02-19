using System.Buffers.Binary;
using System.Net;
using Vox.Core.Configuration;
using Vox.Network.WireGuard;

namespace Vox.Network.Tests;

public class KnockPacketTests
{
    private static byte[] RandomBytes(int length)
    {
        var bytes = new byte[length];
        Random.Shared.NextBytes(bytes);
        return bytes;
    }

    // --- Knock serialization ---

    [Fact]
    public void SerializeKnock_roundtrip_without_password()
    {
        var wgPub = RandomBytes(32);
        var idPub = RandomBytes(32);
        var capsule = RandomBytes(100);
        var signature = RandomBytes(64);
        long timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        var serialized = KnockPacket.SerializeKnock(wgPub, idPub, capsule, null, timestamp, signature);
        var endpoint = new IPEndPoint(IPAddress.Loopback, 12345);
        var request = KnockPacket.DeserializeKnock(serialized, endpoint);

        Assert.Equal(wgPub, request.JoinerWgPubKey);
        Assert.Equal(idPub, request.JoinerIdentityPubKey);
        Assert.Equal(capsule, request.Capsule);
        Assert.Null(request.Password);
        Assert.Equal(timestamp, request.TimestampMs);
        Assert.Equal(signature, request.Signature);
        Assert.Equal(endpoint, request.RemoteEndpoint);
    }

    [Fact]
    public void SerializeKnock_roundtrip_with_password()
    {
        var wgPub = RandomBytes(32);
        var idPub = RandomBytes(32);
        var capsule = RandomBytes(50);
        var password = System.Text.Encoding.UTF8.GetBytes("hunter2");
        var signature = RandomBytes(64);
        long timestamp = 1700000000000L;

        var serialized = KnockPacket.SerializeKnock(wgPub, idPub, capsule, password, timestamp, signature);
        var endpoint = new IPEndPoint(IPAddress.Parse("192.168.1.1"), 9999);
        var request = KnockPacket.DeserializeKnock(serialized, endpoint);

        Assert.Equal(wgPub, request.JoinerWgPubKey);
        Assert.Equal(idPub, request.JoinerIdentityPubKey);
        Assert.Equal(capsule, request.Capsule);
        Assert.Equal("hunter2", request.Password);
        Assert.Equal(timestamp, request.TimestampMs);
        Assert.Equal(signature, request.Signature);
    }

    [Fact]
    public void SerializeKnock_has_correct_magic_and_version()
    {
        var data = KnockPacket.SerializeKnock(
            new byte[32], new byte[32], new byte[10], null, 0, new byte[64]);

        var magic = BinaryPrimitives.ReadUInt32LittleEndian(data);
        Assert.Equal(VoxDefaults.KnockMagic, magic);
        Assert.Equal(VoxDefaults.ProtocolVersion, data[4]);
    }

    [Fact]
    public void SerializeKnock_size_without_password_matches_constant()
    {
        var capsule = new byte[0];
        var data = KnockPacket.SerializeKnock(
            new byte[32], new byte[32], capsule, null, 0, new byte[64]);

        Assert.Equal(KnockPacket.KnockFixedSize, data.Length);
    }

    [Fact]
    public void SerializeKnock_size_includes_capsule_and_password()
    {
        var capsule = new byte[50];
        var password = new byte[12];
        var data = KnockPacket.SerializeKnock(
            new byte[32], new byte[32], capsule, password, 0, new byte[64]);

        Assert.Equal(KnockPacket.KnockFixedSize + 50 + 12, data.Length);
    }

    [Fact]
    public void DeserializeKnock_rejects_wrong_magic()
    {
        var data = KnockPacket.SerializeKnock(
            new byte[32], new byte[32], new byte[10], null, 0, new byte[64]);

        // Corrupt magic
        BinaryPrimitives.WriteUInt32LittleEndian(data, 0xDEADBEEF);

        var endpoint = new IPEndPoint(IPAddress.Loopback, 1234);
        Assert.Throws<InvalidDataException>(() =>
            KnockPacket.DeserializeKnock(data, endpoint));
    }

    [Fact]
    public void DeserializeKnock_rejects_wrong_version()
    {
        var data = KnockPacket.SerializeKnock(
            new byte[32], new byte[32], new byte[10], null, 0, new byte[64]);

        // Corrupt version byte
        data[4] = 0xFF;

        var endpoint = new IPEndPoint(IPAddress.Loopback, 1234);
        Assert.Throws<InvalidDataException>(() =>
            KnockPacket.DeserializeKnock(data, endpoint));
    }

    // --- KnockAccept serialization ---

    [Fact]
    public void SerializeKnockAccept_roundtrip()
    {
        var wgPub = RandomBytes(32);
        var challenge = RandomBytes(32);
        var signature = RandomBytes(64);
        ushort port = 51820;

        var serialized = KnockPacket.SerializeKnockAccept(
            KnockStatus.Accepted, wgPub, port, challenge, signature);

        var accept = KnockPacket.DeserializeKnockAccept(serialized);

        Assert.Equal(KnockStatus.Accepted, accept.StatusCode);
        Assert.Equal(wgPub, accept.BootstrapWgPubKey);
        Assert.Equal(port, accept.WgListenPort);
        Assert.Equal(challenge, accept.Challenge);
        Assert.Equal(signature, accept.BootstrapIdentitySignature);
    }

    [Fact]
    public void SerializeKnockAccept_size_matches_constant()
    {
        var data = KnockPacket.SerializeKnockAccept(
            0, new byte[32], 0, new byte[32], new byte[64]);

        Assert.Equal(KnockPacket.KnockAcceptSize, data.Length);
    }

    [Fact]
    public void SerializeKnockAccept_has_correct_magic()
    {
        var data = KnockPacket.SerializeKnockAccept(
            0, new byte[32], 51820, new byte[32], new byte[64]);

        var magic = BinaryPrimitives.ReadUInt32LittleEndian(data);
        Assert.Equal(VoxDefaults.KnockAcceptMagic, magic);
    }

    [Fact]
    public void DeserializeKnockAccept_rejects_wrong_magic()
    {
        var data = KnockPacket.SerializeKnockAccept(
            0, new byte[32], 0, new byte[32], new byte[64]);

        BinaryPrimitives.WriteUInt32LittleEndian(data, 0x12345678);

        Assert.Throws<InvalidDataException>(() =>
            KnockPacket.DeserializeKnockAccept(data));
    }

    [Theory]
    [InlineData(KnockStatus.Accepted)]
    [InlineData(KnockStatus.InvalidCapsule)]
    [InlineData(KnockStatus.Expired)]
    [InlineData(KnockStatus.PasswordWrong)]
    [InlineData(KnockStatus.GroupFull)]
    [InlineData(KnockStatus.RateLimited)]
    public void KnockAccept_roundtrips_all_status_codes(byte statusCode)
    {
        var data = KnockPacket.SerializeKnockAccept(
            statusCode, new byte[32], 51820, new byte[32], new byte[64]);

        var accept = KnockPacket.DeserializeKnockAccept(data);
        Assert.Equal(statusCode, accept.StatusCode);
    }

    // --- Signable data ---

    [Fact]
    public void GetKnockSignableData_returns_all_but_last_64_bytes()
    {
        var data = KnockPacket.SerializeKnock(
            new byte[32], new byte[32], new byte[20], null, 0, new byte[64]);

        var signable = KnockPacket.GetKnockSignableData(data);
        Assert.Equal(data.Length - 64, signable.Length);
        // Verify it's the prefix
        Assert.True(data.AsSpan(0, signable.Length).SequenceEqual(signable));
    }

    [Fact]
    public void GetKnockAcceptSignableData_returns_all_but_last_64_bytes()
    {
        var data = KnockPacket.SerializeKnockAccept(
            0, new byte[32], 51820, new byte[32], new byte[64]);

        var signable = KnockPacket.GetKnockAcceptSignableData(data);
        Assert.Equal(data.Length - 64, signable.Length);
        Assert.True(data.AsSpan(0, signable.Length).SequenceEqual(signable));
    }
}
