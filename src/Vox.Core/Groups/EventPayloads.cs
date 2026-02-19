using System.Buffers.Binary;
using System.Text;
using Vox.Core.Configuration;
using Vox.Core.Identity;

namespace Vox.Core.Groups;

/// <summary>
/// Serializer for MemberJoined event payload.
/// Layout: peer_id(32) + username_len(1) + username(var) + discriminator(2) + cert(168)
/// </summary>
public static class MemberJoinedPayload
{
    public static byte[] Serialize(PeerId peerId, string username, ushort discriminator, MembershipCertificate cert)
    {
        var usernameBytes = Encoding.UTF8.GetBytes(username);
        if (usernameBytes.Length > VoxDefaults.MaxUsernameBytes)
            throw new ArgumentException($"Username exceeds {VoxDefaults.MaxUsernameBytes} byte limit when UTF-8 encoded ({usernameBytes.Length} bytes).", nameof(username));
        var certBytes = MembershipCertificateSerializer.Serialize(cert);
        var size = PeerId.Size + 1 + usernameBytes.Length + 2 + certBytes.Length;
        var buffer = new byte[size];
        var span = buffer.AsSpan();
        int offset = 0;

        peerId.PublicKey.CopyTo(span[offset..]);
        offset += PeerId.Size;

        span[offset++] = (byte)usernameBytes.Length;
        usernameBytes.CopyTo(span[offset..]);
        offset += usernameBytes.Length;

        BinaryPrimitives.WriteUInt16LittleEndian(span[offset..], discriminator);
        offset += 2;

        certBytes.CopyTo(span[offset..]);

        return buffer;
    }

    public static MemberJoinedData Deserialize(ReadOnlySpan<byte> data)
    {
        int offset = 0;

        var peerId = new PeerId(data.Slice(offset, PeerId.Size));
        offset += PeerId.Size;

        var usernameLen = data[offset++];
        var username = Encoding.UTF8.GetString(data.Slice(offset, usernameLen));
        offset += usernameLen;

        var discriminator = BinaryPrimitives.ReadUInt16LittleEndian(data[offset..]);
        offset += 2;

        var cert = MembershipCertificateSerializer.Deserialize(data[offset..]);

        return new MemberJoinedData(peerId, username, discriminator, cert);
    }
}

public sealed record MemberJoinedData(
    PeerId PeerId,
    string Username,
    ushort Discriminator,
    MembershipCertificate Certificate);

/// <summary>
/// Serializer for MemberLeft event payload.
/// Layout: peer_id(32) + reason_len(1) + reason(var)
/// </summary>
public static class MemberLeftPayload
{
    public static byte[] Serialize(PeerId peerId, string reason)
    {
        var reasonBytes = Encoding.UTF8.GetBytes(reason);
        if (reasonBytes.Length > VoxDefaults.MaxReasonBytes)
            throw new ArgumentException($"Reason exceeds {VoxDefaults.MaxReasonBytes} byte limit when UTF-8 encoded ({reasonBytes.Length} bytes).", nameof(reason));
        var buffer = new byte[PeerId.Size + 1 + reasonBytes.Length];
        var span = buffer.AsSpan();
        int offset = 0;

        peerId.PublicKey.CopyTo(span[offset..]);
        offset += PeerId.Size;

        span[offset++] = (byte)reasonBytes.Length;
        reasonBytes.CopyTo(span[offset..]);

        return buffer;
    }

    public static MemberLeftData Deserialize(ReadOnlySpan<byte> data)
    {
        int offset = 0;

        var peerId = new PeerId(data.Slice(offset, PeerId.Size));
        offset += PeerId.Size;

        var reasonLen = data[offset++];
        var reason = Encoding.UTF8.GetString(data.Slice(offset, reasonLen));

        return new MemberLeftData(peerId, reason);
    }
}

public sealed record MemberLeftData(PeerId PeerId, string Reason);
