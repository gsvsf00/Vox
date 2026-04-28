using System.Buffers.Binary;
using System.Net;
using Vox.Core.Identity;

namespace Vox.Core.Groups;

/// <summary>
/// Binary serializer for <see cref="InviteCapsule"/>.
/// Layout (all little-endian):
///   invite_id(16) + group_id(32) + creator(32) + created_at_ms(8) + expires_at_ms(8) +
///   flags(1) + password_hash_present(1) + [password_hash(32)] +
///   bootstrap_count(1) + foreach bootstrap { wg_pub(32) + ip_len(1) + ip(var) + port(2) } +
///   creator_signature(64)
/// </summary>
public static class InviteCapsuleSerializer
{
    public const int SignatureSize = 64;

    public static byte[] Serialize(InviteCapsule capsule)
    {
        var size = GetSerializedSize(capsule);
        var buffer = new byte[size];
        var span = buffer.AsSpan();
        int offset = 0;

        // invite_id (16 bytes, UUID)
        capsule.InviteId.TryWriteBytes(span[offset..]);
        offset += 16;

        // group_id (32 bytes)
        capsule.GroupId.Bytes.CopyTo(span[offset..]);
        offset += GroupId.Size;

        // creator (32 bytes)
        capsule.Creator.PublicKey.CopyTo(span[offset..]);
        offset += PeerId.Size;

        // created_at_ms (8 bytes)
        BinaryPrimitives.WriteInt64LittleEndian(span[offset..], capsule.CreatedAt.ToUnixTimeMilliseconds());
        offset += 8;

        // expires_at_ms (8 bytes)
        BinaryPrimitives.WriteInt64LittleEndian(span[offset..], capsule.ExpiresAt.ToUnixTimeMilliseconds());
        offset += 8;

        // flags (1 byte)
        span[offset++] = (byte)capsule.Flags;

        // password_hash_present (1 byte) + optional password_hash (32 bytes)
        if (capsule.PasswordHash is { Length: 32 })
        {
            span[offset++] = 1;
            capsule.PasswordHash.CopyTo(span[offset..]);
            offset += 32;
        }
        else
        {
            span[offset++] = 0;
        }

        // bootstrap_count (1 byte) + bootstraps
        span[offset++] = (byte)capsule.BootstrapPeers.Count;
        foreach (var bp in capsule.BootstrapPeers)
        {
            bp.WireGuardPublicKey.CopyTo(span[offset..]);
            offset += 32;

            var ipBytes = bp.Endpoint.Address.GetAddressBytes();
            span[offset++] = (byte)ipBytes.Length;
            ipBytes.CopyTo(span[offset..]);
            offset += ipBytes.Length;

            BinaryPrimitives.WriteUInt16LittleEndian(span[offset..], (ushort)bp.Endpoint.Port);
            offset += 2;
        }

        // creator_signature (64 bytes)
        capsule.CreatorSignature?.CopyTo(span[offset..]);

        return buffer;
    }

    /// <summary>
    /// Returns everything before the 64-byte creator signature for signing.
    /// </summary>
    public static ReadOnlySpan<byte> GetSignableSpan(ReadOnlySpan<byte> serialized)
    {
        return serialized[..^SignatureSize];
    }

    public static InviteCapsule Deserialize(ReadOnlySpan<byte> data)
    {
        int offset = 0;

        var inviteId = new Guid(data.Slice(offset, 16));
        offset += 16;

        var groupId = new GroupId(data.Slice(offset, GroupId.Size));
        offset += GroupId.Size;

        var creator = new PeerId(data.Slice(offset, PeerId.Size));
        offset += PeerId.Size;

        var createdAtMs = BinaryPrimitives.ReadInt64LittleEndian(data[offset..]);
        offset += 8;

        var expiresAtMs = BinaryPrimitives.ReadInt64LittleEndian(data[offset..]);
        offset += 8;

        var flags = (InviteFlags)data[offset++];

        byte[]? passwordHash = null;
        var hasPasswordHash = data[offset++];
        if (hasPasswordHash == 1)
        {
            passwordHash = data.Slice(offset, 32).ToArray();
            offset += 32;
        }

        var bootstrapCount = data[offset++];
        var bootstraps = new List<BootstrapPeer>(bootstrapCount);
        for (int i = 0; i < bootstrapCount; i++)
        {
            var wgPub = data.Slice(offset, 32).ToArray();
            offset += 32;

            var ipLen = data[offset++];
            var ipBytes = data.Slice(offset, ipLen).ToArray();
            offset += ipLen;
            var ip = new IPAddress(ipBytes);

            var port = BinaryPrimitives.ReadUInt16LittleEndian(data[offset..]);
            offset += 2;

            bootstraps.Add(new BootstrapPeer(wgPub, new IPEndPoint(ip, port)));
        }

        var signature = data.Slice(offset, SignatureSize).ToArray();

        return new InviteCapsule
        {
            InviteId = inviteId,
            GroupId = groupId,
            Creator = creator,
            CreatedAt = DateTimeOffset.FromUnixTimeMilliseconds(createdAtMs),
            ExpiresAt = DateTimeOffset.FromUnixTimeMilliseconds(expiresAtMs),
            Flags = flags,
            PasswordHash = passwordHash,
            BootstrapPeers = bootstraps,
            CreatorSignature = signature,
        };
    }

    private static int GetSerializedSize(InviteCapsule capsule)
    {
        int size = 16 + GroupId.Size + PeerId.Size + 8 + 8 + 1 + 1;
        if (capsule.PasswordHash is { Length: 32 })
            size += 32;

        size += 1; // bootstrap_count
        foreach (var bp in capsule.BootstrapPeers)
        {
            size += 32; // wg_pub
            var ipLen = bp.Endpoint.Address.GetAddressBytes().Length;
            size += 1 + ipLen + 2; // ip_len + ip + port
        }

        size += SignatureSize;
        return size;
    }
}
