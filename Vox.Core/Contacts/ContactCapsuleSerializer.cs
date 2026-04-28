using System.Buffers.Binary;
using System.Net;
using System.Text;
using Vox.Core.Identity;

namespace Vox.Core.Contacts;

/// <summary>
/// Binary serializer for <see cref="ContactCapsule"/>.
/// Layout (all little-endian):
///   peer_id(32) + display_name_length(1) + display_name_utf8(var) +
///   endpoint_count(1) + foreach { ip_len(1) + ip(var) + port(2) } +
///   timestamp_ms(8) + signature(64)
/// </summary>
public static class ContactCapsuleSerializer
{
    public const int SignatureSize = 64;

    public static byte[] Serialize(ContactCapsule capsule)
    {
        var size = GetSerializedSize(capsule);
        var buffer = new byte[size];
        var span = buffer.AsSpan();
        int offset = 0;

        // peer_id (32B)
        capsule.PeerId.PublicKey.CopyTo(span[offset..]);
        offset += PeerId.Size;

        // display_name_length (1B) + display_name_utf8 (var)
        var nameBytes = Encoding.UTF8.GetBytes(capsule.DisplayName);
        span[offset++] = (byte)nameBytes.Length;
        nameBytes.CopyTo(span[offset..]);
        offset += nameBytes.Length;

        // endpoint_count (1B) + endpoints
        span[offset++] = (byte)capsule.Endpoints.Count;
        foreach (var ep in capsule.Endpoints)
        {
            var ipBytes = ep.Address.GetAddressBytes();
            span[offset++] = (byte)ipBytes.Length;
            ipBytes.CopyTo(span[offset..]);
            offset += ipBytes.Length;
            BinaryPrimitives.WriteUInt16LittleEndian(span[offset..], (ushort)ep.Port);
            offset += 2;
        }

        // timestamp_ms (8B)
        BinaryPrimitives.WriteInt64LittleEndian(span[offset..], capsule.CreatedAt.ToUnixTimeMilliseconds());
        offset += 8;

        // signature (64B)
        capsule.Signature?.CopyTo(span[offset..]);

        return buffer;
    }

    /// <summary>
    /// Returns everything before the 64-byte signature for signing.
    /// </summary>
    public static ReadOnlySpan<byte> GetSignableSpan(ReadOnlySpan<byte> serialized)
    {
        return serialized[..^SignatureSize];
    }

    public static ContactCapsule Deserialize(ReadOnlySpan<byte> data)
    {
        int offset = 0;

        // peer_id (32B)
        var peerId = new PeerId(data.Slice(offset, PeerId.Size));
        offset += PeerId.Size;

        // display_name
        var nameLen = data[offset++];
        var displayName = Encoding.UTF8.GetString(data.Slice(offset, nameLen));
        offset += nameLen;

        // endpoints
        var endpointCount = data[offset++];
        var endpoints = new List<IPEndPoint>(endpointCount);
        for (int i = 0; i < endpointCount; i++)
        {
            var ipLen = data[offset++];
            var ip = new IPAddress(data.Slice(offset, ipLen));
            offset += ipLen;
            var port = BinaryPrimitives.ReadUInt16LittleEndian(data[offset..]);
            offset += 2;
            endpoints.Add(new IPEndPoint(ip, port));
        }

        // timestamp_ms (8B)
        var timestampMs = BinaryPrimitives.ReadInt64LittleEndian(data[offset..]);
        offset += 8;

        // signature (64B)
        var signature = data.Slice(offset, SignatureSize).ToArray();

        return new ContactCapsule
        {
            PeerId = peerId,
            DisplayName = displayName,
            Endpoints = endpoints,
            CreatedAt = DateTimeOffset.FromUnixTimeMilliseconds(timestampMs),
            Signature = signature,
        };
    }

    private static int GetSerializedSize(ContactCapsule capsule)
    {
        var nameLen = Encoding.UTF8.GetByteCount(capsule.DisplayName);
        int size = PeerId.Size + 1 + nameLen + 1; // peer_id + name_len + name + ep_count

        foreach (var ep in capsule.Endpoints)
        {
            size += 1 + ep.Address.GetAddressBytes().Length + 2; // ip_len + ip + port
        }

        size += 8; // timestamp_ms
        size += SignatureSize;
        return size;
    }
}
