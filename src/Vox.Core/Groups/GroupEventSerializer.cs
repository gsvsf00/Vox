using System.Buffers.Binary;
using Vox.Core.Events;
using Vox.Core.Identity;

namespace Vox.Core.Groups;

/// <summary>
/// Binary serializer for <see cref="GroupEvent"/>.
/// Layout:
///   event_id(16) + group_id(32) + author(32) + lamport_clock(8) +
///   event_type(1) + parent_count(1) + parent_ids(count*16) +
///   payload_length(4) + payload(var) + signature(64)
/// </summary>
public static class GroupEventSerializer
{
    public const int SignatureSize = 64;
    public const int FixedHeaderSize = 16 + GroupId.Size + PeerId.Size + 8 + 1 + 1; // 90 bytes

    public static byte[] Serialize(GroupEvent evt)
    {
        var size = FixedHeaderSize + evt.ParentIds.Count * 16 + 4 + evt.Payload.Length + SignatureSize;
        var buffer = new byte[size];
        var span = buffer.AsSpan();
        int offset = 0;

        evt.EventId.TryWriteBytes(span[offset..]);
        offset += 16;

        evt.GroupId.Bytes.CopyTo(span[offset..]);
        offset += GroupId.Size;

        evt.Author.PublicKey.CopyTo(span[offset..]);
        offset += PeerId.Size;

        BinaryPrimitives.WriteUInt64LittleEndian(span[offset..], evt.LamportClock);
        offset += 8;

        span[offset++] = (byte)evt.EventType;

        span[offset++] = (byte)evt.ParentIds.Count;
        foreach (var parentId in evt.ParentIds)
        {
            parentId.TryWriteBytes(span[offset..]);
            offset += 16;
        }

        BinaryPrimitives.WriteInt32LittleEndian(span[offset..], evt.Payload.Length);
        offset += 4;
        evt.Payload.CopyTo(span[offset..]);
        offset += evt.Payload.Length;

        evt.Signature.CopyTo(span[offset..]);

        return buffer;
    }

    /// <summary>
    /// Returns the signable span (everything before the 64-byte signature).
    /// </summary>
    public static ReadOnlySpan<byte> GetSignableSpan(ReadOnlySpan<byte> serialized)
    {
        return serialized[..^SignatureSize];
    }

    public static GroupEvent Deserialize(ReadOnlySpan<byte> data)
    {
        int offset = 0;

        var eventId = new Guid(data.Slice(offset, 16));
        offset += 16;

        var groupId = new GroupId(data.Slice(offset, GroupId.Size));
        offset += GroupId.Size;

        var author = new PeerId(data.Slice(offset, PeerId.Size));
        offset += PeerId.Size;

        var lamportClock = BinaryPrimitives.ReadUInt64LittleEndian(data[offset..]);
        offset += 8;

        var eventType = (GroupEventType)data[offset++];

        var parentCount = data[offset++];
        var parentIds = new List<Guid>(parentCount);
        for (int i = 0; i < parentCount; i++)
        {
            parentIds.Add(new Guid(data.Slice(offset, 16)));
            offset += 16;
        }

        var payloadLength = BinaryPrimitives.ReadInt32LittleEndian(data[offset..]);
        offset += 4;
        var payload = data.Slice(offset, payloadLength).ToArray();
        offset += payloadLength;

        var signature = data.Slice(offset, SignatureSize).ToArray();

        return new GroupEvent
        {
            EventId = eventId,
            GroupId = groupId,
            Author = author,
            LamportClock = lamportClock,
            EventType = eventType,
            ParentIds = parentIds,
            Payload = payload,
            Signature = signature,
        };
    }
}
