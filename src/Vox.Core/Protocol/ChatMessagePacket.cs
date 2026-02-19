using System.Buffers.Binary;
using Vox.Core.Groups;
using Vox.Core.Identity;

namespace Vox.Core.Protocol;

/// <summary>
/// ChatMessage (0x10) binary packet. Per PROTOCOL.md §9.1.
///
/// Layout:
///   common_header(15) + sender_identity(32) + group_id(32) + message_id(16) +
///   timestamp_ms(8) + lamport_clock(8) + parent_count(1) + parent_event_ids(N×16) +
///   content_length(4) + content_utf8(var) + signature(64)
///
/// Signature covers bytes after the common header through end minus 64 (before signature).
/// </summary>
public struct ChatMessagePacket
{
    public const int SignatureSize = 64;
    /// <summary>Fixed payload size (excluding parents and content): 32+32+16+8+8+1+4+64 = 165 bytes.</summary>
    public const int FixedFieldsSize = PeerId.Size + GroupId.Size + 16 + 8 + 8 + 1 + 4 + SignatureSize;

    public CommonHeader Header;
    public PeerId Sender;
    public GroupId GroupId;
    public Guid MessageId;
    public long TimestampMs;
    public ulong LamportClock;
    public Guid[] ParentEventIds;
    public byte[] ContentUtf8;
    public byte[] Signature;
}

public sealed class ChatMessageSerializer : IPacketSerializer<ChatMessagePacket>
{
    public int GetSerializedSize(in ChatMessagePacket packet)
    {
        var parentCount = packet.ParentEventIds?.Length ?? 0;
        return CommonHeader.Size + ChatMessagePacket.FixedFieldsSize
            + parentCount * 16 + (packet.ContentUtf8?.Length ?? 0);
    }

    public int Serialize(in ChatMessagePacket packet, Span<byte> buffer)
    {
        var parentCount = packet.ParentEventIds?.Length ?? 0;
        var contentLength = packet.ContentUtf8?.Length ?? 0;
        var payloadLength = (uint)(ChatMessagePacket.FixedFieldsSize + parentCount * 16 + contentLength);

        var header = new CommonHeader
        {
            PacketType = PacketTypes.ChatMessage,
            PayloadLength = payloadLength,
            PacketId = packet.Header.PacketId,
            Ttl = packet.Header.Ttl,
            Flags = packet.Header.Flags,
        };
        header.WriteTo(buffer);
        int offset = CommonHeader.Size;

        // sender_identity (32)
        packet.Sender.PublicKey.CopyTo(buffer[offset..]);
        offset += PeerId.Size;

        // group_id (32)
        packet.GroupId.Bytes.CopyTo(buffer[offset..]);
        offset += GroupId.Size;

        // message_id (16)
        packet.MessageId.TryWriteBytes(buffer[offset..]);
        offset += 16;

        // timestamp_ms (8)
        BinaryPrimitives.WriteInt64LittleEndian(buffer[offset..], packet.TimestampMs);
        offset += 8;

        // lamport_clock (8)
        BinaryPrimitives.WriteUInt64LittleEndian(buffer[offset..], packet.LamportClock);
        offset += 8;

        // parent_count (1)
        buffer[offset++] = (byte)parentCount;

        // parent_event_ids (N × 16)
        if (packet.ParentEventIds is not null)
        {
            foreach (var id in packet.ParentEventIds)
            {
                id.TryWriteBytes(buffer[offset..]);
                offset += 16;
            }
        }

        // content_length (4)
        BinaryPrimitives.WriteInt32LittleEndian(buffer[offset..], contentLength);
        offset += 4;

        // content_utf8 (var)
        if (packet.ContentUtf8 is { Length: > 0 })
        {
            packet.ContentUtf8.AsSpan().CopyTo(buffer[offset..]);
            offset += contentLength;
        }

        // signature (64)
        if (packet.Signature is { Length: ChatMessagePacket.SignatureSize })
        {
            packet.Signature.AsSpan().CopyTo(buffer[offset..]);
        }
        offset += ChatMessagePacket.SignatureSize;

        return offset;
    }

    public ChatMessagePacket Deserialize(ReadOnlySpan<byte> buffer)
    {
        var header = CommonHeader.ReadFrom(buffer);
        int offset = CommonHeader.Size;

        var sender = new PeerId(buffer.Slice(offset, PeerId.Size));
        offset += PeerId.Size;

        var groupId = new GroupId(buffer.Slice(offset, GroupId.Size));
        offset += GroupId.Size;

        var messageId = new Guid(buffer.Slice(offset, 16));
        offset += 16;

        var timestampMs = BinaryPrimitives.ReadInt64LittleEndian(buffer[offset..]);
        offset += 8;

        var lamportClock = BinaryPrimitives.ReadUInt64LittleEndian(buffer[offset..]);
        offset += 8;

        var parentCount = buffer[offset++];
        var parentIds = new Guid[parentCount];
        for (int i = 0; i < parentCount; i++)
        {
            parentIds[i] = new Guid(buffer.Slice(offset, 16));
            offset += 16;
        }

        var contentLength = BinaryPrimitives.ReadInt32LittleEndian(buffer[offset..]);
        offset += 4;

        var contentUtf8 = buffer.Slice(offset, contentLength).ToArray();
        offset += contentLength;

        var signature = buffer.Slice(offset, ChatMessagePacket.SignatureSize).ToArray();

        return new ChatMessagePacket
        {
            Header = header,
            Sender = sender,
            GroupId = groupId,
            MessageId = messageId,
            TimestampMs = timestampMs,
            LamportClock = lamportClock,
            ParentEventIds = parentIds,
            ContentUtf8 = contentUtf8,
            Signature = signature,
        };
    }

    /// <summary>
    /// Returns the span of bytes that should be signed/verified.
    /// Per PROTOCOL.md §9.1: signature covers bytes after the common header through end minus 64.
    /// </summary>
    public static ReadOnlySpan<byte> GetSignableSpan(ReadOnlySpan<byte> packet)
    {
        return packet[CommonHeader.Size..^ChatMessagePacket.SignatureSize];
    }
}
