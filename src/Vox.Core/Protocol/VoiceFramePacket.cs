using System.Buffers.Binary;
using Vox.Core.Identity;

namespace Vox.Core.Protocol;

/// <summary>
/// VoiceFrame (0x20): minimal header for voice packets.
/// 49 bytes + Opus payload. Per PROTOCOL.md §12.1.
/// </summary>
public struct VoiceFramePacket
{
    public const int HeaderSize = 49;
    public const byte TypeCode = PacketTypes.VoiceFrame;

    public uint SequenceNumber;
    public long TimestampUs;
    public PeerId Sender;
    public byte CodecFlags;
    public byte ChannelId;
    public Memory<byte> OpusPayload;
}

public sealed class VoiceFrameSerializer : IPacketSerializer<VoiceFramePacket>
{
    public int GetSerializedSize(in VoiceFramePacket packet) =>
        VoiceFramePacket.HeaderSize + packet.OpusPayload.Length;

    public int Serialize(in VoiceFramePacket packet, Span<byte> buffer)
    {
        int offset = 0;
        buffer[offset++] = VoiceFramePacket.TypeCode;
        BinaryPrimitives.WriteUInt32LittleEndian(buffer[offset..], packet.SequenceNumber);
        offset += 4;
        BinaryPrimitives.WriteInt64LittleEndian(buffer[offset..], packet.TimestampUs);
        offset += 8;
        packet.Sender.PublicKey.CopyTo(buffer[offset..]);
        offset += PeerId.Size;
        buffer[offset++] = packet.CodecFlags;
        buffer[offset++] = packet.ChannelId;
        BinaryPrimitives.WriteUInt16LittleEndian(buffer[offset..], (ushort)packet.OpusPayload.Length);
        offset += 2;
        packet.OpusPayload.Span.CopyTo(buffer[offset..]);
        offset += packet.OpusPayload.Length;
        return offset;
    }

    public VoiceFramePacket Deserialize(ReadOnlySpan<byte> buffer)
    {
        int offset = 1; // skip packet_type
        var seq = BinaryPrimitives.ReadUInt32LittleEndian(buffer[offset..]);
        offset += 4;
        var ts = BinaryPrimitives.ReadInt64LittleEndian(buffer[offset..]);
        offset += 8;
        var sender = new PeerId(buffer.Slice(offset, PeerId.Size));
        offset += PeerId.Size;
        var codecFlags = buffer[offset++];
        var channelId = buffer[offset++];
        var frameLen = BinaryPrimitives.ReadUInt16LittleEndian(buffer[offset..]);
        offset += 2;
        var opus = buffer.Slice(offset, frameLen).ToArray();

        return new VoiceFramePacket
        {
            SequenceNumber = seq,
            TimestampUs = ts,
            Sender = sender,
            CodecFlags = codecFlags,
            ChannelId = channelId,
            OpusPayload = opus,
        };
    }
}
