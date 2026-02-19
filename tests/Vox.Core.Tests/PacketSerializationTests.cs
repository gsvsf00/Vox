using Vox.Core.Protocol;

namespace Vox.Core.Tests;

public class PacketSerializationTests
{
    [Fact]
    public void CommonHeader_WriteTo_ReadFrom_roundtrip()
    {
        var header = new CommonHeader
        {
            PacketType = PacketTypes.ChatMessage,
            PayloadLength = 1234,
            PacketId = 9876543210L,
            Ttl = 5,
            Flags = PacketFlags.RequiresAck,
        };

        Span<byte> buffer = stackalloc byte[CommonHeader.Size];
        header.WriteTo(buffer);

        var restored = CommonHeader.ReadFrom(buffer);

        Assert.Equal(header.PacketType, restored.PacketType);
        Assert.Equal(header.PayloadLength, restored.PayloadLength);
        Assert.Equal(header.PacketId, restored.PacketId);
        Assert.Equal(header.Ttl, restored.Ttl);
        Assert.Equal(header.Flags, restored.Flags);
    }

    [Fact]
    public void CommonHeader_size_is_15_bytes()
    {
        Assert.Equal(15, CommonHeader.Size);
    }

    [Fact]
    public void VoiceFramePacket_serialize_deserialize_roundtrip()
    {
        var serializer = new VoiceFrameSerializer();
        var senderKey = new byte[32];
        senderKey[0] = 0xDE;
        senderKey[31] = 0xAD;

        var opusData = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 };

        var packet = new VoiceFramePacket
        {
            SequenceNumber = 42,
            TimestampUs = 1234567890123L,
            Sender = new Identity.PeerId(senderKey),
            CodecFlags = 0x10, // DTX
            ChannelId = 1,
            OpusPayload = opusData,
        };

        var size = serializer.GetSerializedSize(in packet);
        Assert.Equal(VoiceFramePacket.HeaderSize + opusData.Length, size);

        var buffer = new byte[size];
        var written = serializer.Serialize(in packet, buffer);
        Assert.Equal(size, written);

        var restored = serializer.Deserialize(buffer);

        Assert.Equal(packet.SequenceNumber, restored.SequenceNumber);
        Assert.Equal(packet.TimestampUs, restored.TimestampUs);
        Assert.Equal(packet.Sender, restored.Sender);
        Assert.Equal(packet.CodecFlags, restored.CodecFlags);
        Assert.Equal(packet.ChannelId, restored.ChannelId);
        Assert.Equal(opusData, restored.OpusPayload.ToArray());
    }

    [Fact]
    public void VoiceFramePacket_header_is_49_bytes()
    {
        Assert.Equal(49, VoiceFramePacket.HeaderSize);
    }

    [Fact]
    public void VoiceFramePacket_type_code_is_0x20()
    {
        Assert.Equal(0x20, VoiceFramePacket.TypeCode);
    }

    [Fact]
    public void VoiceFrame_first_byte_is_packet_type()
    {
        var serializer = new VoiceFrameSerializer();
        var packet = new VoiceFramePacket
        {
            SequenceNumber = 0,
            TimestampUs = 0,
            Sender = new Identity.PeerId(new byte[32]),
            CodecFlags = 0,
            ChannelId = 0,
            OpusPayload = new byte[] { 0xFF },
        };

        var buf = new byte[serializer.GetSerializedSize(in packet)];
        serializer.Serialize(in packet, buf);

        Assert.Equal(PacketTypes.VoiceFrame, buf[0]);
    }
}
