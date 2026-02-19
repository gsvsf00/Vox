using System.Text;
using Vox.Core.Groups;
using Vox.Core.Identity;
using Vox.Core.Protocol;

namespace Vox.Core.Tests;

public class ChatMessageSerializerTests
{
    private readonly ChatMessageSerializer _serializer = new();

    private static PeerId MakePeerId(byte fill = 0xAA)
    {
        var key = new byte[32];
        Array.Fill(key, fill);
        return new PeerId(key);
    }

    private static GroupId MakeGroupId(byte fill = 0xBB)
    {
        var id = new byte[32];
        Array.Fill(id, fill);
        return new GroupId(id);
    }

    [Fact]
    public void Roundtrip_no_parents_no_content()
    {
        var packet = new ChatMessagePacket
        {
            Header = new CommonHeader { PacketId = 42, Ttl = 3, Flags = PacketFlags.RequiresAck },
            Sender = MakePeerId(),
            GroupId = MakeGroupId(),
            MessageId = Guid.NewGuid(),
            TimestampMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            LamportClock = 7,
            ParentEventIds = [],
            ContentUtf8 = [],
            Signature = new byte[64],
        };

        var size = _serializer.GetSerializedSize(in packet);
        var buffer = new byte[size];
        var written = _serializer.Serialize(in packet, buffer);
        Assert.Equal(size, written);

        var restored = _serializer.Deserialize(buffer);

        Assert.Equal(packet.Sender, restored.Sender);
        Assert.Equal(packet.GroupId, restored.GroupId);
        Assert.Equal(packet.MessageId, restored.MessageId);
        Assert.Equal(packet.TimestampMs, restored.TimestampMs);
        Assert.Equal(packet.LamportClock, restored.LamportClock);
        Assert.Empty(restored.ParentEventIds);
        Assert.Empty(restored.ContentUtf8);
    }

    [Fact]
    public void Roundtrip_with_content_and_parents()
    {
        var parentIds = new[] { Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid() };
        var content = Encoding.UTF8.GetBytes("Hello, Vox! 🎉");

        var packet = new ChatMessagePacket
        {
            Header = new CommonHeader { PacketId = 1 },
            Sender = MakePeerId(0x11),
            GroupId = MakeGroupId(0x22),
            MessageId = Guid.NewGuid(),
            TimestampMs = 1700000000000,
            LamportClock = 100,
            ParentEventIds = parentIds,
            ContentUtf8 = content,
            Signature = new byte[64],
        };

        var size = _serializer.GetSerializedSize(in packet);
        var buffer = new byte[size];
        _serializer.Serialize(in packet, buffer);

        var restored = _serializer.Deserialize(buffer);

        Assert.Equal(3, restored.ParentEventIds.Length);
        for (int i = 0; i < 3; i++)
            Assert.Equal(parentIds[i], restored.ParentEventIds[i]);

        Assert.Equal("Hello, Vox! 🎉", Encoding.UTF8.GetString(restored.ContentUtf8));
    }

    [Fact]
    public void Header_fields_preserved()
    {
        var packet = new ChatMessagePacket
        {
            Header = new CommonHeader { PacketId = 999, Ttl = 5, Flags = PacketFlags.Compressed },
            Sender = MakePeerId(),
            GroupId = MakeGroupId(),
            MessageId = Guid.NewGuid(),
            TimestampMs = 123456789,
            LamportClock = 1,
            ParentEventIds = [],
            ContentUtf8 = "test"u8.ToArray(),
            Signature = new byte[64],
        };

        var buf = new byte[_serializer.GetSerializedSize(in packet)];
        _serializer.Serialize(in packet, buf);

        var header = CommonHeader.ReadFrom(buf);
        Assert.Equal(PacketTypes.ChatMessage, header.PacketType);
        Assert.Equal(999L, header.PacketId);
        Assert.Equal(5, header.Ttl);
        Assert.Equal(PacketFlags.Compressed, header.Flags);
    }

    [Fact]
    public void Payload_length_matches_actual_payload()
    {
        var content = Encoding.UTF8.GetBytes("short");
        var packet = new ChatMessagePacket
        {
            Header = new CommonHeader(),
            Sender = MakePeerId(),
            GroupId = MakeGroupId(),
            MessageId = Guid.NewGuid(),
            TimestampMs = 0,
            LamportClock = 0,
            ParentEventIds = [Guid.NewGuid()],
            ContentUtf8 = content,
            Signature = new byte[64],
        };

        var buf = new byte[_serializer.GetSerializedSize(in packet)];
        _serializer.Serialize(in packet, buf);

        var header = CommonHeader.ReadFrom(buf);
        // PayloadLength = total size - header size
        var expectedPayload = buf.Length - CommonHeader.Size;
        Assert.Equal((uint)expectedPayload, header.PayloadLength);
    }

    [Fact]
    public void Signature_is_last_64_bytes()
    {
        var sig = new byte[64];
        Array.Fill(sig, (byte)0xCC);

        var packet = new ChatMessagePacket
        {
            Header = new CommonHeader(),
            Sender = MakePeerId(),
            GroupId = MakeGroupId(),
            MessageId = Guid.NewGuid(),
            TimestampMs = 0,
            LamportClock = 0,
            ParentEventIds = [],
            ContentUtf8 = "x"u8.ToArray(),
            Signature = sig,
        };

        var buf = new byte[_serializer.GetSerializedSize(in packet)];
        _serializer.Serialize(in packet, buf);

        var lastBytes = buf.AsSpan(buf.Length - 64);
        Assert.True(lastBytes.SequenceEqual(sig));
    }

    [Fact]
    public void GetSignableSpan_excludes_header_and_signature()
    {
        var content = Encoding.UTF8.GetBytes("signable test");
        var packet = new ChatMessagePacket
        {
            Header = new CommonHeader { PacketId = 1 },
            Sender = MakePeerId(),
            GroupId = MakeGroupId(),
            MessageId = Guid.NewGuid(),
            TimestampMs = 12345,
            LamportClock = 1,
            ParentEventIds = [],
            ContentUtf8 = content,
            Signature = new byte[64],
        };

        var buf = new byte[_serializer.GetSerializedSize(in packet)];
        _serializer.Serialize(in packet, buf);

        var signable = ChatMessageSerializer.GetSignableSpan(buf);
        Assert.Equal(buf.Length - CommonHeader.Size - ChatMessagePacket.SignatureSize, signable.Length);
    }

    [Fact]
    public void Fixed_fields_size_is_165()
    {
        Assert.Equal(165, ChatMessagePacket.FixedFieldsSize);
    }

    [Fact]
    public void Minimum_packet_size()
    {
        // No parents, no content
        var packet = new ChatMessagePacket
        {
            Header = new CommonHeader(),
            Sender = MakePeerId(),
            GroupId = MakeGroupId(),
            MessageId = Guid.NewGuid(),
            TimestampMs = 0,
            LamportClock = 0,
            ParentEventIds = [],
            ContentUtf8 = [],
            Signature = new byte[64],
        };

        var size = _serializer.GetSerializedSize(in packet);
        Assert.Equal(CommonHeader.Size + ChatMessagePacket.FixedFieldsSize, size);
        Assert.Equal(180, size); // 15 + 165
    }

    [Fact]
    public void First_byte_is_chat_message_type()
    {
        var packet = new ChatMessagePacket
        {
            Header = new CommonHeader(),
            Sender = MakePeerId(),
            GroupId = MakeGroupId(),
            MessageId = Guid.NewGuid(),
            TimestampMs = 0,
            LamportClock = 0,
            ParentEventIds = [],
            ContentUtf8 = [],
            Signature = new byte[64],
        };

        var buf = new byte[_serializer.GetSerializedSize(in packet)];
        _serializer.Serialize(in packet, buf);
        Assert.Equal(PacketTypes.ChatMessage, buf[0]);
    }
}
