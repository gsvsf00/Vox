using System.Buffers.Binary;

namespace Vox.Core.Protocol;

/// <summary>
/// 15-byte common header for all DataChannel packets (except VoiceFrame).
/// Binary, little-endian per PROTOCOL.md §7.
/// </summary>
public struct CommonHeader
{
    public const int Size = 15;

    public byte PacketType;
    public uint PayloadLength;
    public long PacketId;
    public byte Ttl;
    public PacketFlags Flags;

    public void WriteTo(Span<byte> buffer)
    {
        buffer[0] = PacketType;
        BinaryPrimitives.WriteUInt32LittleEndian(buffer[1..], PayloadLength);
        BinaryPrimitives.WriteInt64LittleEndian(buffer[5..], PacketId);
        buffer[13] = Ttl;
        buffer[14] = (byte)Flags;
    }

    public static CommonHeader ReadFrom(ReadOnlySpan<byte> buffer)
    {
        return new CommonHeader
        {
            PacketType = buffer[0],
            PayloadLength = BinaryPrimitives.ReadUInt32LittleEndian(buffer[1..]),
            PacketId = BinaryPrimitives.ReadInt64LittleEndian(buffer[5..]),
            Ttl = buffer[13],
            Flags = (PacketFlags)buffer[14],
        };
    }
}

[Flags]
public enum PacketFlags : byte
{
    None = 0,
    Compressed = 1 << 0,
    Fragmented = 1 << 1,
    RequiresAck = 1 << 2,
}
