using System.Buffers.Binary;

namespace Vox.Core.Groups;

/// <summary>
/// 32-byte group identifier.
/// </summary>
public readonly struct GroupId : IEquatable<GroupId>
{
    public const int Size = 32;

    private readonly byte[] _id;

    public ReadOnlySpan<byte> Bytes => _id ?? ReadOnlySpan<byte>.Empty;

    public GroupId(byte[] id)
    {
        if (id is not { Length: Size })
            throw new ArgumentException($"GroupId must be {Size} bytes.", nameof(id));
        _id = id;
    }

    public GroupId(ReadOnlySpan<byte> id)
    {
        if (id.Length != Size)
            throw new ArgumentException($"GroupId must be {Size} bytes.", nameof(id));
        _id = id.ToArray();
    }

    public string ToHex() => Convert.ToHexString(_id ?? []);

    public bool Equals(GroupId other) =>
        _id is not null && other._id is not null &&
        _id.AsSpan().SequenceEqual(other._id);

    public override bool Equals(object? obj) => obj is GroupId other && Equals(other);

    public override int GetHashCode() =>
        _id is { Length: >= 4 }
            ? BinaryPrimitives.ReadInt32LittleEndian(_id)
            : 0;

    public override string ToString() => ToHex();

    public static bool operator ==(GroupId left, GroupId right) => left.Equals(right);
    public static bool operator !=(GroupId left, GroupId right) => !left.Equals(right);
}
