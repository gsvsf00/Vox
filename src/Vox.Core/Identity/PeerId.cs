using System.Buffers.Binary;

namespace Vox.Core.Identity;

/// <summary>
/// Uniquely identifies a peer. Wraps an Ed25519 public key (32 bytes).
/// </summary>
public readonly struct PeerId : IEquatable<PeerId>
{
    public const int Size = 32;

    private readonly byte[] _publicKey;

    public ReadOnlySpan<byte> PublicKey => _publicKey ?? ReadOnlySpan<byte>.Empty;

    public PeerId(byte[] publicKey)
    {
        if (publicKey is not { Length: Size })
            throw new ArgumentException($"Public key must be {Size} bytes.", nameof(publicKey));
        _publicKey = publicKey;
    }

    public PeerId(ReadOnlySpan<byte> publicKey)
    {
        if (publicKey.Length != Size)
            throw new ArgumentException($"Public key must be {Size} bytes.", nameof(publicKey));
        _publicKey = publicKey.ToArray();
    }

    public string ToHex() => Convert.ToHexString(_publicKey ?? []);

    public bool Equals(PeerId other) =>
        _publicKey is not null && other._publicKey is not null &&
        _publicKey.AsSpan().SequenceEqual(other._publicKey);

    public override bool Equals(object? obj) => obj is PeerId other && Equals(other);

    public override int GetHashCode() =>
        _publicKey is { Length: >= 4 }
            ? BinaryPrimitives.ReadInt32LittleEndian(_publicKey)
            : 0;

    public override string ToString() => ToHex();

    public static bool operator ==(PeerId left, PeerId right) => left.Equals(right);
    public static bool operator !=(PeerId left, PeerId right) => !left.Equals(right);
}
