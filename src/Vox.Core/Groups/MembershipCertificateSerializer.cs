using System.Buffers.Binary;
using Vox.Core.Identity;

namespace Vox.Core.Groups;

/// <summary>
/// Binary serializer for <see cref="MembershipCertificate"/>.
/// Layout (all little-endian):
///   group_id(32) + admitted_peer_id(32) + admitted_by_peer_id(32) + admitted_at_ms(8) + signature(64)
/// Total: 168 bytes fixed.
/// </summary>
public static class MembershipCertificateSerializer
{
    public const int FixedSize = GroupId.Size + PeerId.Size + PeerId.Size + 8 + 64;
    public const int SignatureSize = 64;

    public static byte[] Serialize(MembershipCertificate cert)
    {
        var buffer = new byte[FixedSize];
        var span = buffer.AsSpan();
        int offset = 0;

        cert.GroupId.Bytes.CopyTo(span[offset..]);
        offset += GroupId.Size;

        cert.AdmittedPeerId.PublicKey.CopyTo(span[offset..]);
        offset += PeerId.Size;

        cert.AdmittedByPeerId.PublicKey.CopyTo(span[offset..]);
        offset += PeerId.Size;

        BinaryPrimitives.WriteInt64LittleEndian(span[offset..], cert.AdmittedAt.ToUnixTimeMilliseconds());
        offset += 8;

        cert.Signature.CopyTo(span[offset..]);

        return buffer;
    }

    /// <summary>
    /// Returns bytes before the signature for signing/verification.
    /// </summary>
    public static ReadOnlySpan<byte> GetSignableSpan(ReadOnlySpan<byte> serialized)
    {
        return serialized[..^SignatureSize];
    }

    public static MembershipCertificate Deserialize(ReadOnlySpan<byte> data)
    {
        if (data.Length < FixedSize)
            throw new InvalidDataException(
                $"MembershipCertificate data too short: {data.Length} < {FixedSize}");

        int offset = 0;

        var groupId = new GroupId(data.Slice(offset, GroupId.Size));
        offset += GroupId.Size;

        var admittedPeerId = new PeerId(data.Slice(offset, PeerId.Size));
        offset += PeerId.Size;

        var admittedByPeerId = new PeerId(data.Slice(offset, PeerId.Size));
        offset += PeerId.Size;

        var admittedAtMs = BinaryPrimitives.ReadInt64LittleEndian(data[offset..]);
        offset += 8;

        var signature = data.Slice(offset, SignatureSize).ToArray();

        return new MembershipCertificate
        {
            GroupId = groupId,
            AdmittedPeerId = admittedPeerId,
            AdmittedByPeerId = admittedByPeerId,
            AdmittedAt = DateTimeOffset.FromUnixTimeMilliseconds(admittedAtMs),
            Signature = signature,
        };
    }
}
