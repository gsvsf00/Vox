using System.Buffers.Binary;
using System.Text;

namespace Vox.Network.WireGuard;

/// <summary>
/// Binary serializer for Knock (VOX\x01) and KnockAccept (VOX\x02) UDP packets.
/// All fields are little-endian. See PROTOCOL.md §5.1 and §5.2.
///
/// Knock (plaintext before crypto_box encryption):
///   magic(4) + version(1) + joiner_wg_pub(32) + joiner_id_pub(32) +
///   capsule_len(2) + capsule(var) + password_len(1) + password(var) +
///   timestamp_ms(8) + identity_signature(64)
///
/// KnockAccept (plaintext before crypto_box encryption):
///   magic(4) + status(1) + bootstrap_wg_pub(32) + wg_listen_port(2) +
///   challenge(32) + bootstrap_identity_signature(64)
/// </summary>
public static class KnockPacket
{
    public const int KnockFixedSize = 4 + 1 + 32 + 32 + 2 + 1 + 8 + 64; // 144 bytes (without capsule & password)
    public const int KnockAcceptSize = 4 + 1 + 32 + 2 + 32 + 64; // 135 bytes

    /// <summary>
    /// Serializes a knock packet (plaintext, before encryption).
    /// Returns the byte array to be encrypted via crypto_box.
    /// </summary>
    public static byte[] SerializeKnock(
        byte[] joinerWgPubKey,
        byte[] joinerIdentityPubKey,
        byte[] capsule,
        byte[]? password,
        long timestampMs,
        byte[] identitySignature)
    {
        var passwordBytes = password ?? Array.Empty<byte>();
        var totalSize = KnockFixedSize + capsule.Length + passwordBytes.Length;
        var buffer = new byte[totalSize];
        var span = buffer.AsSpan();
        int offset = 0;

        // magic: VOX\x01
        BinaryPrimitives.WriteUInt32LittleEndian(span[offset..], Core.Configuration.VoxDefaults.KnockMagic);
        offset += 4;

        // version
        span[offset++] = Core.Configuration.VoxDefaults.ProtocolVersion;

        // joiner WG public key (32)
        joinerWgPubKey.CopyTo(span[offset..]);
        offset += 32;

        // joiner identity public key (32)
        joinerIdentityPubKey.CopyTo(span[offset..]);
        offset += 32;

        // capsule length + capsule
        BinaryPrimitives.WriteUInt16LittleEndian(span[offset..], (ushort)capsule.Length);
        offset += 2;
        capsule.CopyTo(span[offset..]);
        offset += capsule.Length;

        // password length + password
        span[offset++] = (byte)passwordBytes.Length;
        passwordBytes.CopyTo(span[offset..]);
        offset += passwordBytes.Length;

        // timestamp
        BinaryPrimitives.WriteInt64LittleEndian(span[offset..], timestampMs);
        offset += 8;

        // identity signature (64)
        identitySignature.CopyTo(span[offset..]);

        return buffer;
    }

    /// <summary>
    /// Returns the signable portion of a knock packet (everything before the 64-byte signature).
    /// </summary>
    public static ReadOnlySpan<byte> GetKnockSignableData(ReadOnlySpan<byte> knockPlaintext)
    {
        return knockPlaintext[..^64];
    }

    /// <summary>
    /// Deserializes a knock packet from decrypted plaintext.
    /// </summary>
    public static KnockRequest DeserializeKnock(ReadOnlySpan<byte> plaintext, System.Net.IPEndPoint remoteEndpoint)
    {
        int offset = 0;

        var magic = BinaryPrimitives.ReadUInt32LittleEndian(plaintext[offset..]);
        if (magic != Core.Configuration.VoxDefaults.KnockMagic)
            throw new InvalidDataException($"Invalid knock magic: 0x{magic:X8}");
        offset += 4;

        var version = plaintext[offset++];
        if (version != Core.Configuration.VoxDefaults.ProtocolVersion)
            throw new InvalidDataException($"Unsupported protocol version: {version}");

        var joinerWgPub = plaintext.Slice(offset, 32).ToArray();
        offset += 32;

        var joinerIdPub = plaintext.Slice(offset, 32).ToArray();
        offset += 32;

        var capsuleLen = BinaryPrimitives.ReadUInt16LittleEndian(plaintext[offset..]);
        offset += 2;
        var capsule = plaintext.Slice(offset, capsuleLen).ToArray();
        offset += capsuleLen;

        var passwordLen = plaintext[offset++];
        string? password = null;
        if (passwordLen > 0)
        {
            password = Encoding.UTF8.GetString(plaintext.Slice(offset, passwordLen));
            offset += passwordLen;
        }

        var timestampMs = BinaryPrimitives.ReadInt64LittleEndian(plaintext[offset..]);
        offset += 8;

        var signature = plaintext.Slice(offset, 64).ToArray();

        return new KnockRequest(joinerWgPub, joinerIdPub, capsule, password, timestampMs, signature, remoteEndpoint);
    }

    /// <summary>
    /// Serializes a KnockAccept packet (plaintext, before encryption).
    /// </summary>
    public static byte[] SerializeKnockAccept(
        byte statusCode,
        byte[] bootstrapWgPubKey,
        ushort wgListenPort,
        byte[] challenge,
        byte[] bootstrapIdentitySignature)
    {
        var buffer = new byte[KnockAcceptSize];
        var span = buffer.AsSpan();
        int offset = 0;

        // magic: VOX\x02
        BinaryPrimitives.WriteUInt32LittleEndian(span[offset..], Core.Configuration.VoxDefaults.KnockAcceptMagic);
        offset += 4;

        // status
        span[offset++] = statusCode;

        // bootstrap WG public key (32)
        bootstrapWgPubKey.CopyTo(span[offset..]);
        offset += 32;

        // WG listen port
        BinaryPrimitives.WriteUInt16LittleEndian(span[offset..], wgListenPort);
        offset += 2;

        // challenge (32)
        challenge.CopyTo(span[offset..]);
        offset += 32;

        // bootstrap identity signature (64)
        bootstrapIdentitySignature.CopyTo(span[offset..]);

        return buffer;
    }

    /// <summary>
    /// Returns the signable portion of a KnockAccept packet (everything before the 64-byte signature).
    /// </summary>
    public static ReadOnlySpan<byte> GetKnockAcceptSignableData(ReadOnlySpan<byte> knockAcceptPlaintext)
    {
        return knockAcceptPlaintext[..^64];
    }

    /// <summary>
    /// Deserializes a KnockAccept packet from decrypted plaintext.
    /// </summary>
    public static KnockAcceptData DeserializeKnockAccept(ReadOnlySpan<byte> plaintext)
    {
        int offset = 0;

        var magic = BinaryPrimitives.ReadUInt32LittleEndian(plaintext[offset..]);
        if (magic != Core.Configuration.VoxDefaults.KnockAcceptMagic)
            throw new InvalidDataException($"Invalid KnockAccept magic: 0x{magic:X8}");
        offset += 4;

        var status = plaintext[offset++];

        var bootstrapWgPub = plaintext.Slice(offset, 32).ToArray();
        offset += 32;

        var wgListenPort = BinaryPrimitives.ReadUInt16LittleEndian(plaintext[offset..]);
        offset += 2;

        var challenge = plaintext.Slice(offset, 32).ToArray();
        offset += 32;

        var signature = plaintext.Slice(offset, 64).ToArray();

        return new KnockAcceptData(status, bootstrapWgPub, wgListenPort, challenge, signature);
    }
}

/// <summary>
/// Parsed KnockAccept data (before validation).
/// </summary>
public sealed record KnockAcceptData(
    byte StatusCode,
    byte[] BootstrapWgPubKey,
    ushort WgListenPort,
    byte[] Challenge,
    byte[] BootstrapIdentitySignature);

/// <summary>
/// KnockAccept status codes per PROTOCOL.md §5.2.
/// </summary>
public static class KnockStatus
{
    public const byte Accepted = 0;
    public const byte InvalidCapsule = 1;
    public const byte Expired = 2;
    public const byte PasswordWrong = 3;
    public const byte GroupFull = 4;
    public const byte RateLimited = 5;
}
