using System.Buffers.Binary;
using System.Net;
using System.Text;
using Vox.Core.Configuration;
using Vox.Core.Identity;

namespace Vox.Core.Groups;

/// <summary>
/// Binary serializer for the Admission and AdmissionAck packets sent over the WireGuard tunnel.
/// See PROTOCOL.md §5.4 and §5.5.
///
/// Admission (Bootstrap → Joiner):
///   membership_cert(168) +
///   encrypted_group_key_len(2) + encrypted_group_key(var) +
///   peer_count(1) + foreach peer { PeerInfoEntry } +
///   latest_lamport(8)
///
/// AdmissionAck (Joiner → Bootstrap):
///   ack(1) + username_len(1) + username(var) + discriminator(2) + capabilities(2) + signature(64)
/// </summary>
public static class AdmissionPacket
{
    public const int AckSignatureSize = 64;

    public static byte[] SerializeAdmission(
        MembershipCertificate cert,
        byte[] encryptedGroupKey,
        IReadOnlyList<PeerInfo> peerList,
        ulong latestLamport)
    {
        var certBytes = MembershipCertificateSerializer.Serialize(cert);
        var size = GetAdmissionSize(certBytes, encryptedGroupKey, peerList);
        var buffer = new byte[size];
        var span = buffer.AsSpan();
        int offset = 0;

        // membership_cert
        certBytes.CopyTo(span[offset..]);
        offset += certBytes.Length;

        // encrypted_group_key
        BinaryPrimitives.WriteUInt16LittleEndian(span[offset..], (ushort)encryptedGroupKey.Length);
        offset += 2;
        encryptedGroupKey.CopyTo(span[offset..]);
        offset += encryptedGroupKey.Length;

        // peer_count
        span[offset++] = (byte)peerList.Count;

        // peer entries
        foreach (var peer in peerList)
        {
            offset += WritePeerInfoEntry(span[offset..], peer);
        }

        // latest_lamport
        BinaryPrimitives.WriteUInt64LittleEndian(span[offset..], latestLamport);

        return buffer;
    }

    public static AdmissionData DeserializeAdmission(ReadOnlySpan<byte> data)
    {
        int offset = 0;

        // membership_cert (fixed 168 bytes)
        var cert = MembershipCertificateSerializer.Deserialize(data[offset..]);
        offset += MembershipCertificateSerializer.FixedSize;

        // encrypted_group_key
        var encKeyLen = BinaryPrimitives.ReadUInt16LittleEndian(data[offset..]);
        offset += 2;
        var encryptedGroupKey = data.Slice(offset, encKeyLen).ToArray();
        offset += encKeyLen;

        // peer_count
        var peerCount = data[offset++];
        var peers = new List<PeerInfo>(peerCount);

        for (int i = 0; i < peerCount; i++)
        {
            var (peer, consumed) = ReadPeerInfoEntry(data[offset..]);
            peers.Add(peer);
            offset += consumed;
        }

        // latest_lamport
        var latestLamport = BinaryPrimitives.ReadUInt64LittleEndian(data[offset..]);

        return new AdmissionData(cert, encryptedGroupKey, peers, latestLamport);
    }

    public static byte[] SerializeAdmissionAck(
        string username,
        ushort discriminator,
        PeerCapabilities capabilities,
        byte[] signature)
    {
        var usernameBytes = Encoding.UTF8.GetBytes(username);
        if (usernameBytes.Length > VoxDefaults.MaxUsernameBytes)
            throw new ArgumentException($"Username exceeds {VoxDefaults.MaxUsernameBytes} byte limit when UTF-8 encoded ({usernameBytes.Length} bytes).", nameof(username));
        var size = 1 + 1 + usernameBytes.Length + 2 + 2 + AckSignatureSize;
        var buffer = new byte[size];
        var span = buffer.AsSpan();
        int offset = 0;

        span[offset++] = 0x01; // ack byte
        span[offset++] = (byte)usernameBytes.Length;
        usernameBytes.CopyTo(span[offset..]);
        offset += usernameBytes.Length;

        BinaryPrimitives.WriteUInt16LittleEndian(span[offset..], discriminator);
        offset += 2;

        BinaryPrimitives.WriteUInt16LittleEndian(span[offset..], (ushort)capabilities);
        offset += 2;

        signature.CopyTo(span[offset..]);

        return buffer;
    }

    /// <summary>
    /// Returns the signable portion of an AdmissionAck (everything before the 64-byte signature).
    /// </summary>
    public static ReadOnlySpan<byte> GetAckSignableSpan(ReadOnlySpan<byte> ackData)
    {
        return ackData[..^AckSignatureSize];
    }

    public static AdmissionAckData DeserializeAdmissionAck(ReadOnlySpan<byte> data)
    {
        int offset = 0;

        var ack = data[offset++];
        var usernameLen = data[offset++];
        var username = Encoding.UTF8.GetString(data.Slice(offset, usernameLen));
        offset += usernameLen;

        var discriminator = BinaryPrimitives.ReadUInt16LittleEndian(data[offset..]);
        offset += 2;

        var capabilities = (PeerCapabilities)BinaryPrimitives.ReadUInt16LittleEndian(data[offset..]);
        offset += 2;

        var signature = data.Slice(offset, AckSignatureSize).ToArray();

        return new AdmissionAckData(ack, username, discriminator, capabilities, signature);
    }

    private static int WritePeerInfoEntry(Span<byte> span, PeerInfo peer)
    {
        int offset = 0;

        // identity (32)
        peer.Id.PublicKey.CopyTo(span[offset..]);
        offset += PeerId.Size;

        // username_len(1) + username
        var usernameBytes = Encoding.UTF8.GetBytes(peer.Username);
        if (usernameBytes.Length > VoxDefaults.MaxUsernameBytes)
            throw new ArgumentException($"Peer username exceeds {VoxDefaults.MaxUsernameBytes} byte limit when UTF-8 encoded ({usernameBytes.Length} bytes).");
        span[offset++] = (byte)usernameBytes.Length;
        usernameBytes.CopyTo(span[offset..]);
        offset += usernameBytes.Length;

        // discriminator (2)
        BinaryPrimitives.WriteUInt16LittleEndian(span[offset..], peer.Discriminator);
        offset += 2;

        // wg_pubkey (32)
        peer.WireGuardPublicKey.CopyTo(span[offset..]);
        offset += 32;

        // endpoint_count (1)
        span[offset++] = (byte)peer.Endpoints.Count;
        foreach (var ep in peer.Endpoints)
        {
            var ipBytes = ep.Address.GetAddressBytes();
            span[offset++] = (byte)ipBytes.Length;
            ipBytes.CopyTo(span[offset..]);
            offset += ipBytes.Length;
            BinaryPrimitives.WriteUInt16LittleEndian(span[offset..], (ushort)ep.Port);
            offset += 2;
        }

        // status (1)
        span[offset++] = (byte)peer.Status;

        // capabilities (2)
        BinaryPrimitives.WriteUInt16LittleEndian(span[offset..], (ushort)peer.Capabilities);
        offset += 2;

        return offset;
    }

    private static (PeerInfo Peer, int Consumed) ReadPeerInfoEntry(ReadOnlySpan<byte> data)
    {
        int offset = 0;

        var id = new PeerId(data.Slice(offset, PeerId.Size));
        offset += PeerId.Size;

        var usernameLen = data[offset++];
        var username = Encoding.UTF8.GetString(data.Slice(offset, usernameLen));
        offset += usernameLen;

        var discriminator = BinaryPrimitives.ReadUInt16LittleEndian(data[offset..]);
        offset += 2;

        var wgPub = data.Slice(offset, 32).ToArray();
        offset += 32;

        var epCount = data[offset++];
        var endpoints = new List<IPEndPoint>(epCount);
        for (int i = 0; i < epCount; i++)
        {
            var ipLen = data[offset++];
            var ip = new IPAddress(data.Slice(offset, ipLen));
            offset += ipLen;
            var port = BinaryPrimitives.ReadUInt16LittleEndian(data[offset..]);
            offset += 2;
            endpoints.Add(new IPEndPoint(ip, port));
        }

        var status = (PeerStatus)data[offset++];
        var capabilities = (PeerCapabilities)BinaryPrimitives.ReadUInt16LittleEndian(data[offset..]);
        offset += 2;

        var peer = new PeerInfo(id, username, discriminator, wgPub, endpoints, status, capabilities);
        return (peer, offset);
    }

    private static int GetAdmissionSize(
        byte[] certBytes,
        byte[] encryptedGroupKey,
        IReadOnlyList<PeerInfo> peerList)
    {
        int size = certBytes.Length + 2 + encryptedGroupKey.Length + 1;

        foreach (var peer in peerList)
        {
            size += PeerId.Size; // identity
            size += 1 + Encoding.UTF8.GetByteCount(peer.Username); // username
            size += 2; // discriminator
            size += 32; // wg_pubkey
            size += 1; // endpoint_count
            foreach (var ep in peer.Endpoints)
                size += 1 + ep.Address.GetAddressBytes().Length + 2;
            size += 1; // status
            size += 2; // capabilities
        }

        size += 8; // latest_lamport
        return size;
    }
}

public sealed record AdmissionData(
    MembershipCertificate Certificate,
    byte[] EncryptedGroupKey,
    IReadOnlyList<PeerInfo> PeerList,
    ulong LatestLamport);

public sealed record AdmissionAckData(
    byte Ack,
    string Username,
    ushort Discriminator,
    PeerCapabilities Capabilities,
    byte[] Signature);
