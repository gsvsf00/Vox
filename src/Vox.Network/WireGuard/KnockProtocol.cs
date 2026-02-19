using System.Net;
using System.Net.Sockets;
using System.Text;
using Vox.Core.Configuration;
using Vox.Core.Crypto;

namespace Vox.Network.WireGuard;

/// <summary>
/// Builds, encrypts, sends, and receives Knock/KnockAccept UDP packets.
///
/// Encryption scheme (per PROTOCOL.md §5.1, crypto_box semantics):
///
/// Knock wire format:
///   joiner_wg_pubkey(32) ‖ Box(knock_plaintext, bootstrap_wg_pub, joiner_wg_priv)
///   The 32-byte joiner WG pubkey prefix is in cleartext so the bootstrap can
///   perform the DH for BoxOpen. This key is ephemeral per session.
///
/// KnockAccept wire format:
///   Box(accept_plaintext, joiner_wg_pub, bootstrap_wg_priv)
///   Bootstrap already knows joiner_wg_pub from the decrypted knock.
/// </summary>
public sealed class KnockProtocol : IDisposable
{
    private readonly ICryptoService _crypto;
    private readonly byte[] _localWgPublicKey;
    private readonly byte[] _localWgPrivateKey;
    private readonly byte[] _localIdentityPublicKey;
    private readonly byte[] _localIdentityPrivateKey;

    public KnockProtocol(
        ICryptoService crypto,
        byte[] localWgPublicKey,
        byte[] localWgPrivateKey,
        byte[] localIdentityPublicKey,
        byte[] localIdentityPrivateKey)
    {
        _crypto = crypto;
        _localWgPublicKey = localWgPublicKey;
        _localWgPrivateKey = localWgPrivateKey;
        _localIdentityPublicKey = localIdentityPublicKey;
        _localIdentityPrivateKey = localIdentityPrivateKey;
    }

    /// <summary>
    /// Sends a Knock packet to a bootstrap peer and waits for a KnockAccept response.
    /// </summary>
    public async Task<KnockResult> SendKnockAsync(
        IPEndPoint bootstrapEndpoint,
        byte[] bootstrapWgPubKey,
        byte[] capsule,
        string? password,
        CancellationToken ct = default)
    {
        var passwordBytes = password != null ? Encoding.UTF8.GetBytes(password) : null;
        var timestampMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        // Build knock plaintext with placeholder signature, then sign, then rebuild
        var placeholder = KnockPacket.SerializeKnock(
            _localWgPublicKey, _localIdentityPublicKey, capsule,
            passwordBytes, timestampMs, new byte[64]);

        var signature = _crypto.Sign(
            KnockPacket.GetKnockSignableData(placeholder), _localIdentityPrivateKey);

        var knockPlaintext = KnockPacket.SerializeKnock(
            _localWgPublicKey, _localIdentityPublicKey, capsule,
            passwordBytes, timestampMs, signature);

        // Wire: joiner_wg_pub(32) ‖ Box(plaintext, bootstrap_wg_pub, joiner_wg_priv)
        var boxed = _crypto.Box(knockPlaintext, bootstrapWgPubKey, _localWgPrivateKey);
        var wire = new byte[32 + boxed.Length];
        _localWgPublicKey.CopyTo(wire, 0);
        boxed.CopyTo(wire, 32);

        using var udp = new UdpClient();
        await udp.SendAsync(wire, bootstrapEndpoint, ct);

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(VoxDefaults.KnockTimeoutMs);

        try
        {
            var response = await udp.ReceiveAsync(timeoutCts.Token);

            // KnockAccept: Box(plaintext, joiner_wg_pub, bootstrap_wg_priv)
            // We open with: BoxOpen(ciphertext, bootstrap_wg_pub, joiner_wg_priv)
            byte[] acceptPlaintext;
            try
            {
                acceptPlaintext = _crypto.BoxOpen(response.Buffer, bootstrapWgPubKey, _localWgPrivateKey);
            }
            catch
            {
                return new KnockResult(false, KnockStatus.InvalidCapsule, null, null, null);
            }

            var accept = KnockPacket.DeserializeKnockAccept(acceptPlaintext);

            if (accept.StatusCode != KnockStatus.Accepted)
                return new KnockResult(false, accept.StatusCode, null, null, null);

            var wgEndpoint = new IPEndPoint(response.RemoteEndPoint.Address, accept.WgListenPort);

            return new KnockResult(
                true, accept.StatusCode, accept.BootstrapWgPubKey, wgEndpoint, accept.Challenge);
        }
        catch (OperationCanceledException)
        {
            return new KnockResult(false, KnockStatus.RateLimited, null, null, null);
        }
    }

    /// <summary>
    /// Decrypts and validates an incoming knock packet received from a UDP socket.
    /// Wire format: joiner_wg_pub(32) ‖ Box(plaintext, bootstrap_wg_pub, joiner_wg_priv).
    /// Returns null if decryption or validation fails.
    /// </summary>
    public KnockRequest? TryDecryptKnock(byte[] wirePacket, IPEndPoint remoteEndpoint)
    {
        if (wirePacket.Length < 33) // 32-byte pubkey + at minimum some ciphertext
            return null;

        var joinerWgPub = wirePacket.AsSpan(0, 32).ToArray();
        var boxedData = wirePacket.AsSpan(32);

        // BoxOpen(ciphertext, joiner_wg_pub, bootstrap_wg_priv)
        byte[] plaintext;
        try
        {
            plaintext = _crypto.BoxOpen(boxedData, joinerWgPub, _localWgPrivateKey);
        }
        catch
        {
            return null;
        }

        try
        {
            var request = KnockPacket.DeserializeKnock(plaintext, remoteEndpoint);

            // Validate timestamp (±30s tolerance)
            var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            if (Math.Abs(now - request.TimestampMs) > VoxDefaults.TimestampToleranceMs)
                return null;

            // Verify identity signature
            var signableData = KnockPacket.GetKnockSignableData(plaintext);
            if (!_crypto.Verify(signableData, request.Signature, request.JoinerIdentityPubKey))
                return null;

            return request;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Builds an encrypted KnockAccept response packet.
    /// Wire format: Box(accept_plaintext, joiner_wg_pub, bootstrap_wg_priv)
    /// </summary>
    public byte[] BuildKnockAccept(
        byte statusCode,
        ushort wgListenPort,
        byte[] joinerWgPubKey)
    {
        var challenge = _crypto.GenerateRandomBytes(32);

        var placeholder = KnockPacket.SerializeKnockAccept(
            statusCode, _localWgPublicKey, wgListenPort, challenge, new byte[64]);

        var signature = _crypto.Sign(
            KnockPacket.GetKnockAcceptSignableData(placeholder), _localIdentityPrivateKey);

        var acceptPlaintext = KnockPacket.SerializeKnockAccept(
            statusCode, _localWgPublicKey, wgListenPort, challenge, signature);

        // Box(plaintext, joiner_wg_pub, bootstrap_wg_priv)
        return _crypto.Box(acceptPlaintext, joinerWgPubKey, _localWgPrivateKey);
    }

    public void Dispose()
    {
    }
}
