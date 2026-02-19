using System.Net;
using Vox.Core.Crypto;
using Vox.Network.WireGuard;

namespace Vox.Network.Tests;

public class KnockProtocolTests
{
    private readonly ICryptoService _crypto = new LibsodiumCryptoService();

    private (byte[] PublicKey, byte[] PrivateKey, byte[] IdPublicKey, byte[] IdPrivateKey) GenerateKeys()
    {
        var (wgPub, wgPriv) = _crypto.GenerateX25519Keypair();
        var (idPub, idPriv) = _crypto.GenerateEd25519Keypair();
        return (wgPub, wgPriv, idPub, idPriv);
    }

    [Fact]
    public void Knock_encrypt_decrypt_roundtrip()
    {
        var joiner = GenerateKeys();
        var bootstrap = GenerateKeys();

        var joinerProto = new KnockProtocol(_crypto,
            joiner.PublicKey, joiner.PrivateKey,
            joiner.IdPublicKey, joiner.IdPrivateKey);

        var bootstrapProto = new KnockProtocol(_crypto,
            bootstrap.PublicKey, bootstrap.PrivateKey,
            bootstrap.IdPublicKey, bootstrap.IdPrivateKey);

        // Build a knock packet (mimic what SendKnockAsync does internally)
        var capsule = _crypto.GenerateRandomBytes(80);
        var timestampMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        var placeholder = KnockPacket.SerializeKnock(
            joiner.PublicKey, joiner.IdPublicKey, capsule,
            null, timestampMs, new byte[64]);

        var signature = _crypto.Sign(
            KnockPacket.GetKnockSignableData(placeholder), joiner.IdPrivateKey);

        var knockPlaintext = KnockPacket.SerializeKnock(
            joiner.PublicKey, joiner.IdPublicKey, capsule,
            null, timestampMs, signature);

        // Encrypt: joiner_wg_pub(32) ‖ Box(plaintext, bootstrap_wg_pub, joiner_wg_priv)
        var boxed = _crypto.Box(knockPlaintext, bootstrap.PublicKey, joiner.PrivateKey);
        var wire = new byte[32 + boxed.Length];
        joiner.PublicKey.CopyTo(wire, 0);
        boxed.CopyTo(wire, 32);

        // Bootstrap side decrypts
        var endpoint = new IPEndPoint(IPAddress.Loopback, 12345);
        var request = bootstrapProto.TryDecryptKnock(wire, endpoint);

        Assert.NotNull(request);
        Assert.Equal(joiner.PublicKey, request.JoinerWgPubKey);
        Assert.Equal(joiner.IdPublicKey, request.JoinerIdentityPubKey);
        Assert.Equal(capsule, request.Capsule);
        Assert.Null(request.Password);
        Assert.Equal(timestampMs, request.TimestampMs);
    }

    [Fact]
    public void Knock_with_password_roundtrips()
    {
        var joiner = GenerateKeys();
        var bootstrap = GenerateKeys();

        var bootstrapProto = new KnockProtocol(_crypto,
            bootstrap.PublicKey, bootstrap.PrivateKey,
            bootstrap.IdPublicKey, bootstrap.IdPrivateKey);

        var capsule = _crypto.GenerateRandomBytes(30);
        var passwordBytes = System.Text.Encoding.UTF8.GetBytes("secretpass");
        var timestampMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        var placeholder = KnockPacket.SerializeKnock(
            joiner.PublicKey, joiner.IdPublicKey, capsule,
            passwordBytes, timestampMs, new byte[64]);

        var signature = _crypto.Sign(
            KnockPacket.GetKnockSignableData(placeholder), joiner.IdPrivateKey);

        var knockPlaintext = KnockPacket.SerializeKnock(
            joiner.PublicKey, joiner.IdPublicKey, capsule,
            passwordBytes, timestampMs, signature);

        var boxed = _crypto.Box(knockPlaintext, bootstrap.PublicKey, joiner.PrivateKey);
        var wire = new byte[32 + boxed.Length];
        joiner.PublicKey.CopyTo(wire, 0);
        boxed.CopyTo(wire, 32);

        var endpoint = new IPEndPoint(IPAddress.Loopback, 9876);
        var request = bootstrapProto.TryDecryptKnock(wire, endpoint);

        Assert.NotNull(request);
        Assert.Equal("secretpass", request.Password);
    }

    [Fact]
    public void TryDecryptKnock_returns_null_for_wrong_keys()
    {
        var joiner = GenerateKeys();
        var bootstrap = GenerateKeys();
        var wrongPeer = GenerateKeys();

        // Encrypt with joiner → bootstrap keys
        var capsule = _crypto.GenerateRandomBytes(20);
        var timestampMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        var placeholder = KnockPacket.SerializeKnock(
            joiner.PublicKey, joiner.IdPublicKey, capsule,
            null, timestampMs, new byte[64]);
        var signature = _crypto.Sign(
            KnockPacket.GetKnockSignableData(placeholder), joiner.IdPrivateKey);
        var knockPlaintext = KnockPacket.SerializeKnock(
            joiner.PublicKey, joiner.IdPublicKey, capsule,
            null, timestampMs, signature);

        var boxed = _crypto.Box(knockPlaintext, bootstrap.PublicKey, joiner.PrivateKey);
        var wire = new byte[32 + boxed.Length];
        joiner.PublicKey.CopyTo(wire, 0);
        boxed.CopyTo(wire, 32);

        // Try to decrypt with wrong keys
        var wrongProto = new KnockProtocol(_crypto,
            wrongPeer.PublicKey, wrongPeer.PrivateKey,
            wrongPeer.IdPublicKey, wrongPeer.IdPrivateKey);

        var endpoint = new IPEndPoint(IPAddress.Loopback, 1111);
        var result = wrongProto.TryDecryptKnock(wire, endpoint);

        Assert.Null(result);
    }

    [Fact]
    public void TryDecryptKnock_returns_null_for_corrupted_data()
    {
        var bootstrap = GenerateKeys();
        var bootstrapProto = new KnockProtocol(_crypto,
            bootstrap.PublicKey, bootstrap.PrivateKey,
            bootstrap.IdPublicKey, bootstrap.IdPrivateKey);

        var garbage = _crypto.GenerateRandomBytes(200);
        var endpoint = new IPEndPoint(IPAddress.Loopback, 1111);

        var result = bootstrapProto.TryDecryptKnock(garbage, endpoint);
        Assert.Null(result);
    }

    [Fact]
    public void TryDecryptKnock_returns_null_for_too_short_packet()
    {
        var bootstrap = GenerateKeys();
        var bootstrapProto = new KnockProtocol(_crypto,
            bootstrap.PublicKey, bootstrap.PrivateKey,
            bootstrap.IdPublicKey, bootstrap.IdPrivateKey);

        var tooShort = new byte[10];
        var endpoint = new IPEndPoint(IPAddress.Loopback, 1111);

        var result = bootstrapProto.TryDecryptKnock(tooShort, endpoint);
        Assert.Null(result);
    }

    [Fact]
    public void TryDecryptKnock_rejects_expired_timestamp()
    {
        var joiner = GenerateKeys();
        var bootstrap = GenerateKeys();

        var bootstrapProto = new KnockProtocol(_crypto,
            bootstrap.PublicKey, bootstrap.PrivateKey,
            bootstrap.IdPublicKey, bootstrap.IdPrivateKey);

        var capsule = _crypto.GenerateRandomBytes(20);
        // Set timestamp 60 seconds in the past (tolerance is 30s)
        var timestampMs = DateTimeOffset.UtcNow.AddSeconds(-60).ToUnixTimeMilliseconds();

        var placeholder = KnockPacket.SerializeKnock(
            joiner.PublicKey, joiner.IdPublicKey, capsule,
            null, timestampMs, new byte[64]);
        var signature = _crypto.Sign(
            KnockPacket.GetKnockSignableData(placeholder), joiner.IdPrivateKey);
        var knockPlaintext = KnockPacket.SerializeKnock(
            joiner.PublicKey, joiner.IdPublicKey, capsule,
            null, timestampMs, signature);

        var boxed = _crypto.Box(knockPlaintext, bootstrap.PublicKey, joiner.PrivateKey);
        var wire = new byte[32 + boxed.Length];
        joiner.PublicKey.CopyTo(wire, 0);
        boxed.CopyTo(wire, 32);

        var endpoint = new IPEndPoint(IPAddress.Loopback, 1111);
        var result = bootstrapProto.TryDecryptKnock(wire, endpoint);

        Assert.Null(result);
    }

    [Fact]
    public void TryDecryptKnock_rejects_forged_signature()
    {
        var joiner = GenerateKeys();
        var bootstrap = GenerateKeys();
        var impersonator = GenerateKeys();

        var bootstrapProto = new KnockProtocol(_crypto,
            bootstrap.PublicKey, bootstrap.PrivateKey,
            bootstrap.IdPublicKey, bootstrap.IdPrivateKey);

        var capsule = _crypto.GenerateRandomBytes(20);
        var timestampMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        // Sign with impersonator's key but claim to be joiner
        var placeholder = KnockPacket.SerializeKnock(
            joiner.PublicKey, joiner.IdPublicKey, capsule,
            null, timestampMs, new byte[64]);
        var forgedSignature = _crypto.Sign(
            KnockPacket.GetKnockSignableData(placeholder), impersonator.IdPrivateKey);
        var knockPlaintext = KnockPacket.SerializeKnock(
            joiner.PublicKey, joiner.IdPublicKey, capsule,
            null, timestampMs, forgedSignature);

        var boxed = _crypto.Box(knockPlaintext, bootstrap.PublicKey, joiner.PrivateKey);
        var wire = new byte[32 + boxed.Length];
        joiner.PublicKey.CopyTo(wire, 0);
        boxed.CopyTo(wire, 32);

        var endpoint = new IPEndPoint(IPAddress.Loopback, 1111);
        var result = bootstrapProto.TryDecryptKnock(wire, endpoint);

        Assert.Null(result);
    }

    // --- KnockAccept tests ---

    [Fact]
    public void BuildKnockAccept_produces_decryptable_response()
    {
        var joiner = GenerateKeys();
        var bootstrap = GenerateKeys();

        var bootstrapProto = new KnockProtocol(_crypto,
            bootstrap.PublicKey, bootstrap.PrivateKey,
            bootstrap.IdPublicKey, bootstrap.IdPrivateKey);

        var acceptWire = bootstrapProto.BuildKnockAccept(
            KnockStatus.Accepted, 51820, joiner.PublicKey);

        // Joiner side decrypts: BoxOpen(ciphertext, bootstrap_wg_pub, joiner_wg_priv)
        var acceptPlaintext = _crypto.BoxOpen(acceptWire, bootstrap.PublicKey, joiner.PrivateKey);
        var accept = KnockPacket.DeserializeKnockAccept(acceptPlaintext);

        Assert.Equal(KnockStatus.Accepted, accept.StatusCode);
        Assert.Equal(bootstrap.PublicKey, accept.BootstrapWgPubKey);
        Assert.Equal((ushort)51820, accept.WgListenPort);
        Assert.Equal(32, accept.Challenge.Length);
    }

    [Fact]
    public void BuildKnockAccept_signature_verifies()
    {
        var joiner = GenerateKeys();
        var bootstrap = GenerateKeys();

        var bootstrapProto = new KnockProtocol(_crypto,
            bootstrap.PublicKey, bootstrap.PrivateKey,
            bootstrap.IdPublicKey, bootstrap.IdPrivateKey);

        var acceptWire = bootstrapProto.BuildKnockAccept(
            KnockStatus.Accepted, 51820, joiner.PublicKey);

        var acceptPlaintext = _crypto.BoxOpen(acceptWire, bootstrap.PublicKey, joiner.PrivateKey);
        var accept = KnockPacket.DeserializeKnockAccept(acceptPlaintext);

        var signableData = KnockPacket.GetKnockAcceptSignableData(acceptPlaintext);
        var verified = _crypto.Verify(signableData, accept.BootstrapIdentitySignature, bootstrap.IdPublicKey);

        Assert.True(verified);
    }

    [Fact]
    public void BuildKnockAccept_rejection_status_roundtrips()
    {
        var joiner = GenerateKeys();
        var bootstrap = GenerateKeys();

        var bootstrapProto = new KnockProtocol(_crypto,
            bootstrap.PublicKey, bootstrap.PrivateKey,
            bootstrap.IdPublicKey, bootstrap.IdPrivateKey);

        var acceptWire = bootstrapProto.BuildKnockAccept(
            KnockStatus.GroupFull, 51820, joiner.PublicKey);

        var acceptPlaintext = _crypto.BoxOpen(acceptWire, bootstrap.PublicKey, joiner.PrivateKey);
        var accept = KnockPacket.DeserializeKnockAccept(acceptPlaintext);

        Assert.Equal(KnockStatus.GroupFull, accept.StatusCode);
    }

    [Fact]
    public void BuildKnockAccept_generates_unique_challenges()
    {
        var joiner = GenerateKeys();
        var bootstrap = GenerateKeys();

        var bootstrapProto = new KnockProtocol(_crypto,
            bootstrap.PublicKey, bootstrap.PrivateKey,
            bootstrap.IdPublicKey, bootstrap.IdPrivateKey);

        var wire1 = bootstrapProto.BuildKnockAccept(KnockStatus.Accepted, 51820, joiner.PublicKey);
        var wire2 = bootstrapProto.BuildKnockAccept(KnockStatus.Accepted, 51820, joiner.PublicKey);

        var pt1 = _crypto.BoxOpen(wire1, bootstrap.PublicKey, joiner.PrivateKey);
        var pt2 = _crypto.BoxOpen(wire2, bootstrap.PublicKey, joiner.PrivateKey);

        var accept1 = KnockPacket.DeserializeKnockAccept(pt1);
        var accept2 = KnockPacket.DeserializeKnockAccept(pt2);

        // Challenges should be different (random 32 bytes)
        Assert.False(accept1.Challenge.AsSpan().SequenceEqual(accept2.Challenge));
    }
}
