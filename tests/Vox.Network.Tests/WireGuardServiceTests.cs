using System.Net;
using Vox.Core.Crypto;
using Vox.Network.WireGuard;

namespace Vox.Network.Tests;

public class WireGuardServiceTests
{
    private readonly ICryptoService _crypto = new LibsodiumCryptoService();

    [Fact]
    public void WireGuardPublicKey_is_32_bytes()
    {
        var (idPub, idPriv) = _crypto.GenerateEd25519Keypair();
        var service = new WireGuardService(_crypto, new StubTunnelProvider(), idPub, idPriv);

        Assert.Equal(32, service.WireGuardPublicKey.Length);
    }

    [Fact]
    public void WireGuardPublicKey_is_stable_for_session()
    {
        var (idPub, idPriv) = _crypto.GenerateEd25519Keypair();
        var service = new WireGuardService(_crypto, new StubTunnelProvider(), idPub, idPriv);

        var key1 = service.WireGuardPublicKey;
        var key2 = service.WireGuardPublicKey;

        Assert.Same(key1, key2);
    }

    [Fact]
    public void Different_sessions_generate_different_WG_keys()
    {
        var (idPub, idPriv) = _crypto.GenerateEd25519Keypair();
        var service1 = new WireGuardService(_crypto, new StubTunnelProvider(), idPub, idPriv);
        var service2 = new WireGuardService(_crypto, new StubTunnelProvider(), idPub, idPriv);

        // Ephemeral keys should differ (probabilistic but vanishingly unlikely to collide)
        Assert.False(service1.WireGuardPublicKey.AsSpan().SequenceEqual(service2.WireGuardPublicKey));
    }

    [Fact]
    public async Task EstablishTunnelAsync_creates_tunnel_with_stub_provider()
    {
        var (idPub, idPriv) = _crypto.GenerateEd25519Keypair();
        var service = new WireGuardService(_crypto, new StubTunnelProvider(), idPub, idPriv);

        var peerWgPub = _crypto.GenerateRandomBytes(32);
        var endpoint = new IPEndPoint(IPAddress.Loopback, 51820);
        var psk = _crypto.GenerateRandomBytes(32);

        await using var tunnel = await service.EstablishTunnelAsync(peerWgPub, endpoint, psk);

        Assert.Equal(peerWgPub, tunnel.RemoteWgPubKey);
        Assert.Equal(endpoint, tunnel.RemoteEndpoint);
        Assert.NotNull(tunnel.ReadStream);
        Assert.NotNull(tunnel.WriteStream);
    }

    [Fact]
    public async Task StubTunnelProvider_creates_writable_streams()
    {
        var provider = new StubTunnelProvider();
        var endpoint = new IPEndPoint(IPAddress.Loopback, 51820);

        var tunnel = await provider.CreateTunnelAsync(
            new byte[32], new byte[32], new byte[32], endpoint, new byte[32]);

        // Write to the write stream should not throw
        var data = new byte[] { 1, 2, 3 };
        await tunnel.WriteStream.WriteAsync(data);
        await tunnel.WriteStream.FlushAsync();

        await tunnel.DisposeAsync();
    }

    [Fact]
    public void ListenForKnocks_throws_when_called_twice()
    {
        var (idPub, idPriv) = _crypto.GenerateEd25519Keypair();
        var service = new WireGuardService(_crypto, new StubTunnelProvider(), idPub, idPriv);

        // Use port 0 to let the OS assign
        service.ListenForKnocks(0, _ => Task.FromResult(new KnockResponse(true, KnockStatus.Accepted)));

        Assert.Throws<InvalidOperationException>(() =>
            service.ListenForKnocks(0, _ => Task.FromResult(new KnockResponse(true, KnockStatus.Accepted))));

        service.StopListening();
    }

    [Fact]
    public async Task DisposeAsync_completes_without_error()
    {
        var (idPub, idPriv) = _crypto.GenerateEd25519Keypair();
        var service = new WireGuardService(_crypto, new StubTunnelProvider(), idPub, idPriv);

        // Dispose even when nothing was started
        await service.DisposeAsync();
    }
}
