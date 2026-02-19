using System.Net;
using Microsoft.Extensions.Logging;
using Vox.Core.Crypto;

namespace Vox.Network.WireGuard;

/// <summary>
/// Orchestrates the full knock → accept → tunnel lifecycle.
/// 
/// The WireGuard tunnel itself (Noise_IKpsk2) requires a native implementation
/// (boringtun or similar). This service manages the knock protocol around it
/// and delegates actual tunnel establishment to an <see cref="ITunnelProvider"/>.
///
/// For MVP, the tunnel provider returns a stub until boringtun is integrated.
/// </summary>
public sealed class WireGuardService : IWireGuardService, IAsyncDisposable
{
    private readonly ICryptoService _crypto;
    private readonly ITunnelProvider _tunnelProvider;
    private readonly ILogger<WireGuardService>? _logger;

    // Ephemeral WG keypair for this session
    private readonly byte[] _wgPublicKey;
    private readonly byte[] _wgPrivateKey;

    // Identity keys (long-lived)
    private readonly byte[] _identityPublicKey;
    private readonly byte[] _identityPrivateKey;

    private KnockProtocol? _knockProtocol;
    private KnockListener? _listener;

    public WireGuardService(
        ICryptoService crypto,
        ITunnelProvider tunnelProvider,
        byte[] identityPublicKey,
        byte[] identityPrivateKey,
        ILogger<WireGuardService>? logger = null)
    {
        _crypto = crypto;
        _tunnelProvider = tunnelProvider;
        _identityPublicKey = identityPublicKey;
        _identityPrivateKey = identityPrivateKey;
        _logger = logger;

        // Generate ephemeral WireGuard keypair per session
        (_wgPublicKey, _wgPrivateKey) = crypto.GenerateX25519Keypair();
    }

    /// <summary>
    /// The ephemeral WireGuard public key for this session.
    /// This is included in invite URLs so joiners can encrypt their knock.
    /// </summary>
    public byte[] WireGuardPublicKey => _wgPublicKey;

    private KnockProtocol GetOrCreateKnockProtocol()
    {
        return _knockProtocol ??= new KnockProtocol(
            _crypto, _wgPublicKey, _wgPrivateKey,
            _identityPublicKey, _identityPrivateKey);
    }

    public async Task<KnockResult> SendKnockAsync(
        IPEndPoint endpoint,
        byte[] bootstrapWgPubKey,
        byte[] capsule,
        string? password,
        CancellationToken ct = default)
    {
        var protocol = GetOrCreateKnockProtocol();

        _logger?.LogInformation("Sending knock to {Endpoint}", endpoint);

        var result = await protocol.SendKnockAsync(endpoint, bootstrapWgPubKey, capsule, password, ct);

        if (result.Accepted)
            _logger?.LogInformation("Knock accepted by {Endpoint}, WG port {Port}",
                endpoint, result.WgEndpoint?.Port);
        else
            _logger?.LogWarning("Knock rejected by {Endpoint}, status={Status}",
                endpoint, result.StatusCode);

        return result;
    }

    public void ListenForKnocks(int port, Func<KnockRequest, Task<KnockResponse>> handler)
    {
        if (_listener is not null)
            throw new InvalidOperationException("Already listening for knocks.");

        var protocol = GetOrCreateKnockProtocol();

        _listener = new KnockListener(protocol,
            _logger is ILogger<KnockListener> typedLogger ? typedLogger : null);
        _listener.Start(port, handler);

        _logger?.LogInformation("Listening for knocks on port {Port}", port);
    }

    public async Task<WireGuardTunnel> EstablishTunnelAsync(
        byte[] peerWgPubKey,
        IPEndPoint peerEndpoint,
        byte[] psk,
        CancellationToken ct = default)
    {
        _logger?.LogInformation("Establishing WireGuard tunnel to {Endpoint}", peerEndpoint);

        var tunnel = await _tunnelProvider.CreateTunnelAsync(
            _wgPublicKey, _wgPrivateKey, peerWgPubKey, peerEndpoint, psk, ct);

        _logger?.LogInformation("WireGuard tunnel established to {Endpoint}", peerEndpoint);

        return tunnel;
    }

    public void StopListening()
    {
        if (_listener is not null)
        {
            _ = _listener.DisposeAsync();
            _listener = null;
            _logger?.LogInformation("Stopped listening for knocks");
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_listener is not null)
            await _listener.DisposeAsync();

        _knockProtocol?.Dispose();
    }
}

/// <summary>
/// Abstraction for creating WireGuard tunnels. Implementations provide
/// the actual Noise_IKpsk2 handshake (e.g. via boringtun FFI).
/// </summary>
public interface ITunnelProvider
{
    Task<WireGuardTunnel> CreateTunnelAsync(
        byte[] localWgPublicKey,
        byte[] localWgPrivateKey,
        byte[] peerWgPublicKey,
        IPEndPoint peerEndpoint,
        byte[] psk,
        CancellationToken ct = default);
}

/// <summary>
/// Stub tunnel provider for MVP development before boringtun integration.
/// Creates an in-memory duplex stream pair for testing.
/// </summary>
public sealed class StubTunnelProvider : ITunnelProvider
{
    public Task<WireGuardTunnel> CreateTunnelAsync(
        byte[] localWgPublicKey,
        byte[] localWgPrivateKey,
        byte[] peerWgPublicKey,
        IPEndPoint peerEndpoint,
        byte[] psk,
        CancellationToken ct = default)
    {
        var (read, write) = DuplexStream.CreatePair();

        var tunnel = new WireGuardTunnel
        {
            RemoteWgPubKey = peerWgPublicKey,
            RemoteEndpoint = peerEndpoint,
            ReadStream = read,
            WriteStream = write,
        };

        return Task.FromResult(tunnel);
    }
}

/// <summary>
/// In-memory bidirectional stream for testing tunnel communication.
/// </summary>
internal static class DuplexStream
{
    public static (Stream readSide, Stream writeSide) CreatePair()
    {
        var pipe = new System.IO.Pipelines.Pipe();
        return (pipe.Reader.AsStream(), pipe.Writer.AsStream());
    }
}
