using System.Net;

namespace Vox.Network.WireGuard;

/// <summary>
/// Manages WireGuard-compatible handshake and tunnel lifecycle.
/// Backed by boringtun (P/Invoke) or managed Noise fallback.
/// </summary>
public interface IWireGuardService
{
    /// <summary>Send a knock to a bootstrap peer and wait for KnockAccept/rejection.</summary>
    Task<KnockResult> SendKnockAsync(
        IPEndPoint endpoint,
        byte[] bootstrapWgPubKey,
        byte[] capsule,
        string? password,
        CancellationToken ct = default);

    /// <summary>Start listening for incoming knock packets on the specified port.</summary>
    void ListenForKnocks(int port, Func<KnockRequest, Task<KnockResponse>> handler);

    /// <summary>
    /// Establish a WireGuard tunnel with a peer whose WG public key is known.
    /// The PSK is the group symmetric key.
    /// </summary>
    Task<WireGuardTunnel> EstablishTunnelAsync(
        byte[] peerWgPubKey,
        IPEndPoint peerEndpoint,
        byte[] psk,
        CancellationToken ct = default);

    void StopListening();
}

public sealed record KnockResult(
    bool Accepted,
    byte StatusCode,
    byte[]? BootstrapWgPubKey,
    IPEndPoint? WgEndpoint,
    byte[]? Challenge);

public sealed record KnockRequest(
    byte[] JoinerWgPubKey,
    byte[] JoinerIdentityPubKey,
    byte[] Capsule,
    string? Password,
    long TimestampMs,
    byte[] Signature,
    IPEndPoint RemoteEndpoint);

public sealed record KnockResponse(bool Accepted, byte StatusCode);

/// <summary>
/// Represents a live WireGuard tunnel.
/// Read/Write streams provide the encrypted channel.
/// </summary>
public sealed class WireGuardTunnel : IAsyncDisposable
{
    public required byte[] RemoteWgPubKey { get; init; }
    public required IPEndPoint RemoteEndpoint { get; init; }
    public required Stream ReadStream { get; init; }
    public required Stream WriteStream { get; init; }

    public ValueTask DisposeAsync()
    {
        ReadStream.Dispose();
        WriteStream.Dispose();
        return ValueTask.CompletedTask;
    }
}
