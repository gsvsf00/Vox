using Vox.Core.Identity;

namespace Vox.Network.Transport;

/// <summary>
/// Abstraction over WebRTC DataChannel transport.
/// Chat, Voice, Routing, Presence all send through this.
/// </summary>
public interface ITransportService
{
    Task<bool> ConnectToPeerAsync(PeerInfo peer, CancellationToken ct = default);
    Task DisconnectFromPeerAsync(PeerId peerId);
    Task SendAsync(PeerId destination, byte[] data, DataChannelName channel);
    Task BroadcastAsync(byte[] data, DataChannelName channel);
    IObservable<IncomingMessage> IncomingMessages { get; }
    IReadOnlyDictionary<PeerId, PeerConnectionState> ConnectedPeers { get; }
}

public readonly record struct DataChannelName(string Value)
{
    public static readonly DataChannelName Signaling = new("vox-signaling");
    public static readonly DataChannelName Chat = new("vox-chat");
    public static readonly DataChannelName Voice = new("vox-voice");
    public static readonly DataChannelName Routing = new("vox-routing");
    public static readonly DataChannelName Presence = new("vox-presence");
}

public sealed record IncomingMessage(PeerId Sender, DataChannelName Channel, byte[] Data);

public enum PeerConnectionState : byte
{
    Connecting = 0,
    Connected = 1,
    Degraded = 2,
    Disconnected = 3,
}
