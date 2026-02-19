using Vox.Core.Identity;
using Vox.Core.Protocol;

namespace Vox.Network.Routing;

/// <summary>
/// Mesh routing engine. Maintains link-state database, computes shortest paths,
/// and determines relay sets for multicast voice distribution.
/// </summary>
public interface IMeshRouter
{
    PeerId? GetNextHop(PeerId destination);
    IReadOnlyList<PeerId> GetMulticastRelaySet(PeerId source);
    void UpdateLinkMetrics(PeerId peer, LinkMetrics metrics);
    void OnPeerConnected(PeerId peer);
    void OnPeerDisconnected(PeerId peer);
    IReadOnlyDictionary<PeerId, RouteEntry> GetRoutingTable();
    IObservable<RoutingTableChanged> RoutingChanges { get; }
    void Distribute(VoiceFramePacket frame);
}

public sealed record LinkMetrics(
    ushort RttMs,
    ushort JitterMs,
    byte LossPercent,
    byte StabilityPercent,
    byte CapacityPercent);

public sealed record RouteEntry(
    PeerId Destination,
    PeerId PrimaryNextHop,
    PeerId? BackupNextHop,
    double Cost,
    int HopCount);

public sealed record RoutingTableChanged(
    IReadOnlyDictionary<PeerId, RouteEntry> NewTable,
    DateTimeOffset Timestamp);
