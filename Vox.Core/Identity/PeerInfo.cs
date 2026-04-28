using System.Net;

namespace Vox.Core.Identity;

public sealed record PeerInfo(
    PeerId Id,
    string Username,
    ushort Discriminator,
    byte[] WireGuardPublicKey,
    List<IPEndPoint> Endpoints,
    PeerStatus Status,
    PeerCapabilities Capabilities
)
{
    public string DisplayName => Username;
}

public enum PeerStatus : byte
{
    Offline = 0,
    Online = 1,
    Away = 2,
    DoNotDisturb = 3,
}

[Flags]
public enum PeerCapabilities : ushort
{
    None = 0,
    Voice = 1 << 0,
    Relay = 1 << 1,
    HighBandwidth = 1 << 2,
}
