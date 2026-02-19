using System.Buffers.Binary;
using Vox.Core.Identity;

namespace Vox.Core.Protocol;

/// <summary>
/// RelayFrame (0x21): wraps a VoiceFrame for multi-hop relay.
/// Uses common header. Per PROTOCOL.md §12.2.
/// </summary>
public struct RelayFramePacket
{
    public CommonHeader Header;
    public PeerId OriginalSender;

    /// <summary>All-0xFF means multicast (broadcast to all group members).</summary>
    public PeerId FinalDestination;

    public byte HopCount;

    /// <summary>Identity pubkeys of each relay hop (for loop prevention).</summary>
    public List<PeerId> RelayPath;

    public Memory<byte> InnerPacket;
}
