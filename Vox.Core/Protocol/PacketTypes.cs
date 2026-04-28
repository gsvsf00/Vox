namespace Vox.Core.Protocol;

/// <summary>
/// All MVP packet type codes per PROTOCOL.md §8.
/// </summary>
public static class PacketTypes
{
    // --- Handshake (raw UDP) ---
    public const byte Knock = 0x01;
    public const byte KnockAccept = 0x02;
    public const byte Admission = 0x03;
    public const byte AdmissionAck = 0x04;

    // --- Chat (vox-chat DC) ---
    public const byte ChatMessage = 0x10;
    public const byte ChatAck = 0x11;

    // --- Voice (vox-voice DC) ---
    public const byte VoiceFrame = 0x20;
    public const byte RelayFrame = 0x21;

    // --- Presence (vox-presence DC) ---
    public const byte PresenceUpdate = 0x30;

    // --- Routing (vox-routing DC) ---
    public const byte LinkStateUpdate = 0x40;
    public const byte RoutingProbe = 0x41;
    public const byte RoutingPong = 0x42;

    // --- Signaling (vox-signaling DC) ---
    public const byte PeerListSync = 0x50;
    public const byte SdpOffer = 0x51;
    public const byte SdpAnswer = 0x52;
    public const byte IceCandidate = 0x53;
    public const byte GroupStateSync = 0x60;
    public const byte GroupEvent = 0x61;

    // --- Contacts (vox-signaling DC) ---
    public const byte ContactRequest = 0x70;
    public const byte ContactAccept = 0x71;
    public const byte ContactReject = 0x72;
}
