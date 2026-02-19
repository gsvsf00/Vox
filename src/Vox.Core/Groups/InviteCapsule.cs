using System.Net;
using Vox.Core.Identity;

namespace Vox.Core.Groups;

/// <summary>
/// Cleartext invite capsule (before encryption with group key).
/// </summary>
public sealed class InviteCapsule
{
    public required Guid InviteId { get; init; }
    public required GroupId GroupId { get; init; }
    public required PeerId Creator { get; init; }
    public required DateTimeOffset CreatedAt { get; init; }
    public required DateTimeOffset ExpiresAt { get; init; }
    public required InviteFlags Flags { get; init; }

    /// <summary>BLAKE2b hash of the password, or null if no password required.</summary>
    public byte[]? PasswordHash { get; init; }

    public required List<BootstrapPeer> BootstrapPeers { get; init; }

    /// <summary>Ed25519 signature over all preceding fields (set after serialization).</summary>
    public byte[]? CreatorSignature { get; set; }
}

[Flags]
public enum InviteFlags : byte
{
    None = 0,
    PasswordRequired = 1 << 0,
    SingleUse = 1 << 1,
}

public sealed record BootstrapPeer(byte[] WireGuardPublicKey, IPEndPoint Endpoint);
