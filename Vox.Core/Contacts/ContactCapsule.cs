using System.Net;
using Vox.Core.Identity;

namespace Vox.Core.Contacts;

/// <summary>
/// Cleartext contact capsule (before GZIP + encryption).
/// Contains only public information; integrity via Ed25519 signature.
/// </summary>
public sealed class ContactCapsule
{
    public required PeerId PeerId { get; init; }
    public required string DisplayName { get; init; }
    public required List<IPEndPoint> Endpoints { get; init; }
    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>Ed25519 signature over all preceding fields (set after serialization).</summary>
    public byte[]? Signature { get; set; }
}
