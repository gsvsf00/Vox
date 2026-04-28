using Vox.Core.Identity;

namespace Vox.Core.Groups;

/// <summary>
/// Signed statement: "PeerId X is a member of GroupId Y, admitted by PeerId Z at time T."
/// Verified by any group member using the admitter's public key.
/// </summary>
public sealed class MembershipCertificate
{
    public required GroupId GroupId { get; init; }
    public required PeerId AdmittedPeerId { get; init; }
    public required PeerId AdmittedByPeerId { get; init; }
    public required DateTimeOffset AdmittedAt { get; init; }

    /// <summary>Ed25519 signature by the admitting peer over all preceding fields.</summary>
    public required byte[] Signature { get; init; }
}
