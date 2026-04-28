using Vox.Core.Identity;

namespace Vox.Core.Contacts;

/// <summary>
/// A locally stored contact. Contacts are established via Contact Link/QR or shared group membership.
/// No global search or Name#1234 lookup exists.
/// </summary>
public sealed class ContactInfo
{
    public required PeerId PeerId { get; init; }
    public required string DisplayName { get; set; }
    public required ContactStatus Status { get; set; }
    public DateTimeOffset AddedAt { get; init; } = DateTimeOffset.UtcNow;
}

public enum ContactStatus : byte
{
    Pending = 0,
    Accepted = 1,
    Blocked = 2,
}
