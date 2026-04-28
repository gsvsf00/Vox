using Vox.Core.Identity;

namespace Vox.Core.Contacts;

/// <summary>
/// Manages contacts: add via contact link, accept/reject incoming requests, list contacts.
/// Contact Link/QR or shared group required — no global search.
/// </summary>
public interface IContactService
{
    /// <summary>Generate a Contact Link URL for the local identity.</summary>
    string CreateContactLink();

    /// <summary>Initiate a contact request from a received Contact Link.</summary>
    Task<ContactRequestResult> SendContactRequestAsync(string contactLink);

    /// <summary>Accept an incoming contact request.</summary>
    Task AcceptContactAsync(PeerId requester);

    /// <summary>Reject an incoming contact request.</summary>
    Task RejectContactAsync(PeerId requester);

    /// <summary>Remove a contact.</summary>
    Task RemoveContactAsync(PeerId peerId);

    /// <summary>All known contacts (pending + accepted).</summary>
    IReadOnlyList<ContactInfo> GetContacts();

    /// <summary>Incoming contact requests awaiting acceptance.</summary>
    IReadOnlyList<ContactInfo> GetPendingRequests();

    /// <summary>Fires when contact list changes (add/accept/reject/remove).</summary>
    IObservable<ContactEvent> ContactEvents { get; }
}

public sealed record ContactRequestResult(bool Success, string? Error);

public sealed record ContactEvent(PeerId PeerId, ContactEventType Type);

public enum ContactEventType : byte
{
    RequestReceived = 0,
    Accepted = 1,
    Rejected = 2,
    Removed = 3,
}
