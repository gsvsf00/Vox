using Vox.Core.Groups;
using Vox.Core.Identity;

namespace Vox.Chat;

/// <summary>
/// Handles text message sending, receiving, deduplication, and local storage.
/// </summary>
public interface IChatService
{
    Task SendMessageAsync(GroupId groupId, string content);
    IObservable<ChatMessageReceived> IncomingMessages { get; }
    Task<IReadOnlyList<ChatMessageRecord>> GetHistoryAsync(
        GroupId groupId, int limit = 100, Guid? before = null);
}

public sealed record ChatMessageReceived(
    ChatMessageRecord Message,
    bool FromSync);

public sealed record ChatMessageRecord(
    Guid MessageId,
    GroupId GroupId,
    PeerId Author,
    string AuthorDisplayName,
    string Content,
    DateTimeOffset Timestamp,
    ulong LamportClock,
    bool Verified);
