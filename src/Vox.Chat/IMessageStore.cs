using Vox.Core.Groups;

namespace Vox.Chat;

/// <summary>
/// Persistence layer for chat messages.
/// </summary>
public interface IMessageStore : IDisposable
{
    Task SaveAsync(ChatMessageRecord message);

    /// <summary>
    /// Retrieve message history for a group, ordered chronologically (oldest first).
    /// If <paramref name="beforeMessageId"/> is specified, returns messages before that message.
    /// </summary>
    Task<IReadOnlyList<ChatMessageRecord>> GetHistoryAsync(
        GroupId groupId, int limit, Guid? beforeMessageId = null);
}
