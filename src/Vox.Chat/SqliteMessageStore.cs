using Microsoft.Data.Sqlite;
using Vox.Core.Groups;
using Vox.Core.Identity;

namespace Vox.Chat;

/// <summary>
/// SQLite-backed message store. Each instance manages a single database file.
/// </summary>
public sealed class SqliteMessageStore : IMessageStore
{
    private readonly SqliteConnection _connection;

    public SqliteMessageStore(string dbPath)
    {
        _connection = new SqliteConnection($"Data Source={dbPath}");
        _connection.Open();
        InitializeSchema();
    }

    private void InitializeSchema()
    {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS messages (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT NOT NULL UNIQUE,
                group_id TEXT NOT NULL,
                author_pubkey TEXT NOT NULL,
                author_display_name TEXT NOT NULL,
                content TEXT NOT NULL,
                timestamp_ms INTEGER NOT NULL,
                lamport_clock INTEGER NOT NULL,
                verified INTEGER NOT NULL DEFAULT 1
            );
            CREATE INDEX IF NOT EXISTS idx_messages_group
                ON messages(group_id, seq DESC);
            """;
        cmd.ExecuteNonQuery();
    }

    public async Task SaveAsync(ChatMessageRecord message)
    {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = """
            INSERT OR IGNORE INTO messages
                (message_id, group_id, author_pubkey, author_display_name,
                 content, timestamp_ms, lamport_clock, verified)
            VALUES (@mid, @gid, @author, @name, @content, @ts, @lc, @verified)
            """;
        cmd.Parameters.AddWithValue("@mid", message.MessageId.ToString());
        cmd.Parameters.AddWithValue("@gid", message.GroupId.ToHex());
        cmd.Parameters.AddWithValue("@author", message.Author.ToHex());
        cmd.Parameters.AddWithValue("@name", message.AuthorDisplayName);
        cmd.Parameters.AddWithValue("@content", message.Content);
        cmd.Parameters.AddWithValue("@ts", message.Timestamp.ToUnixTimeMilliseconds());
        cmd.Parameters.AddWithValue("@lc", (long)message.LamportClock);
        cmd.Parameters.AddWithValue("@verified", message.Verified ? 1 : 0);
        await cmd.ExecuteNonQueryAsync();
    }

    public async Task<IReadOnlyList<ChatMessageRecord>> GetHistoryAsync(
        GroupId groupId, int limit, Guid? beforeMessageId = null)
    {
        using var cmd = _connection.CreateCommand();

        if (beforeMessageId is null)
        {
            cmd.CommandText = """
                SELECT message_id, group_id, author_pubkey, author_display_name,
                       content, timestamp_ms, lamport_clock, verified
                FROM messages
                WHERE group_id = @gid
                ORDER BY seq DESC
                LIMIT @limit
                """;
        }
        else
        {
            cmd.CommandText = """
                SELECT message_id, group_id, author_pubkey, author_display_name,
                       content, timestamp_ms, lamport_clock, verified
                FROM messages
                WHERE group_id = @gid
                  AND seq < (SELECT seq FROM messages WHERE message_id = @before)
                ORDER BY seq DESC
                LIMIT @limit
                """;
            cmd.Parameters.AddWithValue("@before", beforeMessageId.Value.ToString());
        }

        cmd.Parameters.AddWithValue("@gid", groupId.ToHex());
        cmd.Parameters.AddWithValue("@limit", limit);

        var results = new List<ChatMessageRecord>();
        using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            results.Add(new ChatMessageRecord(
                Guid.Parse(reader.GetString(0)),
                new GroupId(Convert.FromHexString(reader.GetString(1))),
                new PeerId(Convert.FromHexString(reader.GetString(2))),
                reader.GetString(3),
                reader.GetString(4),
                DateTimeOffset.FromUnixTimeMilliseconds(reader.GetInt64(5)),
                (ulong)reader.GetInt64(6),
                reader.GetInt32(7) != 0
            ));
        }

        // Reverse to return chronological order (oldest first)
        results.Reverse();
        return results;
    }

    public void Dispose()
    {
        SqliteConnection.ClearPool(_connection);
        _connection.Dispose();
    }
}
