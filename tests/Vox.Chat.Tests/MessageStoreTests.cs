using Vox.Chat;
using Vox.Core.Groups;
using Vox.Core.Identity;

namespace Vox.Chat.Tests;

public class MessageStoreTests : IDisposable
{
    private readonly string _dbPath;
    private readonly SqliteMessageStore _store;
    private readonly GroupId _groupId;
    private readonly PeerId _peerId;

    public MessageStoreTests()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"vox_test_{Guid.NewGuid():N}.db");
        _store = new SqliteMessageStore(_dbPath);

        var groupBytes = new byte[32];
        groupBytes[0] = 0x01;
        _groupId = new GroupId(groupBytes);

        var peerBytes = new byte[32];
        peerBytes[0] = 0xAA;
        _peerId = new PeerId(peerBytes);
    }

    public void Dispose()
    {
        _store.Dispose();
        if (File.Exists(_dbPath))
            File.Delete(_dbPath);
    }

    private ChatMessageRecord MakeRecord(
        Guid? messageId = null,
        GroupId? groupId = null,
        ulong lamportClock = 1,
        string content = "hello",
        long? timestampMs = null)
    {
        return new ChatMessageRecord(
            messageId ?? Guid.NewGuid(),
            groupId ?? _groupId,
            _peerId,
            "TestUser#0001",
            content,
            DateTimeOffset.FromUnixTimeMilliseconds(timestampMs ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()),
            lamportClock,
            Verified: true);
    }

    [Fact]
    public async Task Save_and_retrieve_single_message()
    {
        var record = MakeRecord(content: "first message");
        await _store.SaveAsync(record);

        var history = await _store.GetHistoryAsync(_groupId, limit: 10);

        Assert.Single(history);
        Assert.Equal(record.MessageId, history[0].MessageId);
        Assert.Equal("first message", history[0].Content);
        Assert.Equal(record.Author, history[0].Author);
        Assert.Equal(record.AuthorDisplayName, history[0].AuthorDisplayName);
        Assert.Equal(record.LamportClock, history[0].LamportClock);
        Assert.True(history[0].Verified);
    }

    [Fact]
    public async Task History_returns_chronological_order()
    {
        await _store.SaveAsync(MakeRecord(content: "msg1", lamportClock: 1, timestampMs: 1000));
        await _store.SaveAsync(MakeRecord(content: "msg2", lamportClock: 2, timestampMs: 2000));
        await _store.SaveAsync(MakeRecord(content: "msg3", lamportClock: 3, timestampMs: 3000));

        var history = await _store.GetHistoryAsync(_groupId, limit: 10);

        Assert.Equal(3, history.Count);
        Assert.Equal("msg1", history[0].Content);
        Assert.Equal("msg2", history[1].Content);
        Assert.Equal("msg3", history[2].Content);
    }

    [Fact]
    public async Task History_respects_limit()
    {
        for (int i = 0; i < 10; i++)
            await _store.SaveAsync(MakeRecord(content: $"msg{i}", lamportClock: (ulong)i));

        var history = await _store.GetHistoryAsync(_groupId, limit: 3);

        Assert.Equal(3, history.Count);
        // Should return the latest 3 in chronological order
        Assert.Equal("msg7", history[0].Content);
        Assert.Equal("msg8", history[1].Content);
        Assert.Equal("msg9", history[2].Content);
    }

    [Fact]
    public async Task History_pagination_with_before()
    {
        var messageIds = new Guid[5];
        for (int i = 0; i < 5; i++)
        {
            messageIds[i] = Guid.NewGuid();
            await _store.SaveAsync(MakeRecord(
                messageId: messageIds[i], content: $"msg{i}", lamportClock: (ulong)i));
        }

        // Get messages before msg3
        var history = await _store.GetHistoryAsync(_groupId, limit: 10, beforeMessageId: messageIds[3]);

        Assert.Equal(3, history.Count);
        Assert.Equal("msg0", history[0].Content);
        Assert.Equal("msg1", history[1].Content);
        Assert.Equal("msg2", history[2].Content);
    }

    [Fact]
    public async Task History_filters_by_group()
    {
        var groupBytes2 = new byte[32];
        groupBytes2[0] = 0x02;
        var otherGroup = new GroupId(groupBytes2);

        await _store.SaveAsync(MakeRecord(groupId: _groupId, content: "group1"));
        await _store.SaveAsync(MakeRecord(groupId: otherGroup, content: "group2"));
        await _store.SaveAsync(MakeRecord(groupId: _groupId, content: "group1-again"));

        var history = await _store.GetHistoryAsync(_groupId, limit: 10);

        Assert.Equal(2, history.Count);
        Assert.All(history, m => Assert.Equal(_groupId, m.GroupId));
    }

    [Fact]
    public async Task Duplicate_message_id_is_ignored()
    {
        var id = Guid.NewGuid();
        await _store.SaveAsync(MakeRecord(messageId: id, content: "first"));
        await _store.SaveAsync(MakeRecord(messageId: id, content: "duplicate"));

        var history = await _store.GetHistoryAsync(_groupId, limit: 10);

        Assert.Single(history);
        Assert.Equal("first", history[0].Content);
    }

    [Fact]
    public async Task Empty_history_returns_empty_list()
    {
        var history = await _store.GetHistoryAsync(_groupId, limit: 10);
        Assert.Empty(history);
    }

    [Fact]
    public async Task Timestamp_roundtrips_correctly()
    {
        var ts = DateTimeOffset.Parse("2026-01-15T12:30:00Z");
        var record = MakeRecord(timestampMs: ts.ToUnixTimeMilliseconds());
        await _store.SaveAsync(record);

        var history = await _store.GetHistoryAsync(_groupId, limit: 1);
        Assert.Equal(ts, history[0].Timestamp);
    }

    [Fact]
    public async Task Verified_false_persists()
    {
        var record = new ChatMessageRecord(
            Guid.NewGuid(), _groupId, _peerId,
            "User#0001", "unverified msg",
            DateTimeOffset.UtcNow, 1, Verified: false);

        await _store.SaveAsync(record);

        var history = await _store.GetHistoryAsync(_groupId, limit: 1);
        Assert.False(history[0].Verified);
    }
}
