using System.Text;
using Vox.Chat;
using Vox.Core.Crypto;
using Vox.Core.Groups;
using Vox.Core.Identity;
using Vox.Core.Protocol;

namespace Vox.Chat.Tests;

/// <summary>
/// Stub transport that captures broadcast packets for inspection.
/// </summary>
internal sealed class StubTransport : IMessageTransport
{
    public List<(GroupId Group, byte[] Packet)> Sent { get; } = [];

    public Task BroadcastAsync(GroupId groupId, byte[] packet)
    {
        Sent.Add((groupId, packet));
        return Task.CompletedTask;
    }
}

/// <summary>
/// Collects IObservable notifications.
/// </summary>
internal sealed class TestObserver<T> : IObserver<T>
{
    public List<T> Values { get; } = [];
    public bool Completed { get; private set; }
    public Exception? Error { get; private set; }

    public void OnCompleted() => Completed = true;
    public void OnError(Exception error) => Error = error;
    public void OnNext(T value) => Values.Add(value);
}

public class ChatServiceTests : IDisposable
{
    private readonly ICryptoService _cryptoService = new LibsodiumCryptoService();
    private readonly LocalIdentity _identity;
    private readonly GroupId _groupId;
    private readonly StubTransport _transport = new();
    private readonly SqliteMessageStore _store;
    private readonly ChatService _service;
    private readonly string _dbPath;

    public ChatServiceTests()
    {
        var (sigPub, sigPriv) = _cryptoService.GenerateEd25519Keypair();
        var (encPub, encPriv) = _cryptoService.GenerateX25519Keypair();
        _identity = new LocalIdentity
        {
            Username = "TestUser",
            Discriminator = 1234,
            SigningPublicKey = sigPub,
            SigningPrivateKey = sigPriv,
            EncryptionPublicKey = encPub,
            EncryptionPrivateKey = encPriv,
        };

        var groupBytes = new byte[32];
        groupBytes[0] = 0x01;
        _groupId = new GroupId(groupBytes);

        _dbPath = Path.Combine(Path.GetTempPath(), $"vox_chat_test_{Guid.NewGuid():N}.db");
        _store = new SqliteMessageStore(_dbPath);
        _service = new ChatService(_identity, _cryptoService, _transport, _store);
    }

    public void Dispose()
    {
        _service.Dispose();
        _store.Dispose();
        if (File.Exists(_dbPath))
            File.Delete(_dbPath);
    }

    [Fact]
    public async Task SendMessage_stores_locally()
    {
        await _service.SendMessageAsync(_groupId, "Hello, world!");

        var history = await _service.GetHistoryAsync(_groupId);
        Assert.Single(history);
        Assert.Equal("Hello, world!", history[0].Content);
        Assert.Equal(_identity.PeerId, history[0].Author);
        Assert.Equal("TestUser#1234", history[0].AuthorDisplayName);
        Assert.True(history[0].Verified);
    }

    [Fact]
    public async Task SendMessage_broadcasts_via_transport()
    {
        await _service.SendMessageAsync(_groupId, "broadcast me");

        Assert.Single(_transport.Sent);
        Assert.Equal(_groupId, _transport.Sent[0].Group);
        Assert.True(_transport.Sent[0].Packet.Length > 0);
    }

    [Fact]
    public async Task SendMessage_packet_has_valid_signature()
    {
        await _service.SendMessageAsync(_groupId, "signed message");

        var packet = _transport.Sent[0].Packet;
        var signable = ChatMessageSerializer.GetSignableSpan(packet);
        var signature = packet.AsSpan(packet.Length - ChatMessagePacket.SignatureSize);

        Assert.True(_cryptoService.Verify(signable, signature, _identity.SigningPublicKey));
    }

    [Fact]
    public async Task SendMessage_notifies_observers()
    {
        var observer = new TestObserver<ChatMessageReceived>();
        using var sub = _service.IncomingMessages.Subscribe(observer);

        await _service.SendMessageAsync(_groupId, "observable test");

        Assert.Single(observer.Values);
        Assert.Equal("observable test", observer.Values[0].Message.Content);
        Assert.False(observer.Values[0].FromSync);
    }

    [Fact]
    public async Task SendMessage_rejects_empty_content()
    {
        await Assert.ThrowsAsync<ArgumentException>(
            () => _service.SendMessageAsync(_groupId, ""));
    }

    [Fact]
    public async Task SendMessage_rejects_oversized_content()
    {
        var oversized = new string('X', 5000);
        await Assert.ThrowsAsync<ArgumentException>(
            () => _service.SendMessageAsync(_groupId, oversized));
    }

    [Fact]
    public async Task SendMessage_increments_lamport_clock()
    {
        await _service.SendMessageAsync(_groupId, "msg1");
        await _service.SendMessageAsync(_groupId, "msg2");

        var history = await _service.GetHistoryAsync(_groupId);
        Assert.Equal(2, history.Count);
        Assert.True(history[1].LamportClock > history[0].LamportClock);
    }

    [Fact]
    public async Task HandleIncoming_valid_packet()
    {
        // Build a valid signed packet from a different identity
        var (remoteSigPub, remoteSigPriv) = _cryptoService.GenerateEd25519Keypair();
        var remoteIdentity = new PeerId(remoteSigPub);

        var serializer = new ChatMessageSerializer();
        var packet = new ChatMessagePacket
        {
            Header = new CommonHeader { PacketId = 1 },
            Sender = remoteIdentity,
            GroupId = _groupId,
            MessageId = Guid.NewGuid(),
            TimestampMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            LamportClock = 5,
            ParentEventIds = [],
            ContentUtf8 = Encoding.UTF8.GetBytes("remote message"),
            Signature = new byte[64],
        };

        var size = serializer.GetSerializedSize(in packet);
        var buffer = new byte[size];
        serializer.Serialize(in packet, buffer);

        // Sign it
        var signable = ChatMessageSerializer.GetSignableSpan(buffer);
        var sig = _cryptoService.Sign(signable, remoteSigPriv);
        sig.CopyTo(buffer.AsSpan(size - ChatMessagePacket.SignatureSize));

        var observer = new TestObserver<ChatMessageReceived>();
        using var sub = _service.IncomingMessages.Subscribe(observer);

        var result = await _service.HandleIncomingPacketAsync(buffer);

        Assert.NotNull(result);
        Assert.Equal("remote message", result.Content);
        Assert.Equal(remoteIdentity, result.Author);
        Assert.True(result.Verified);

        // Should be stored
        var history = await _service.GetHistoryAsync(_groupId);
        Assert.Single(history);

        // Should trigger observer
        Assert.Single(observer.Values);
    }

    [Fact]
    public async Task HandleIncoming_rejects_invalid_signature()
    {
        var (remoteSigPub, _) = _cryptoService.GenerateEd25519Keypair();
        var (_, wrongPrivKey) = _cryptoService.GenerateEd25519Keypair();

        var serializer = new ChatMessageSerializer();
        var packet = new ChatMessagePacket
        {
            Header = new CommonHeader { PacketId = 1 },
            Sender = new PeerId(remoteSigPub),
            GroupId = _groupId,
            MessageId = Guid.NewGuid(),
            TimestampMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            LamportClock = 1,
            ParentEventIds = [],
            ContentUtf8 = "bad sig"u8.ToArray(),
            Signature = new byte[64],
        };

        var size = serializer.GetSerializedSize(in packet);
        var buffer = new byte[size];
        serializer.Serialize(in packet, buffer);

        // Sign with the WRONG key
        var signable = ChatMessageSerializer.GetSignableSpan(buffer);
        var sig = _cryptoService.Sign(signable, wrongPrivKey);
        sig.CopyTo(buffer.AsSpan(size - ChatMessagePacket.SignatureSize));

        var result = await _service.HandleIncomingPacketAsync(buffer);
        Assert.Null(result);

        var history = await _service.GetHistoryAsync(_groupId);
        Assert.Empty(history);
    }

    [Fact]
    public async Task HandleIncoming_rejects_duplicate()
    {
        var (remoteSigPub, remoteSigPriv) = _cryptoService.GenerateEd25519Keypair();

        var serializer = new ChatMessageSerializer();
        var packet = new ChatMessagePacket
        {
            Header = new CommonHeader { PacketId = 1 },
            Sender = new PeerId(remoteSigPub),
            GroupId = _groupId,
            MessageId = Guid.NewGuid(),
            TimestampMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            LamportClock = 1,
            ParentEventIds = [],
            ContentUtf8 = "dedup me"u8.ToArray(),
            Signature = new byte[64],
        };

        var size = serializer.GetSerializedSize(in packet);
        var buffer = new byte[size];
        serializer.Serialize(in packet, buffer);

        var signable = ChatMessageSerializer.GetSignableSpan(buffer);
        var sig = _cryptoService.Sign(signable, remoteSigPriv);
        sig.CopyTo(buffer.AsSpan(size - ChatMessagePacket.SignatureSize));

        // First call should succeed
        var first = await _service.HandleIncomingPacketAsync(buffer);
        Assert.NotNull(first);

        // Second call should be deduplicated
        var second = await _service.HandleIncomingPacketAsync(buffer);
        Assert.Null(second);
    }

    [Fact]
    public async Task HandleIncoming_rejects_too_short_packet()
    {
        var result = await _service.HandleIncomingPacketAsync(new byte[10]);
        Assert.Null(result);
    }

    [Fact]
    public async Task HandleIncoming_rejects_wrong_packet_type()
    {
        var buffer = new byte[CommonHeader.Size + ChatMessagePacket.FixedFieldsSize + 10];
        buffer[0] = PacketTypes.VoiceFrame; // wrong type

        var result = await _service.HandleIncomingPacketAsync(buffer);
        Assert.Null(result);
    }

    [Fact]
    public async Task SendMessage_does_not_echo_back_on_handle()
    {
        await _service.SendMessageAsync(_groupId, "no echo");

        // Try to "receive" the same packet we sent
        var sentPacket = _transport.Sent[0].Packet;
        var result = await _service.HandleIncomingPacketAsync(sentPacket);

        // Should be rejected as duplicate (message ID was marked seen during send)
        Assert.Null(result);
    }

    [Fact]
    public async Task Multiple_messages_have_unique_ids()
    {
        await _service.SendMessageAsync(_groupId, "msg1");
        await _service.SendMessageAsync(_groupId, "msg2");
        await _service.SendMessageAsync(_groupId, "msg3");

        var history = await _service.GetHistoryAsync(_groupId);
        var ids = history.Select(m => m.MessageId).ToList();
        Assert.Equal(3, ids.Distinct().Count());
    }

    [Fact]
    public async Task Unicode_content_roundtrips()
    {
        await _service.SendMessageAsync(_groupId, "你好世界 🌍 مرحبا");

        var history = await _service.GetHistoryAsync(_groupId);
        Assert.Equal("你好世界 🌍 مرحبا", history[0].Content);
    }

    [Fact]
    public async Task GetHistory_pagination()
    {
        for (int i = 0; i < 10; i++)
            await _service.SendMessageAsync(_groupId, $"msg{i}");

        var page1 = await _service.GetHistoryAsync(_groupId, limit: 3);
        Assert.Equal(3, page1.Count);
        Assert.Equal("msg7", page1[0].Content);
        Assert.Equal("msg8", page1[1].Content);
        Assert.Equal("msg9", page1[2].Content);

        var page2 = await _service.GetHistoryAsync(_groupId, limit: 3, before: page1[0].MessageId);
        Assert.Equal(3, page2.Count);
        Assert.Equal("msg4", page2[0].Content);
        Assert.Equal("msg5", page2[1].Content);
        Assert.Equal("msg6", page2[2].Content);
    }
}
