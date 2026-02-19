using System.Text;
using Vox.Core.Configuration;
using Vox.Core.Crypto;
using Vox.Core.Events;
using Vox.Core.Groups;
using Vox.Core.Identity;
using Vox.Core.Observable;
using Vox.Core.Protocol;

namespace Vox.Chat;

/// <summary>
/// Core chat service: sends, receives, signs, verifies, deduplicates, and stores messages.
/// </summary>
public sealed class ChatService : IChatService, IDisposable
{
    private const int PeerIdDisplayHexLength = 8;

    private readonly LocalIdentity _localIdentity;
    private readonly ICryptoService _cryptoService;
    private readonly IMessageTransport _transport;
    private readonly IMessageStore _store;
    private readonly MessageDeduplicator _dedup;
    private readonly LamportClock _clock = new();
    private readonly ChatMessageSerializer _serializer = new();
    private readonly EventSubject<ChatMessageReceived> _incomingSubject = new();
    private long _packetIdCounter;

    public IObservable<ChatMessageReceived> IncomingMessages => _incomingSubject;

    public ChatService(
        LocalIdentity localIdentity,
        ICryptoService crypto,
        IMessageTransport transport,
        IMessageStore store,
        MessageDeduplicator? dedup = null)
    {
        _localIdentity = localIdentity;
        _cryptoService = crypto;
        _transport = transport;
        _store = store;
        _dedup = dedup ?? new MessageDeduplicator();
    }

    public async Task SendMessageAsync(GroupId groupId, string content)
    {
        var contentBytes = Encoding.UTF8.GetBytes(content);
        if (contentBytes.Length == 0)
            throw new ArgumentException("Message cannot be empty.", nameof(content));
        if (contentBytes.Length > VoxDefaults.MaxChatMessageBytes)
            throw new ArgumentException(
                $"Message exceeds {VoxDefaults.MaxChatMessageBytes} byte limit.", nameof(content));

        var messageId = Guid.NewGuid();
        var timestampMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var lamportClock = _clock.Tick();
        var packetId = Interlocked.Increment(ref _packetIdCounter);

        var packet = new ChatMessagePacket
        {
            Header = new CommonHeader
            {
                PacketId = packetId,
                Ttl = 0,
                Flags = PacketFlags.None,
            },
            Sender = _localIdentity.PeerId,
            GroupId = groupId,
            MessageId = messageId,
            TimestampMs = timestampMs,
            LamportClock = lamportClock,
            ParentEventIds = [],
            ContentUtf8 = contentBytes,
            Signature = new byte[ChatMessagePacket.SignatureSize],
        };

        // Serialize with placeholder signature, then sign, then overwrite
        var size = _serializer.GetSerializedSize(in packet);
        var buffer = new byte[size];
        _serializer.Serialize(in packet, buffer);

        var signable = ChatMessageSerializer.GetSignableSpan(buffer);
        var signature = _cryptoService.Sign(signable, _localIdentity.SigningPrivateKey);
        signature.CopyTo(buffer.AsSpan(size - ChatMessagePacket.SignatureSize));

        // Mark as seen to prevent echo
        _dedup.TryAdd(messageId);

        // Store locally
        var record = new ChatMessageRecord(
            messageId, groupId, _localIdentity.PeerId,
            _localIdentity.DisplayName, content,
            DateTimeOffset.FromUnixTimeMilliseconds(timestampMs),
            lamportClock, Verified: true);

        await _store.SaveAsync(record);
        await _transport.BroadcastAsync(groupId, buffer);

        _incomingSubject.OnNext(new ChatMessageReceived(record, FromSync: false));
    }

    /// <summary>
    /// Process an incoming raw chat packet from the network.
    /// Verifies signature, deduplicates, stores, and notifies observers.
    /// Returns the message record if valid, or null if dropped.
    /// </summary>
    public async Task<ChatMessageRecord?> HandleIncomingPacketAsync(ReadOnlyMemory<byte> data)
    {
        if (data.Length < CommonHeader.Size + ChatMessagePacket.FixedFieldsSize)
            return null;

        var header = CommonHeader.ReadFrom(data.Span);
        if (header.PacketType != PacketTypes.ChatMessage)
            return null;

        ChatMessagePacket packet;
        try
        {
            packet = _serializer.Deserialize(data.Span);
        }
        catch
        {
            return null;
        }

        // Dedup
        if (!_dedup.TryAdd(packet.MessageId))
            return null;

        // Verify signature
        var signable = ChatMessageSerializer.GetSignableSpan(data.Span);
        var verified = _cryptoService.Verify(signable, packet.Signature, packet.Sender.PublicKey);
        if (!verified)
            return null;

        // Update lamport clock
        _clock.Receive(packet.LamportClock);

        var content = Encoding.UTF8.GetString(packet.ContentUtf8);
        var displayName = packet.Sender.ToHex()[..PeerIdDisplayHexLength] + "…";

        var record = new ChatMessageRecord(
            packet.MessageId, packet.GroupId, packet.Sender,
            displayName, content,
            DateTimeOffset.FromUnixTimeMilliseconds(packet.TimestampMs),
            packet.LamportClock, Verified: true);

        await _store.SaveAsync(record);

        _incomingSubject.OnNext(new ChatMessageReceived(record, FromSync: false));

        return record;
    }

    public Task<IReadOnlyList<ChatMessageRecord>> GetHistoryAsync(
        GroupId groupId, int limit = 100, Guid? before = null)
    {
        return _store.GetHistoryAsync(groupId, limit, before);
    }

    public void Dispose()
    {
        _incomingSubject.Dispose();
    }
}
