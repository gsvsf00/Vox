namespace Vox.Chat;

/// <summary>
/// Bounded deduplication cache for chat message IDs.
/// Thread-safe. Evicts oldest entries when capacity is exceeded.
/// </summary>
public sealed class MessageDeduplicator
{
    private readonly LinkedList<Guid> _order = new();
    private readonly HashSet<Guid> _seen = new();
    private readonly int _capacity;
    private readonly object _lock = new();

    public MessageDeduplicator(int capacity = 10_000)
    {
        if (capacity < 1)
            throw new ArgumentOutOfRangeException(nameof(capacity));
        _capacity = capacity;
    }

    /// <summary>
    /// Attempts to mark a message ID as seen.
    /// Returns true if the ID was new (not a duplicate).
    /// Returns false if the ID was already seen (duplicate).
    /// </summary>
    public bool TryAdd(Guid messageId)
    {
        lock (_lock)
        {
            if (!_seen.Add(messageId))
                return false;

            _order.AddLast(messageId);

            while (_seen.Count > _capacity)
            {
                var oldest = _order.First!.Value;
                _order.RemoveFirst();
                _seen.Remove(oldest);
            }

            return true;
        }
    }

    public bool Contains(Guid messageId)
    {
        lock (_lock) return _seen.Contains(messageId);
    }

    public int Count
    {
        get { lock (_lock) return _seen.Count; }
    }
}
