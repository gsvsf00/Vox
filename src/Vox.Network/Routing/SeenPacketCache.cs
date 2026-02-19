using Vox.Core.Identity;

namespace Vox.Network.Routing;

/// <summary>
/// LRU cache of recently seen packet IDs for loop prevention.
/// Thread-safe. Entries expire after a configurable TTL.
/// </summary>
public sealed class SeenPacketCache
{
    private readonly int _capacity;
    private readonly TimeSpan _ttl;
    private readonly Dictionary<long, long> _entries; // packetId -> timestampTicks
    private readonly LinkedList<long> _order;

    public SeenPacketCache(int capacity = 8192, int ttlSeconds = 5)
    {
        _capacity = capacity;
        _ttl = TimeSpan.FromSeconds(ttlSeconds);
        _entries = new Dictionary<long, long>(capacity);
        _order = new LinkedList<long>();
    }

    /// <summary>Returns true if this packet was already seen (duplicate). Adds it if new.</summary>
    public bool CheckAndAdd(long packetId)
    {
        lock (_entries)
        {
            Evict();

            if (_entries.ContainsKey(packetId))
                return true;

            if (_entries.Count >= _capacity)
            {
                var oldest = _order.First!.Value;
                _order.RemoveFirst();
                _entries.Remove(oldest);
            }

            _entries[packetId] = Environment.TickCount64;
            _order.AddLast(packetId);
            return false;
        }
    }

    private void Evict()
    {
        var now = Environment.TickCount64;
        var ttlTicks = (long)_ttl.TotalMilliseconds;

        while (_order.Count > 0)
        {
            var oldest = _order.First!.Value;
            if (now - _entries[oldest] > ttlTicks)
            {
                _order.RemoveFirst();
                _entries.Remove(oldest);
            }
            else
            {
                break;
            }
        }
    }
}
