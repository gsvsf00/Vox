using Vox.Chat;

namespace Vox.Chat.Tests;

public class MessageDeduplicatorTests
{
    [Fact]
    public void TryAdd_returns_true_for_new_id()
    {
        var dedup = new MessageDeduplicator();
        Assert.True(dedup.TryAdd(Guid.NewGuid()));
    }

    [Fact]
    public void TryAdd_returns_false_for_duplicate()
    {
        var dedup = new MessageDeduplicator();
        var id = Guid.NewGuid();

        Assert.True(dedup.TryAdd(id));
        Assert.False(dedup.TryAdd(id));
    }

    [Fact]
    public void Contains_reflects_added_ids()
    {
        var dedup = new MessageDeduplicator();
        var id = Guid.NewGuid();

        Assert.False(dedup.Contains(id));
        dedup.TryAdd(id);
        Assert.True(dedup.Contains(id));
    }

    [Fact]
    public void Count_tracks_unique_ids()
    {
        var dedup = new MessageDeduplicator();

        dedup.TryAdd(Guid.NewGuid());
        dedup.TryAdd(Guid.NewGuid());
        dedup.TryAdd(Guid.NewGuid());

        Assert.Equal(3, dedup.Count);
    }

    [Fact]
    public void Evicts_oldest_when_capacity_exceeded()
    {
        var dedup = new MessageDeduplicator(capacity: 3);
        var ids = Enumerable.Range(0, 5).Select(_ => Guid.NewGuid()).ToArray();

        foreach (var id in ids)
            dedup.TryAdd(id);

        // Capacity is 3, so first 2 should be evicted
        Assert.Equal(3, dedup.Count);
        Assert.False(dedup.Contains(ids[0]));
        Assert.False(dedup.Contains(ids[1]));
        Assert.True(dedup.Contains(ids[2]));
        Assert.True(dedup.Contains(ids[3]));
        Assert.True(dedup.Contains(ids[4]));
    }

    [Fact]
    public void Duplicate_does_not_increase_count()
    {
        var dedup = new MessageDeduplicator();
        var id = Guid.NewGuid();

        dedup.TryAdd(id);
        dedup.TryAdd(id);
        dedup.TryAdd(id);

        Assert.Equal(1, dedup.Count);
    }

    [Fact]
    public void Evicted_id_can_be_re_added()
    {
        var dedup = new MessageDeduplicator(capacity: 2);
        var first = Guid.NewGuid();

        dedup.TryAdd(first);
        dedup.TryAdd(Guid.NewGuid());
        dedup.TryAdd(Guid.NewGuid()); // evicts 'first'

        Assert.False(dedup.Contains(first));
        Assert.True(dedup.TryAdd(first)); // can be re-added
    }

    [Fact]
    public void Thread_safety_concurrent_adds()
    {
        var dedup = new MessageDeduplicator(capacity: 10_000);
        var ids = Enumerable.Range(0, 1000).Select(_ => Guid.NewGuid()).ToArray();

        Parallel.ForEach(ids, id => dedup.TryAdd(id));

        Assert.Equal(1000, dedup.Count);
    }

    [Fact]
    public void Constructor_rejects_zero_capacity()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new MessageDeduplicator(0));
    }
}
