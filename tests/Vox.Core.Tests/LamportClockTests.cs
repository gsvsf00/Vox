using Vox.Core.Events;

namespace Vox.Core.Tests;

public class LamportClockTests
{
    [Fact]
    public void Initial_value_is_zero()
    {
        var clock = new LamportClock();
        Assert.Equal(0UL, clock.Value);
    }

    [Fact]
    public void Tick_increments()
    {
        var clock = new LamportClock();

        Assert.Equal(1UL, clock.Tick());
        Assert.Equal(2UL, clock.Tick());
        Assert.Equal(3UL, clock.Tick());
    }

    [Fact]
    public void Receive_takes_max_plus_one()
    {
        var clock = new LamportClock();
        clock.Tick(); // local = 1

        // Remote is ahead
        var result = clock.Receive(10);
        Assert.Equal(11UL, result);
        Assert.Equal(11UL, clock.Value);
    }

    [Fact]
    public void Receive_when_local_is_ahead()
    {
        var clock = new LamportClock();
        for (int i = 0; i < 20; i++) clock.Tick(); // local = 20

        var result = clock.Receive(5); // remote is behind
        Assert.Equal(21UL, result); // max(20, 5) + 1 = 21
    }

    [Fact]
    public void Concurrent_ticks_are_monotonic()
    {
        var clock = new LamportClock();
        var results = new ulong[1000];

        Parallel.For(0, 1000, i =>
        {
            results[i] = clock.Tick();
        });

        // All values should be unique (no duplicates)
        Assert.Equal(1000, results.Distinct().Count());
        Assert.Equal(1000UL, clock.Value);
    }
}
