namespace Vox.Core.Events;

/// <summary>
/// Lamport clock for causal ordering across peers.
/// Thread-safe via Interlocked operations.
/// </summary>
public sealed class LamportClock
{
    private long _value;

    public ulong Value => (ulong)Interlocked.Read(ref _value);

    /// <summary>Increment for a local event and return the new value.</summary>
    public ulong Tick()
    {
        return (ulong)Interlocked.Increment(ref _value);
    }

    /// <summary>
    /// Update on receiving a remote event: max(local, remote) + 1.
    /// </summary>
    public ulong Receive(ulong remoteValue)
    {
        while (true)
        {
            var current = Interlocked.Read(ref _value);
            var newValue = Math.Max(current, (long)remoteValue) + 1;
            if (Interlocked.CompareExchange(ref _value, newValue, current) == current)
                return (ulong)newValue;

            System.Threading.Thread.SpinWait(1);
        }
    }
}
