namespace Vox.Voice;

/// <summary>
/// Adaptive jitter buffer for incoming voice frames.
/// Compensates for network jitter by buffering frames before playback.
/// </summary>
public sealed class AdaptiveJitterBuffer
{
    private readonly SortedDictionary<uint, JitterEntry> _buffer = new();
    private uint _nextExpectedSequence;
    private double _jitterEstimate;
    private double _targetDelayMs;

    private readonly double _minDelayMs;
    private readonly double _maxDelayMs;

    public double CurrentDelayMs => _targetDelayMs;
    public int BufferedFrames => _buffer.Count;

    public AdaptiveJitterBuffer(
        double minDelayMs = 20,
        double initialDelayMs = 60,
        double maxDelayMs = 200)
    {
        _minDelayMs = minDelayMs;
        _targetDelayMs = initialDelayMs;
        _maxDelayMs = maxDelayMs;
    }

    /// <summary>Enqueue a received frame.</summary>
    public void Push(uint sequence, long arrivalTimestampUs, ReadOnlyMemory<byte> opusData)
    {
        if (_buffer.ContainsKey(sequence))
            return; // duplicate

        _buffer[sequence] = new JitterEntry(sequence, arrivalTimestampUs, opusData);

        // Update jitter estimate
        // (simplified: real impl would track expected vs actual arrival interval)
    }

    /// <summary>
    /// Try to dequeue the next frame for playback.
    /// Returns null if no frame is ready (caller should generate comfort noise / PLC).
    /// </summary>
    public ReadOnlyMemory<byte>? Pop()
    {
        if (_buffer.Count == 0)
            return null;

        if (_buffer.TryGetValue(_nextExpectedSequence, out var entry))
        {
            _buffer.Remove(_nextExpectedSequence);
            _nextExpectedSequence++;
            return entry.OpusData;
        }

        // Gap: check if we should skip ahead
        var first = _buffer.Keys.First();
        if (first > _nextExpectedSequence)
        {
            // Too many missing frames — skip ahead
            _nextExpectedSequence = first;
            if (_buffer.TryGetValue(first, out var skipped))
            {
                _buffer.Remove(first);
                _nextExpectedSequence++;
                return skipped.OpusData;
            }

            return null;
        }

        return null; // Wait for the expected frame
    }

    public void Reset()
    {
        _buffer.Clear();
        _jitterEstimate = 0;
        _nextExpectedSequence = 0;
    }

    private readonly record struct JitterEntry(
        uint Sequence,
        long ArrivalTimestampUs,
        ReadOnlyMemory<byte> OpusData);
}
