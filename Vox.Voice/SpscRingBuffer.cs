namespace Vox.Voice;

/// <summary>
/// Lock-free single-producer single-consumer ring buffer for audio samples.
/// Pre-allocated; no heap allocation during read/write.
/// </summary>
public sealed class SpscRingBuffer<T> where T : unmanaged
{
    private readonly T[] _buffer;
    private volatile int _readPos;
    private volatile int _writePos;

    public int Capacity { get; }

    public SpscRingBuffer(int capacity)
    {
        Capacity = capacity;
        _buffer = new T[capacity];
    }

    public int AvailableRead
    {
        get
        {
            var w = _writePos;
            var r = _readPos;
            return w >= r ? w - r : Capacity - r + w;
        }
    }

    public int AvailableWrite
    {
        get => Capacity - 1 - AvailableRead;
    }

    public bool TryWrite(ReadOnlySpan<T> data)
    {
        if (data.Length > AvailableWrite)
            return false;

        var writePos = _writePos;
        foreach (var item in data)
        {
            _buffer[writePos] = item;
            writePos = (writePos + 1) % Capacity;
        }
        _writePos = writePos;
        return true;
    }

    public int Read(Span<T> output)
    {
        var available = Math.Min(output.Length, AvailableRead);
        for (int i = 0; i < available; i++)
        {
            output[i] = _buffer[_readPos];
            _readPos = (_readPos + 1) % Capacity;
        }
        return available;
    }
}
