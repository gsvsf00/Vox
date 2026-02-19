namespace Vox.Core.Observable;

/// <summary>
/// Thread-safe multicast IObservable implementation.
/// Minimal replacement for System.Reactive's Subject&lt;T&gt;.
/// </summary>
public sealed class EventSubject<T> : IObservable<T>, IDisposable
{
    private readonly List<IObserver<T>> _observers = [];
    private readonly object _lock = new();
    private bool _disposed;

    public IDisposable Subscribe(IObserver<T> observer)
    {
        lock (_lock)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(EventSubject<T>));
            _observers.Add(observer);
        }
        return new Subscription(this, observer);
    }

    public void OnNext(T value)
    {
        IObserver<T>[] snapshot;
        lock (_lock) snapshot = [.. _observers];

        foreach (var observer in snapshot)
        {
            try { observer.OnNext(value); }
            catch (Exception ex) { observer.OnError(ex); }
        }
    }

    public void Dispose()
    {
        IObserver<T>[] snapshot;
        lock (_lock)
        {
            if (_disposed) return;
            _disposed = true;
            snapshot = [.. _observers];
            _observers.Clear();
        }

        foreach (var observer in snapshot)
        {
            try { observer.OnCompleted(); }
            catch { /* ensure all observers are notified */ }
        }
    }

    private void Remove(IObserver<T> observer)
    {
        lock (_lock) _observers.Remove(observer);
    }

    private sealed class Subscription(EventSubject<T> subject, IObserver<T> observer) : IDisposable
    {
        public void Dispose() => subject.Remove(observer);
    }
}
