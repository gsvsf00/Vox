namespace Vox.Core.Plugins;

/// <summary>
/// Custom renderer for chat messages.
/// The first renderer whose <see cref="CanRender"/> returns true is used.
/// Registered via DI as IEnumerable&lt;IMessageRenderer&gt;.
/// </summary>
public interface IMessageRenderer
{
    /// <summary>Priority (lower = checked first).</summary>
    int Priority { get; }

    /// <summary>Whether this renderer handles the given message content.</summary>
    bool CanRender(string content);

    /// <summary>Blazor component type to render the message.</summary>
    Type ComponentType { get; }
}
