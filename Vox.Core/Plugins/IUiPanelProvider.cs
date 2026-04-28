namespace Vox.Core.Plugins;

/// <summary>
/// Injects a panel into a named slot in the UI layout.
/// Registered via DI as IEnumerable&lt;IUiPanelProvider&gt;.
/// </summary>
public interface IUiPanelProvider
{
    /// <summary>Target slot name, e.g. "right-sidebar", "footer".</summary>
    string SlotName { get; }

    /// <summary>Order within the slot (lower = earlier).</summary>
    int Order { get; }

    /// <summary>Blazor component type to render in the slot.</summary>
    Type ComponentType { get; }
}
