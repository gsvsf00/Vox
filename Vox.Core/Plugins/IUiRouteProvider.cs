namespace Vox.Core.Plugins;

/// <summary>
/// Provides additional navigable routes to the UI shell.
/// Registered via DI as IEnumerable&lt;IUiRouteProvider&gt;.
/// </summary>
public interface IUiRouteProvider
{
    /// <summary>Route path, e.g. "/settings/my-plugin".</summary>
    string Route { get; }

    /// <summary>Display label shown in navigation.</summary>
    string Label { get; }

    /// <summary>Optional icon name (CSS class or SVG id).</summary>
    string? Icon { get; }

    /// <summary>Blazor component type to render for this route.</summary>
    Type ComponentType { get; }
}
