namespace Vox.Core.Plugins;

/// <summary>
/// Adds a section to the settings view.
/// Registered via DI as IEnumerable&lt;ISettingsSectionProvider&gt;.
/// </summary>
public interface ISettingsSectionProvider
{
    /// <summary>Section label displayed in the settings sidebar.</summary>
    string Label { get; }

    /// <summary>Order within the settings list (lower = earlier).</summary>
    int Order { get; }

    /// <summary>Blazor component type to render as the settings section body.</summary>
    Type ComponentType { get; }
}
