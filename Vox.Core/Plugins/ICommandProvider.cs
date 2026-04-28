namespace Vox.Core.Plugins;

/// <summary>
/// Provides slash-commands (e.g. /nick, /status) for the chat input.
/// Registered via DI as IEnumerable&lt;ICommandProvider&gt;.
/// </summary>
public interface ICommandProvider
{
    /// <summary>Command name without the leading '/'.</summary>
    string Name { get; }

    /// <summary>Short description shown in autocomplete.</summary>
    string Description { get; }

    /// <summary>Execute the command with the given argument text.</summary>
    Task ExecuteAsync(string arguments);
}
