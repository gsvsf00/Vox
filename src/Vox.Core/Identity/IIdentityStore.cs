using Vox.Core.Crypto;

namespace Vox.Core.Identity;

/// <summary>
/// Abstraction for identity persistence.
/// The default implementation stores keys encrypted on disk.
/// </summary>
public interface IIdentityStore
{
    LocalIdentity? Load(ICryptoService crypto, string? password = null);
    void Save(LocalIdentity identity, ICryptoService crypto, string? password = null);
}
