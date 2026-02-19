namespace Vox.Core.Identity;

public interface IIdentityService
{
    /// <summary>
    /// Load existing identity from disk or create a new one.
    /// </summary>
    LocalIdentity GetOrCreateIdentity(string username);

    /// <summary>
    /// Sign data with the local identity's Ed25519 private key.
    /// </summary>
    byte[] Sign(ReadOnlySpan<byte> data);

    /// <summary>
    /// Verify an Ed25519 signature against a public key.
    /// </summary>
    bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature);
}
