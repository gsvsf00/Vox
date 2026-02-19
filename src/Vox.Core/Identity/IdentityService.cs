using System.Text.Json;
using Vox.Core.Crypto;

namespace Vox.Core.Identity;

/// <summary>
/// Manages local identity: create-or-load from encrypted storage,
/// sign data, verify signatures.
/// </summary>
public sealed class IdentityService : IIdentityService
{
    private readonly ICryptoService _crypto;
    private readonly IIdentityStore _store;
    private LocalIdentity? _identity;
    private readonly object _lock = new();

    public IdentityService(ICryptoService crypto, IIdentityStore store)
    {
        _crypto = crypto;
        _store = store;
    }

    public LocalIdentity GetOrCreateIdentity(string username, string? password = null)
    {
        lock (_lock)
        {
            if (_identity is not null)
                return _identity;

            // Try to load existing identity
            var loaded = _store.Load(_crypto, password);
            if (loaded is not null)
            {
                _identity = loaded;
                return _identity;
            }

            // Generate new identity
            var (sigPub, sigPriv) = _crypto.GenerateEd25519Keypair();
            var (encPub, encPriv) = _crypto.GenerateX25519Keypair();
            var discriminator = GenerateDiscriminator();

            _identity = new LocalIdentity
            {
                Username = ValidateUsername(username),
                Discriminator = discriminator,
                SigningPublicKey = sigPub,
                SigningPrivateKey = sigPriv,
                EncryptionPublicKey = encPub,
                EncryptionPrivateKey = encPriv,
                CreatedAt = DateTimeOffset.UtcNow,
            };

            _store.Save(_identity, _crypto, password);
            return _identity;
        }
    }

    public byte[] Sign(ReadOnlySpan<byte> data)
    {
        var identity = _identity ?? throw new InvalidOperationException("Identity not loaded.");
        return _crypto.Sign(data, identity.SigningPrivateKey);
    }

    public bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        return _crypto.Verify(data, signature, publicKey);
    }

    private ushort GenerateDiscriminator()
    {
        var bytes = _crypto.GenerateRandomBytes(2);
        return (ushort)(BitConverter.ToUInt16(bytes) % 10000);
    }

    private static string ValidateUsername(string username)
    {
        if (string.IsNullOrWhiteSpace(username))
            throw new ArgumentException("Username cannot be empty.", nameof(username));
        if (username.Length < 2 || username.Length > 32)
            throw new ArgumentException("Username must be 2-32 characters.", nameof(username));
        if (username.Contains('#'))
            throw new ArgumentException("Username cannot contain '#'.", nameof(username));
        return username;
    }
}
