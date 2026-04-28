namespace Vox.Core.Identity;

/// <summary>
/// The local user's identity: keypairs + display profile.
/// </summary>
public sealed class LocalIdentity
{
    /// <summary>Display name (2-32 chars, no '#').</summary>
    public required string Username { get; init; }

    /// <summary>4-digit zero-padded discriminator (0000-9999).</summary>
    public required ushort Discriminator { get; init; }

    /// <summary>Ed25519 public key (32 bytes) — canonical identity.</summary>
    public required byte[] SigningPublicKey { get; init; }

    /// <summary>Ed25519 private key (64 bytes).</summary>
    public required byte[] SigningPrivateKey { get; init; }

    /// <summary>X25519 public key (32 bytes) — derived for encryption.</summary>
    public required byte[] EncryptionPublicKey { get; init; }

    /// <summary>X25519 private key (32 bytes).</summary>
    public required byte[] EncryptionPrivateKey { get; init; }

    public PeerId PeerId => new(SigningPublicKey);

    public string DisplayName => Username;

    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;
}
