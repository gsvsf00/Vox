using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Geralt;
using Vox.Core.Crypto;

namespace Vox.Core.Identity;

/// <summary>
/// Stores the local identity on disk.
/// 
/// Layout:
///   {baseDir}/
///     profile.json        — username, discriminator, creation date, public keys (plaintext)
///     identity.key        — private keys, encrypted if a password was provided
/// 
/// When a password is provided:
///   identity.key = salt (16 bytes) ‖ XChaCha20-Poly1305(private_keys, Argon2id(password, salt))
///   Argon2id params: 3 iterations, 64 MiB — resistant to offline brute-force.
/// 
/// When no password is provided:
///   identity.key = raw private key bytes (96 bytes). The caller is responsible for
///   filesystem-level protection (OS permissions, full-disk encryption, etc.).
/// </summary>
public sealed class FileIdentityStore : IIdentityStore
{
    private const int PrivateKeyBlobSize = 96; // 64 (Ed25519) + 32 (X25519)
    private const int Argon2Iterations = 3;
    private const int Argon2MemorySize = 67_108_864; // 64 MiB

    private readonly string _baseDir;

    public FileIdentityStore(string baseDir)
    {
        _baseDir = baseDir;
    }

    public LocalIdentity? Load(ICryptoService crypto, string? password = null)
    {
        var profilePath = Path.Combine(_baseDir, "profile.json");
        var keyPath = Path.Combine(_baseDir, "identity.key");

        if (!File.Exists(profilePath) || !File.Exists(keyPath))
            return null;

        var profileJson = File.ReadAllText(profilePath);
        var profile = JsonSerializer.Deserialize<IdentityProfile>(profileJson);
        if (profile is null)
            return null;

        var sigPub = Convert.FromBase64String(profile.SigningPublicKey);
        var encPub = Convert.FromBase64String(profile.EncryptionPublicKey);

        var keyBlob = File.ReadAllBytes(keyPath);
        byte[] privateKeys;

        if (profile.PasswordProtected)
        {
            if (string.IsNullOrEmpty(password))
                throw new InvalidOperationException("This identity is password-protected. A password is required to unlock it.");

            if (keyBlob.Length < Argon2id.SaltSize)
                throw new InvalidOperationException("Key file is too short — storage may be corrupted.");

            var salt = keyBlob.AsSpan(0, Argon2id.SaltSize);
            var ciphertext = keyBlob.AsSpan(Argon2id.SaltSize);

            var storageKey = DeriveKeyFromPassword(password, salt);
            try
            {
                privateKeys = crypto.Decrypt(ciphertext, storageKey);
            }
            catch
            {
                throw new InvalidOperationException("Failed to decrypt identity keys. Wrong password or corrupted storage.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(storageKey);
            }
        }
        else
        {
            privateKeys = keyBlob;
        }

        if (privateKeys.Length != PrivateKeyBlobSize)
            throw new InvalidOperationException("Decrypted key material has unexpected length.");

        var sigPriv = privateKeys[..64];
        var encPriv = privateKeys[64..96];

        return new LocalIdentity
        {
            Username = profile.Username,
            Discriminator = profile.Discriminator,
            SigningPublicKey = sigPub,
            SigningPrivateKey = sigPriv,
            EncryptionPublicKey = encPub,
            EncryptionPrivateKey = encPriv,
            CreatedAt = profile.CreatedAt,
        };
    }

    public void Save(LocalIdentity identity, ICryptoService crypto, string? password = null)
    {
        Directory.CreateDirectory(_baseDir);

        bool passwordProtected = !string.IsNullOrEmpty(password);

        var profile = new IdentityProfile
        {
            Username = identity.Username,
            Discriminator = identity.Discriminator,
            SigningPublicKey = Convert.ToBase64String(identity.SigningPublicKey),
            EncryptionPublicKey = Convert.ToBase64String(identity.EncryptionPublicKey),
            CreatedAt = identity.CreatedAt,
            PasswordProtected = passwordProtected,
        };

        var profileJson = JsonSerializer.Serialize(profile, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(Path.Combine(_baseDir, "profile.json"), profileJson);

        var privateKeys = new byte[PrivateKeyBlobSize];
        identity.SigningPrivateKey.CopyTo(privateKeys, 0);
        identity.EncryptionPrivateKey.CopyTo(privateKeys, 64);

        byte[] keyBlob;
        if (passwordProtected)
        {
            var salt = new byte[Argon2id.SaltSize];
            SecureRandom.Fill(salt);

            var storageKey = DeriveKeyFromPassword(password!, salt);
            try
            {
                var encrypted = crypto.Encrypt(privateKeys, storageKey);
                keyBlob = new byte[salt.Length + encrypted.Length];
                salt.CopyTo(keyBlob, 0);
                encrypted.CopyTo(keyBlob, salt.Length);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(storageKey);
            }
        }
        else
        {
            keyBlob = privateKeys;
        }

        File.WriteAllBytes(Path.Combine(_baseDir, "identity.key"), keyBlob);

        Array.Clear(privateKeys);
    }

    private static byte[] DeriveKeyFromPassword(string password, ReadOnlySpan<byte> salt)
    {
        var key = new byte[Argon2id.KeySize]; // 32 bytes
        var passwordBytes = Encoding.UTF8.GetBytes(password);
        try
        {
            Argon2id.DeriveKey(key, passwordBytes, salt, Argon2Iterations, Argon2MemorySize);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
        return key;
    }

    private sealed class IdentityProfile
    {
        public string Username { get; set; } = "";
        public ushort Discriminator { get; set; }
        public string SigningPublicKey { get; set; } = "";
        public string EncryptionPublicKey { get; set; } = "";
        public DateTimeOffset CreatedAt { get; set; }
        public bool PasswordProtected { get; set; }
    }
}
