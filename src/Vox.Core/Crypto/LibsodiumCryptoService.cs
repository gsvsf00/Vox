using System.Security.Cryptography;
using Geralt;

namespace Vox.Core.Crypto;

/// <summary>
/// ICryptoService implementation backed by libsodium via Geralt.
/// All methods are stateless and thread-safe.
/// </summary>
public sealed class LibsodiumCryptoService : ICryptoService
{
    // --- Symmetric AEAD (XChaCha20-Poly1305) ---

    public byte[] Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key)
    {
        Span<byte> nonce = stackalloc byte[XChaCha20Poly1305.NonceSize];
        SecureRandom.Fill(nonce);

        var ciphertext = new byte[nonce.Length + plaintext.Length + XChaCha20Poly1305.TagSize];
        nonce.CopyTo(ciphertext);

        XChaCha20Poly1305.Encrypt(
            ciphertext.AsSpan(nonce.Length),
            plaintext,
            nonce,
            key);

        return ciphertext;
    }

    public byte[] Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> key)
    {
        if (ciphertext.Length < XChaCha20Poly1305.NonceSize + XChaCha20Poly1305.TagSize)
            throw new CryptographicException("Ciphertext too short.");

        var nonce = ciphertext[..XChaCha20Poly1305.NonceSize];
        var encrypted = ciphertext[XChaCha20Poly1305.NonceSize..];
        var plaintext = new byte[encrypted.Length - XChaCha20Poly1305.TagSize];

        XChaCha20Poly1305.Decrypt(plaintext, encrypted, nonce, key);

        return plaintext;
    }

    // --- Asymmetric box (X25519 DH + XChaCha20-Poly1305) ---

    public byte[] Box(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> recipientPublicKey, ReadOnlySpan<byte> senderPrivateKey)
    {
        Span<byte> nonce = stackalloc byte[XChaCha20Poly1305.NonceSize];
        SecureRandom.Fill(nonce);

        Span<byte> sharedKey = stackalloc byte[32];
        X25519.ComputeSharedSecret(sharedKey, senderPrivateKey, recipientPublicKey);

        var result = new byte[XChaCha20Poly1305.NonceSize + plaintext.Length + XChaCha20Poly1305.TagSize];
        nonce.CopyTo(result);

        XChaCha20Poly1305.Encrypt(
            result.AsSpan(XChaCha20Poly1305.NonceSize),
            plaintext,
            nonce,
            sharedKey);

        CryptographicOperations.ZeroMemory(sharedKey);
        return result;
    }

    public byte[] BoxOpen(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> senderPublicKey, ReadOnlySpan<byte> recipientPrivateKey)
    {
        if (ciphertext.Length < XChaCha20Poly1305.NonceSize + XChaCha20Poly1305.TagSize)
            throw new CryptographicException("Box ciphertext too short.");

        var nonce = ciphertext[..XChaCha20Poly1305.NonceSize];
        var encrypted = ciphertext[XChaCha20Poly1305.NonceSize..];

        Span<byte> sharedKey = stackalloc byte[32];
        X25519.ComputeSharedSecret(sharedKey, recipientPrivateKey, senderPublicKey);

        var plaintext = new byte[encrypted.Length - XChaCha20Poly1305.TagSize];
        XChaCha20Poly1305.Decrypt(plaintext, encrypted, nonce, sharedKey);

        CryptographicOperations.ZeroMemory(sharedKey);
        return plaintext;
    }

    // --- Signing (Ed25519) ---

    public byte[] Sign(ReadOnlySpan<byte> data, ReadOnlySpan<byte> privateKey)
    {
        var signature = new byte[Ed25519.SignatureSize];
        Ed25519.Sign(signature, data, privateKey);
        return signature;
    }

    public bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKey)
    {
        try
        {
            return Ed25519.Verify(signature, data, publicKey);
        }
        catch
        {
            return false;
        }
    }

    // --- Hashing (BLAKE2b) ---

    public byte[] Hash(ReadOnlySpan<byte> data, int outputLength = 32)
    {
        var hash = new byte[outputLength];
        BLAKE2b.ComputeHash(hash, data);
        return hash;
    }

    // --- Key generation ---

    public (byte[] PublicKey, byte[] PrivateKey) GenerateEd25519Keypair()
    {
        var publicKey = new byte[Ed25519.PublicKeySize];
        var privateKey = new byte[Ed25519.PrivateKeySize];
        Ed25519.GenerateKeyPair(publicKey, privateKey);
        return (publicKey, privateKey);
    }

    public (byte[] PublicKey, byte[] PrivateKey) GenerateX25519Keypair()
    {
        var publicKey = new byte[X25519.PublicKeySize];
        var privateKey = new byte[X25519.PrivateKeySize];
        X25519.GenerateKeyPair(publicKey, privateKey);
        return (publicKey, privateKey);
    }

    public byte[] GenerateSymmetricKey(int length = 32)
    {
        var key = new byte[length];
        SecureRandom.Fill(key);
        return key;
    }

    public byte[] GenerateRandomBytes(int length)
    {
        var bytes = new byte[length];
        SecureRandom.Fill(bytes);
        return bytes;
    }
}


