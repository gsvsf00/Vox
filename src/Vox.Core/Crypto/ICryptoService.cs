namespace Vox.Core.Crypto;

/// <summary>
/// Cryptographic primitives backed by libsodium (or managed fallback).
/// All byte arrays returned are freshly allocated — callers own them.
/// </summary>
public interface ICryptoService
{
    // --- Symmetric (XChaCha20-Poly1305) ---

    byte[] Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key);
    byte[] Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> key);

    // --- Asymmetric box (X25519 DH + XChaCha20-Poly1305) ---

    byte[] Box(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> recipientPublicKey, ReadOnlySpan<byte> senderPrivateKey);
    byte[] BoxOpen(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> senderPublicKey, ReadOnlySpan<byte> recipientPrivateKey);

    // --- Signing (Ed25519) ---

    byte[] Sign(ReadOnlySpan<byte> data, ReadOnlySpan<byte> privateKey);
    bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKey);

    // --- Hashing (BLAKE2b) ---

    byte[] Hash(ReadOnlySpan<byte> data, int outputLength = 32);

    // --- Key generation ---

    (byte[] PublicKey, byte[] PrivateKey) GenerateEd25519Keypair();
    (byte[] PublicKey, byte[] PrivateKey) GenerateX25519Keypair();
    byte[] GenerateSymmetricKey(int length = 32);
    byte[] GenerateRandomBytes(int length);
}
