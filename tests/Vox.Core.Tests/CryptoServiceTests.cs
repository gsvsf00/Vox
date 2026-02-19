using Vox.Core.Crypto;

namespace Vox.Core.Tests;

public class LibsodiumCryptoServiceTests
{
    private readonly LibsodiumCryptoService _crypto = new();

    // --- Symmetric encryption ---

    [Fact]
    public void Encrypt_Decrypt_roundtrip()
    {
        var key = _crypto.GenerateSymmetricKey();
        var plaintext = "Hello, Vox!"u8;

        var ciphertext = _crypto.Encrypt(plaintext, key);
        var decrypted = _crypto.Decrypt(ciphertext, key);

        Assert.Equal(plaintext.ToArray(), decrypted);
    }

    [Fact]
    public void Encrypt_produces_different_ciphertext_each_time()
    {
        var key = _crypto.GenerateSymmetricKey();
        var plaintext = "determinism test"u8;

        var ct1 = _crypto.Encrypt(plaintext, key);
        var ct2 = _crypto.Encrypt(plaintext, key);

        Assert.NotEqual(ct1, ct2); // different nonces
    }

    [Fact]
    public void Decrypt_with_wrong_key_throws()
    {
        var key1 = _crypto.GenerateSymmetricKey();
        var key2 = _crypto.GenerateSymmetricKey();
        var ciphertext = _crypto.Encrypt("secret"u8, key1);

        Assert.ThrowsAny<Exception>(() => _crypto.Decrypt(ciphertext, key2));
    }

    [Fact]
    public void Decrypt_tampered_ciphertext_throws()
    {
        var key = _crypto.GenerateSymmetricKey();
        var ciphertext = _crypto.Encrypt("integrity"u8, key);

        // Flip a byte in the encrypted portion (past the nonce)
        ciphertext[^5] ^= 0xFF;

        Assert.ThrowsAny<Exception>(() => _crypto.Decrypt(ciphertext, key));
    }

    [Fact]
    public void Encrypt_empty_plaintext_roundtrips()
    {
        var key = _crypto.GenerateSymmetricKey();
        var ciphertext = _crypto.Encrypt(ReadOnlySpan<byte>.Empty, key);
        var decrypted = _crypto.Decrypt(ciphertext, key);

        Assert.Empty(decrypted);
    }

    // --- Box (asymmetric) ---

    [Fact]
    public void Box_BoxOpen_roundtrip()
    {
        var (alicePub, alicePriv) = _crypto.GenerateX25519Keypair();
        var (bobPub, bobPriv) = _crypto.GenerateX25519Keypair();

        var message = "peer-to-peer"u8;
        var boxed = _crypto.Box(message, bobPub, alicePriv);
        var opened = _crypto.BoxOpen(boxed, alicePub, bobPriv);

        Assert.Equal(message.ToArray(), opened);
    }

    [Fact]
    public void Box_wrong_recipient_key_throws()
    {
        var (alicePub, alicePriv) = _crypto.GenerateX25519Keypair();
        var (bobPub, _) = _crypto.GenerateX25519Keypair();
        var (_, evePriv) = _crypto.GenerateX25519Keypair();

        var boxed = _crypto.Box("secret"u8, bobPub, alicePriv);

        Assert.ThrowsAny<Exception>(() => _crypto.BoxOpen(boxed, alicePub, evePriv));
    }

    // --- Ed25519 signing ---

    [Fact]
    public void Sign_Verify_valid_signature()
    {
        var (pub, priv) = _crypto.GenerateEd25519Keypair();
        var data = "sign this"u8;

        var sig = _crypto.Sign(data, priv);

        Assert.True(_crypto.Verify(data, sig, pub));
    }

    [Fact]
    public void Verify_wrong_key_returns_false()
    {
        var (_, priv) = _crypto.GenerateEd25519Keypair();
        var (wrongPub, _) = _crypto.GenerateEd25519Keypair();
        var data = "message"u8;

        var sig = _crypto.Sign(data, priv);

        Assert.False(_crypto.Verify(data, sig, wrongPub));
    }

    [Fact]
    public void Verify_tampered_data_returns_false()
    {
        var (pub, priv) = _crypto.GenerateEd25519Keypair();
        var data = "original"u8.ToArray();

        var sig = _crypto.Sign(data, priv);
        data[0] ^= 0xFF; // tamper

        Assert.False(_crypto.Verify(data, sig, pub));
    }

    [Fact]
    public void Verify_tampered_signature_returns_false()
    {
        var (pub, priv) = _crypto.GenerateEd25519Keypair();
        var data = "original"u8;

        var sig = _crypto.Sign(data, priv);
        sig[0] ^= 0xFF; // tamper

        Assert.False(_crypto.Verify(data, sig, pub));
    }

    [Fact]
    public void Signature_is_64_bytes()
    {
        var (_, priv) = _crypto.GenerateEd25519Keypair();
        var sig = _crypto.Sign("data"u8, priv);

        Assert.Equal(64, sig.Length);
    }

    // --- BLAKE2b hashing ---

    [Fact]
    public void Hash_deterministic()
    {
        var data = "hash me"u8;
        var h1 = _crypto.Hash(data);
        var h2 = _crypto.Hash(data);

        Assert.Equal(h1, h2);
    }

    [Fact]
    public void Hash_different_output_lengths()
    {
        var data = "hash me"u8;
        var h16 = _crypto.Hash(data, 16);
        var h32 = _crypto.Hash(data, 32);
        var h64 = _crypto.Hash(data, 64);

        Assert.Equal(16, h16.Length);
        Assert.Equal(32, h32.Length);
        Assert.Equal(64, h64.Length);
    }

    [Fact]
    public void Hash_different_inputs_produce_different_outputs()
    {
        var h1 = _crypto.Hash("input1"u8);
        var h2 = _crypto.Hash("input2"u8);

        Assert.NotEqual(h1, h2);
    }

    // --- Key generation ---

    [Fact]
    public void Ed25519_keypair_has_correct_sizes()
    {
        var (pub, priv) = _crypto.GenerateEd25519Keypair();

        Assert.Equal(32, pub.Length);
        Assert.Equal(64, priv.Length);
    }

    [Fact]
    public void X25519_keypair_has_correct_sizes()
    {
        var (pub, priv) = _crypto.GenerateX25519Keypair();

        Assert.Equal(32, pub.Length);
        Assert.Equal(32, priv.Length);
    }

    [Fact]
    public void GenerateRandomBytes_has_correct_length()
    {
        var bytes = _crypto.GenerateRandomBytes(64);
        Assert.Equal(64, bytes.Length);
    }

    [Fact]
    public void GenerateRandomBytes_is_not_deterministic()
    {
        var b1 = _crypto.GenerateRandomBytes(32);
        var b2 = _crypto.GenerateRandomBytes(32);

        Assert.NotEqual(b1, b2);
    }
}
