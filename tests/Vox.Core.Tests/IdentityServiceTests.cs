using Vox.Core.Crypto;
using Vox.Core.Identity;

namespace Vox.Core.Tests;

public class IdentityServiceTests : IDisposable
{
    private readonly string _tempDir;
    private readonly ICryptoService _crypto;

    public IdentityServiceTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "vox-test-" + Guid.NewGuid().ToString("N")[..8]);
        _crypto = new LibsodiumCryptoService();
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, recursive: true);
    }

    private IdentityService CreateService() =>
        new(_crypto, new FileIdentityStore(_tempDir));

    [Fact]
    public void GetOrCreateIdentity_creates_new_identity()
    {
        var svc = CreateService();
        var identity = svc.GetOrCreateIdentity("Alice");

        Assert.Equal("Alice", identity.Username);
        Assert.InRange(identity.Discriminator, (ushort)0, (ushort)9999);
        Assert.Equal(32, identity.SigningPublicKey.Length);
        Assert.Equal(64, identity.SigningPrivateKey.Length);
        Assert.Equal(32, identity.EncryptionPublicKey.Length);
        Assert.Equal(32, identity.EncryptionPrivateKey.Length);
    }

    [Fact]
    public void GetOrCreateIdentity_returns_same_instance_on_second_call()
    {
        var svc = CreateService();
        var id1 = svc.GetOrCreateIdentity("Alice");
        var id2 = svc.GetOrCreateIdentity("Alice");

        Assert.Same(id1, id2);
    }

    [Fact]
    public void Identity_persists_and_loads_across_instances()
    {
        // Create identity (no password — plaintext keys)
        var svc1 = CreateService();
        var original = svc1.GetOrCreateIdentity("Bob");

        // Load from new service pointing at same directory
        var svc2 = CreateService();
        var loaded = svc2.GetOrCreateIdentity("Ignored"); // username ignored on load

        Assert.Equal(original.Username, loaded.Username);
        Assert.Equal(original.Discriminator, loaded.Discriminator);
        Assert.Equal(original.SigningPublicKey, loaded.SigningPublicKey);
        Assert.Equal(original.SigningPrivateKey, loaded.SigningPrivateKey);
        Assert.Equal(original.EncryptionPublicKey, loaded.EncryptionPublicKey);
        Assert.Equal(original.EncryptionPrivateKey, loaded.EncryptionPrivateKey);
    }

    [Fact]
    public void Identity_with_password_persists_and_loads()
    {
        var svc1 = CreateService();
        var original = svc1.GetOrCreateIdentity("Secure", "hunter2");

        var svc2 = CreateService();
        var loaded = svc2.GetOrCreateIdentity("Ignored", "hunter2");

        Assert.Equal(original.Username, loaded.Username);
        Assert.Equal(original.SigningPrivateKey, loaded.SigningPrivateKey);
        Assert.Equal(original.EncryptionPrivateKey, loaded.EncryptionPrivateKey);
    }

    [Fact]
    public void Identity_with_password_wrong_password_throws()
    {
        var svc1 = CreateService();
        svc1.GetOrCreateIdentity("Locked", "correctPassword");

        var svc2 = CreateService();
        Assert.Throws<InvalidOperationException>(() =>
            svc2.GetOrCreateIdentity("Ignored", "wrongPassword"));
    }

    [Fact]
    public void Identity_with_password_no_password_on_load_throws()
    {
        var svc1 = CreateService();
        svc1.GetOrCreateIdentity("Locked", "myPassword");

        var svc2 = CreateService();
        Assert.Throws<InvalidOperationException>(() =>
            svc2.GetOrCreateIdentity("Ignored")); // no password
    }

    [Fact]
    public void Identity_without_password_stores_plaintext_keys()
    {
        var svc = CreateService();
        var identity = svc.GetOrCreateIdentity("Plain");

        var keyBlob = File.ReadAllBytes(Path.Combine(_tempDir, "identity.key"));
        // Without password, key file is raw 96 bytes (64 + 32)
        Assert.Equal(96, keyBlob.Length);
    }

    [Fact]
    public void Identity_files_are_created_on_disk()
    {
        var svc = CreateService();
        svc.GetOrCreateIdentity("Charlie");

        Assert.True(File.Exists(Path.Combine(_tempDir, "profile.json")));
        Assert.True(File.Exists(Path.Combine(_tempDir, "identity.key")));
    }

    [Fact]
    public void DisplayName_format_is_correct()
    {
        var svc = CreateService();
        var identity = svc.GetOrCreateIdentity("Delta");

        // Should match Username#0000-9999
        Assert.Matches(@"^Delta#\d{4}$", identity.DisplayName);
    }

    [Fact]
    public void PeerId_derived_from_signing_public_key()
    {
        var svc = CreateService();
        var identity = svc.GetOrCreateIdentity("Echo");

        Assert.Equal(identity.SigningPublicKey, identity.PeerId.PublicKey.ToArray());
    }

    [Fact]
    public void Sign_produces_valid_signature()
    {
        var svc = CreateService();
        var identity = svc.GetOrCreateIdentity("Foxtrot");

        var data = "test message"u8;
        var sig = svc.Sign(data);

        Assert.True(svc.Verify(identity.SigningPublicKey, data, sig));
    }

    [Fact]
    public void Sign_before_identity_loaded_throws()
    {
        var svc = CreateService();

        Assert.Throws<InvalidOperationException>(() => svc.Sign("data"u8));
    }

    [Fact]
    public void Verify_with_wrong_data_returns_false()
    {
        var svc = CreateService();
        var identity = svc.GetOrCreateIdentity("Golf");

        var sig = svc.Sign("original"u8);

        Assert.False(svc.Verify(identity.SigningPublicKey, "modified"u8, sig));
    }

    // --- Username validation ---

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    public void Username_empty_or_whitespace_throws(string username)
    {
        var svc = CreateService();
        Assert.ThrowsAny<ArgumentException>(() => svc.GetOrCreateIdentity(username));
    }

    [Fact]
    public void Username_with_hash_throws()
    {
        var svc = CreateService();
        Assert.Throws<ArgumentException>(() => svc.GetOrCreateIdentity("Bad#Name"));
    }

    [Fact]
    public void Username_too_short_throws()
    {
        var svc = CreateService();
        Assert.Throws<ArgumentException>(() => svc.GetOrCreateIdentity("A"));
    }

    [Fact]
    public void Username_too_long_throws()
    {
        var svc = CreateService();
        Assert.Throws<ArgumentException>(() => svc.GetOrCreateIdentity(new string('X', 33)));
    }

    [Fact]
    public void Username_at_boundary_2_chars_works()
    {
        var svc = CreateService();
        var identity = svc.GetOrCreateIdentity("AB");
        Assert.Equal("AB", identity.Username);
    }

    [Fact]
    public void Username_at_boundary_32_chars_works()
    {
        var svc = CreateService();
        var identity = svc.GetOrCreateIdentity(new string('X', 32));
        Assert.Equal(32, identity.Username.Length);
    }
}
