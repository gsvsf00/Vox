using System.IO.Compression;

namespace Vox.Core.Crypto;

/// <summary>
/// Capsule type discriminator (second byte of the cleartext envelope).
/// </summary>
public enum CapsuleType : byte
{
    GroupInvite = 0x01,
    ContactInvite = 0x02,
}

/// <summary>
/// Unified encoding pipeline for all shareable Vox links.
/// Pipeline: Serialize → prefix(version+type) → GZIP → Encrypt(AEAD) → Base64URL(no padding).
/// </summary>
public static class CapsuleCodec
{
    /// <summary>Current capsule envelope version.</summary>
    public const byte Version = 0x01;

    /// <summary>
    /// Well-known encryption key for ContactInvite capsules (no shared secret).
    /// Precomputed BLAKE2b-256("vox-contact-capsule-v1").
    /// Contact links contain only public info; the signature provides integrity.
    /// </summary>
    public static ReadOnlySpan<byte> ContactCapsuleKey =>
    [
        0xC3, 0x4A, 0xB5, 0x19, 0xE7, 0x6D, 0x02, 0xF8,
        0x91, 0x3C, 0xA7, 0x54, 0xDE, 0x80, 0x1B, 0x63,
        0x47, 0xF2, 0x0E, 0x9A, 0xBC, 0x55, 0xD1, 0x78,
        0x2F, 0x64, 0xE3, 0x06, 0x8B, 0xA9, 0x40, 0xCD,
    ];

    /// <summary>
    /// Encode a payload into a self-contained capsule token.
    /// </summary>
    /// <param name="type">Capsule type discriminator.</param>
    /// <param name="payload">Serialized payload bytes (e.g. InviteCapsule binary).</param>
    /// <param name="key">32-byte symmetric key for AEAD encryption.</param>
    /// <param name="crypto">Crypto service for AEAD encryption.</param>
    /// <returns>Base64URL-encoded token (no padding, URL-safe).</returns>
    public static string Encode(CapsuleType type, ReadOnlySpan<byte> payload, ReadOnlySpan<byte> key, ICryptoService crypto)
    {
        // 1. Prefix: version(1) + type(1) + payload
        var envelopeLength = 2 + payload.Length;
        var envelope = new byte[envelopeLength];
        envelope[0] = Version;
        envelope[1] = (byte)type;
        payload.CopyTo(envelope.AsSpan(2));

        // 2. GZIP compress
        var compressed = GzipCompress(envelope);

        // 3. Encrypt (AEAD — XChaCha20-Poly1305)
        var encrypted = crypto.Encrypt(compressed, key);

        // 4. Base64URL encode (no padding)
        return Base64UrlEncode(encrypted);
    }

    /// <summary>
    /// Decode a capsule token back to type + payload.
    /// </summary>
    /// <param name="token">Base64URL-encoded token (no padding).</param>
    /// <param name="key">32-byte symmetric key for AEAD decryption.</param>
    /// <param name="crypto">Crypto service for AEAD decryption.</param>
    /// <returns>The capsule type and raw payload bytes.</returns>
    /// <exception cref="FormatException">Token is malformed or decryption failed.</exception>
    public static (CapsuleType Type, byte[] Payload) Decode(string token, ReadOnlySpan<byte> key, ICryptoService crypto)
    {
        // 1. Base64URL decode
        var encrypted = Base64UrlDecode(token);

        // 2. Decrypt
        byte[] compressed;
        try
        {
            compressed = crypto.Decrypt(encrypted, key);
        }
        catch (Exception ex)
        {
            throw new FormatException("Capsule decryption failed.", ex);
        }

        // 3. GZIP decompress
        var envelope = GzipDecompress(compressed);

        // 4. Parse version + type
        if (envelope.Length < 2)
            throw new FormatException("Capsule envelope too short.");

        var version = envelope[0];
        if (version != Version)
            throw new FormatException($"Unsupported capsule version {version}.");

        var type = (CapsuleType)envelope[1];

        // 5. Extract payload
        var payload = envelope[2..];

        return (type, payload);
    }

    // ── Base64URL helpers (public, reusable) ────────────────

    public static string Base64UrlEncode(ReadOnlySpan<byte> data) =>
        Convert.ToBase64String(data)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    public static byte[] Base64UrlDecode(string encoded)
    {
        var s = encoded.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4)
        {
            case 2: s += "=="; break;
            case 3: s += "="; break;
        }
        return Convert.FromBase64String(s);
    }

    // ── GZIP helpers ─────────────────────────────────────

    private static byte[] GzipCompress(byte[] data)
    {
        using var output = new MemoryStream();
        using (var gzip = new GZipStream(output, CompressionLevel.SmallestSize))
        {
            gzip.Write(data);
        }
        return output.ToArray();
    }

    private static byte[] GzipDecompress(byte[] data)
    {
        using var input = new MemoryStream(data);
        using var gzip = new GZipStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        gzip.CopyTo(output);
        return output.ToArray();
    }
}
