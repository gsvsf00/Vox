namespace Vox.Core.Configuration;

/// <summary>
/// Application-wide configuration constants and defaults.
/// </summary>
public static class VoxDefaults
{
    // --- Audio ---
    public const int AudioSampleRate = 48_000;
    public const int AudioFrameDurationMs = 20;
    public const int AudioSamplesPerFrame = AudioSampleRate * AudioFrameDurationMs / 1000; // 960
    public const int AudioChannels = 1;
    public const int OpusBitrateDefault = 32_000;
    public const int OpusComplexityDefault = 5;

    // --- Routing ---
    public const int ProbeIntervalMs = 1_000;
    public const int RouteRecomputeIntervalMs = 10_000;
    public const int LinkDownThreshold = 3; // consecutive failed probes
    public const int LinkUpThreshold = 5;   // consecutive successful probes
    public const int RouteDampeningMs = 500;

    // --- Mesh ---
    public const int MaxTtl = 7;
    public const int SeenCacheCapacity = 8192;
    public const int SeenCacheTtlSeconds = 5;
    public const int FullMeshThreshold = 5; // use full mesh if group size <= this

    // --- Jitter buffer ---
    public const int JitterBufferMinMs = 20;
    public const int JitterBufferInitialMs = 60;
    public const int JitterBufferMaxMs = 200;

    // --- Handshake ---
    public const int KnockTimeoutMs = 5_000;
    public const int WgHandshakeTimeoutMs = 5_000;
    public const int TimestampToleranceMs = 30_000;

    // --- Chat ---
    public const int MaxChatMessageBytes = 4_000;

    // --- Protocol ---
    public const uint KnockMagic = 0x564F5801;
    public const uint KnockAcceptMagic = 0x564F5802;
    public const byte ProtocolVersion = 0x01;
}
