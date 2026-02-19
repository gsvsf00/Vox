using Vox.Core.Groups;

namespace Vox.Voice;

/// <summary>
/// Orchestrates the full voice pipeline: capture → denoise → encode → send + receive → decode → mix → play.
/// One instance per active voice session.
/// </summary>
public interface IVoicePipeline
{
    Task StartAsync(VoiceSessionConfig config, CancellationToken ct = default);
    Task StopAsync();
    bool IsSpeaking { get; }
    void SetPushToTalk(bool pressed);
    void SetMicDevice(AudioDevice device);
    void SetSpeakerDevice(AudioDevice device);
    void SetNoiseSuppression(bool enabled);
    IObservable<VoicePipelineStats> Stats { get; }
}

public sealed record VoiceSessionConfig(
    GroupId GroupId,
    byte ChannelId,
    bool PushToTalk,
    bool NoiseSuppression,
    int OpusBitrate = 32_000);

public sealed class VoicePipelineStats
{
    public double CaptureLatencyMs { get; set; }
    public double EncodeLatencyMs { get; set; }
    public double DecodeLatencyMs { get; set; }
    public double JitterBufferDepthMs { get; set; }
    public double MixingLatencyMs { get; set; }
    public int DroppedFrames { get; set; }
    public int RelayedFrames { get; set; }
    public double OutgoingBitrateKbps { get; set; }
    public double IncomingBitrateKbps { get; set; }
}
