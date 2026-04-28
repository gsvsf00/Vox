namespace Vox.Voice;

/// <summary>
/// Platform-abstracted audio device enumeration and selection.
/// </summary>
public interface IAudioDeviceService
{
    IReadOnlyList<AudioDevice> GetCaptureDevices();
    IReadOnlyList<AudioDevice> GetPlaybackDevices();
    AudioDevice GetDefaultCaptureDevice();
    AudioDevice GetDefaultPlaybackDevice();
    void SetCaptureDevice(AudioDevice device);
    void SetPlaybackDevice(AudioDevice device);
    event Action? DevicesChanged;
}

public sealed record AudioDevice(string Id, string Name, bool IsDefault);
