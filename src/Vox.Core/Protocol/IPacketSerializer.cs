namespace Vox.Core.Protocol;

/// <summary>
/// Zero-allocation packet serializer contract.
/// Implementations use Span&lt;byte&gt; for hot-path serialization.
/// </summary>
public interface IPacketSerializer<T> where T : struct
{
    int Serialize(in T packet, Span<byte> buffer);
    T Deserialize(ReadOnlySpan<byte> buffer);
    int GetSerializedSize(in T packet);
}
