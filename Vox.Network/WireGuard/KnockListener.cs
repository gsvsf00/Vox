using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;

namespace Vox.Network.WireGuard;

/// <summary>
/// Listens for incoming UDP Knock packets on a specified port.
/// Decrypts, validates, and dispatches them to an application-provided handler.
/// </summary>
public sealed class KnockListener : IAsyncDisposable
{
    private readonly KnockProtocol _protocol;
    private readonly ILogger<KnockListener>? _logger;
    private UdpClient? _udp;
    private CancellationTokenSource? _cts;
    private Task? _listenTask;

    public KnockListener(KnockProtocol protocol, ILogger<KnockListener>? logger = null)
    {
        _protocol = protocol;
        _logger = logger;
    }

    /// <summary>
    /// Starts listening for knock packets on the specified port.
    /// For each valid knock, <paramref name="handler"/> is called to decide accept/reject.
    /// The handler returns a <see cref="KnockResponse"/>.
    /// </summary>
    public void Start(int port, Func<KnockRequest, Task<KnockResponse>> handler)
    {
        if (_udp is not null)
            throw new InvalidOperationException("Already listening.");

        _udp = new UdpClient(port);
        _cts = new CancellationTokenSource();
        _listenTask = ListenLoopAsync(handler, _cts.Token);
    }

    /// <summary>
    /// Stops listening and releases the UDP socket.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        if (_cts is not null)
        {
            await _cts.CancelAsync();

            _udp?.Dispose(); // unblocks ReceiveAsync

            if (_listenTask is not null)
            {
                try { await _listenTask; }
                catch (OperationCanceledException) { }
            }

            _cts.Dispose();
        }

        _udp = null;
        _cts = null;
        _listenTask = null;
    }

    private async Task ListenLoopAsync(Func<KnockRequest, Task<KnockResponse>> handler, CancellationToken ct)
    {
        var udp = _udp!;

        while (!ct.IsCancellationRequested)
        {
            UdpReceiveResult received;
            try
            {
                received = await udp.ReceiveAsync(ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (SocketException ex)
            {
                _logger?.LogWarning(ex, "Socket error in knock listener");
                continue;
            }

            // Decrypt and validate the knock
            var request = _protocol.TryDecryptKnock(received.Buffer, received.RemoteEndPoint);
            if (request is null)
            {
                _logger?.LogDebug("Dropped invalid knock from {Endpoint}", received.RemoteEndPoint);
                continue;
            }

            _logger?.LogInformation("Valid knock from {Endpoint}, joiner identity {Identity}",
                received.RemoteEndPoint,
                Convert.ToHexString(request.JoinerIdentityPubKey)[..16]);

            // Dispatch to handler
            KnockResponse response;
            try
            {
                response = await handler(request);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Knock handler threw for {Endpoint}", received.RemoteEndPoint);
                response = new KnockResponse(false, KnockStatus.RateLimited);
            }

            // Build and send KnockAccept
            var wgListenPort = (ushort)((IPEndPoint)udp.Client.LocalEndPoint!).Port;
            var acceptPacket = _protocol.BuildKnockAccept(
                response.StatusCode,
                wgListenPort,
                request.JoinerWgPubKey);

            try
            {
                await udp.SendAsync(acceptPacket, received.RemoteEndPoint, ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Failed to send KnockAccept to {Endpoint}", received.RemoteEndPoint);
            }
        }
    }
}
