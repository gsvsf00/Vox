using System.Net;
using Vox.Core.Crypto;

namespace Vox.Core.Groups;

/// <summary>
/// vox://join/&lt;capsule_token&gt;?ep=&lt;ip:port&gt;&amp;bpk=&lt;base64url(wg_pubkey)&gt;
/// The capsule_token is produced by <see cref="CapsuleCodec.Encode"/>.
/// </summary>
public static class InviteUrl
{
    private const string Scheme = "vox";
    private const string Host = "join";

    /// <summary>
    /// Build an invite URL from a pre-encoded capsule token and bootstrap peers.
    /// </summary>
    /// <param name="capsuleToken">Base64URL capsule token (from <see cref="CapsuleCodec.Encode"/>).</param>
    /// <param name="bootstrapPeers">At least one bootstrap peer.</param>
    public static string Create(string capsuleToken, List<BootstrapPeer> bootstrapPeers)
    {
        if (bootstrapPeers is not { Count: > 0 })
            throw new ArgumentException("At least one bootstrap peer is required.", nameof(bootstrapPeers));

        var endpoints = string.Join(",", bootstrapPeers.Select(bp => bp.Endpoint));
        var bpk = CapsuleCodec.Base64UrlEncode(bootstrapPeers[0].WireGuardPublicKey);

        return $"{Scheme}://{Host}/{capsuleToken}?ep={endpoints}&bpk={bpk}";
    }

    public static ParsedInvite Parse(string url)
    {
        // vox://join/<capsule>?ep=<ip:port>,<ip:port>&bpk=<base64url>
        if (!url.StartsWith($"{Scheme}://{Host}/", StringComparison.OrdinalIgnoreCase))
            throw new FormatException("Invalid Vox invite URL scheme.");

        var withoutScheme = url[($"{Scheme}://{Host}/".Length)..];
        var queryIndex = withoutScheme.IndexOf('?');
        if (queryIndex < 0)
            throw new FormatException("Missing query parameters (ep, bpk).");

        var capsuleToken = withoutScheme[..queryIndex];
        var queryString = withoutScheme[(queryIndex + 1)..];

        var parameters = ParseQueryString(queryString);

        if (!parameters.TryGetValue("ep", out var epValue) || string.IsNullOrEmpty(epValue))
            throw new FormatException("Missing 'ep' parameter.");
        if (!parameters.TryGetValue("bpk", out var bpkValue) || string.IsNullOrEmpty(bpkValue))
            throw new FormatException("Missing 'bpk' parameter.");

        var bootstrapWgPubKey = CapsuleCodec.Base64UrlDecode(bpkValue);
        var endpoints = epValue.Split(',')
            .Select(ep =>
            {
                var parts = ep.Split(':');
                if (parts.Length != 2 || string.IsNullOrWhiteSpace(parts[0]) || string.IsNullOrWhiteSpace(parts[1]))
                    throw new FormatException($"Malformed endpoint '{ep}' in 'ep' parameter. Expected format '<ip:port>'.");

                if (!IPAddress.TryParse(parts[0], out var ipAddress))
                    throw new FormatException($"Invalid IP address '{parts[0]}' in endpoint '{ep}'.");

                if (!int.TryParse(parts[1], out var port) || port <= 0 || port > 65535)
                    throw new FormatException($"Invalid port '{parts[1]}' in endpoint '{ep}'. Port must be an integer between 1 and 65535.");

                return new IPEndPoint(ipAddress, port);
            })
            .ToList();

        return new ParsedInvite(capsuleToken, bootstrapWgPubKey, endpoints);
    }

    private static Dictionary<string, string> ParseQueryString(string query)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var pair in query.Split('&'))
        {
            var eqIndex = pair.IndexOf('=');
            if (eqIndex > 0)
                result[pair[..eqIndex]] = Uri.UnescapeDataString(pair[(eqIndex + 1)..]);
        }
        return result;
    }
}

/// <summary>
/// Parsed invite URL. CapsuleToken is the raw Base64URL string;
/// decode it with <see cref="CapsuleCodec.Decode"/> using the group key.
/// </summary>
public sealed record ParsedInvite(
    string CapsuleToken,
    byte[] BootstrapWireGuardPublicKey,
    List<IPEndPoint> Endpoints
);
