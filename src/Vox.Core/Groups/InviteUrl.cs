using System.Net;
using System.Text;

namespace Vox.Core.Groups;

/// <summary>
/// vox://join/&lt;base64url(encrypted_capsule)&gt;?ep=&lt;ip:port&gt;&amp;bpk=&lt;base64url(wg_pubkey)&gt;
/// </summary>
public static class InviteUrl
{
    private const string Scheme = "vox";
    private const string Host = "join";

    public static string Create(byte[] encryptedCapsule, List<BootstrapPeer> bootstrapPeers)
    {
        if (bootstrapPeers is not { Count: > 0 })
            throw new ArgumentException("At least one bootstrap peer is required.", nameof(bootstrapPeers));

        var capsuleB64 = Base64UrlEncode(encryptedCapsule);
        var endpoints = string.Join(",", bootstrapPeers.Select(bp => bp.Endpoint));
        var bpk = Base64UrlEncode(bootstrapPeers[0].WireGuardPublicKey);

        return $"{Scheme}://{Host}/{capsuleB64}?ep={endpoints}&bpk={bpk}";
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

        var capsuleB64 = withoutScheme[..queryIndex];
        var queryString = withoutScheme[(queryIndex + 1)..];

        var parameters = ParseQueryString(queryString);

        if (!parameters.TryGetValue("ep", out var epValue) || string.IsNullOrEmpty(epValue))
            throw new FormatException("Missing 'ep' parameter.");
        if (!parameters.TryGetValue("bpk", out var bpkValue) || string.IsNullOrEmpty(bpkValue))
            throw new FormatException("Missing 'bpk' parameter.");

        var capsule = Base64UrlDecode(capsuleB64);
        var bootstrapWgPubKey = Base64UrlDecode(bpkValue);
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

        return new ParsedInvite(capsule, bootstrapWgPubKey, endpoints);
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

    private static string Base64UrlEncode(byte[] data) =>
        Convert.ToBase64String(data)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private static byte[] Base64UrlDecode(string base64Url)
    {
        var s = base64Url.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4)
        {
            case 2: s += "=="; break;
            case 3: s += "="; break;
        }
        return Convert.FromBase64String(s);
    }
}

public sealed record ParsedInvite(
    byte[] EncryptedCapsule,
    byte[] BootstrapWireGuardPublicKey,
    List<IPEndPoint> Endpoints
);
