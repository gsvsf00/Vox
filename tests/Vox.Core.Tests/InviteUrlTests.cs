using System.Net;
using Vox.Core.Crypto;
using Vox.Core.Groups;

namespace Vox.Core.Tests;

public class InviteUrlTests
{
    [Fact]
    public void Create_and_Parse_roundtrip()
    {
        var token = CapsuleCodec.Base64UrlEncode(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
        var wgKey = new byte[32];
        wgKey[0] = 0xAA;
        var peers = new List<BootstrapPeer>
        {
            new(wgKey, new IPEndPoint(IPAddress.Parse("192.168.1.1"), 51820))
        };

        var url = InviteUrl.Create(token, peers);
        var parsed = InviteUrl.Parse(url);

        Assert.Equal(token, parsed.CapsuleToken);
        Assert.Equal(wgKey, parsed.BootstrapWireGuardPublicKey);
        Assert.Single(parsed.Endpoints);
        Assert.Equal("192.168.1.1", parsed.Endpoints[0].Address.ToString());
        Assert.Equal(51820, parsed.Endpoints[0].Port);
    }

    [Fact]
    public void Create_multiple_endpoints()
    {
        var token = CapsuleCodec.Base64UrlEncode(new byte[] { 10, 20 });
        var wgKey = new byte[32];
        var peers = new List<BootstrapPeer>
        {
            new(wgKey, new IPEndPoint(IPAddress.Parse("10.0.0.1"), 1234)),
            new(wgKey, new IPEndPoint(IPAddress.Parse("10.0.0.2"), 5678)),
        };

        var url = InviteUrl.Create(token, peers);
        var parsed = InviteUrl.Parse(url);

        Assert.Equal(2, parsed.Endpoints.Count);
    }

    [Fact]
    public void Url_starts_with_vox_scheme()
    {
        var token = CapsuleCodec.Base64UrlEncode(new byte[] { 1 });
        var peers = new List<BootstrapPeer>
        {
            new(new byte[32], new IPEndPoint(IPAddress.Loopback, 1000))
        };

        var url = InviteUrl.Create(token, peers);

        Assert.StartsWith("vox://join/", url);
    }

    [Fact]
    public void Parse_invalid_scheme_throws()
    {
        Assert.Throws<FormatException>(() => InviteUrl.Parse("https://example.com/foo"));
    }

    [Fact]
    public void Parse_missing_query_params_throws()
    {
        Assert.Throws<FormatException>(() => InviteUrl.Parse("vox://join/capsuledata"));
    }

    [Fact]
    public void Parse_missing_bpk_throws()
    {
        Assert.Throws<FormatException>(() => InviteUrl.Parse("vox://join/capsuledata?ep=1.2.3.4:5678"));
    }

    [Fact]
    public void Create_empty_peers_throws()
    {
        Assert.Throws<ArgumentException>(() =>
            InviteUrl.Create("dGVzdA", new List<BootstrapPeer>()));
    }
}
