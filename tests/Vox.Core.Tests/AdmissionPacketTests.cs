using System.Net;
using Vox.Core.Crypto;
using Vox.Core.Groups;
using Vox.Core.Identity;

namespace Vox.Core.Tests;

public class AdmissionPacketTests
{
    private readonly ICryptoService _crypto = new LibsodiumCryptoService();

    private MembershipCertificate CreateTestCert()
    {
        return new MembershipCertificate
        {
            GroupId = new GroupId(_crypto.GenerateRandomBytes(32)),
            AdmittedPeerId = new PeerId(_crypto.GenerateRandomBytes(32)),
            AdmittedByPeerId = new PeerId(_crypto.GenerateRandomBytes(32)),
            AdmittedAt = DateTimeOffset.UtcNow,
            Signature = _crypto.GenerateRandomBytes(64),
        };
    }

    private PeerInfo CreateTestPeer(string name, int index)
    {
        return new PeerInfo(
            new PeerId(_crypto.GenerateRandomBytes(32)),
            name,
            (ushort)(1000 + index),
            _crypto.GenerateRandomBytes(32),
            [new IPEndPoint(IPAddress.Parse($"10.0.0.{index + 1}"), 5000 + index)],
            PeerStatus.Online,
            PeerCapabilities.Voice | PeerCapabilities.Relay);
    }

    [Fact]
    public void Admission_Roundtrip_PreservesAllFields()
    {
        var cert = CreateTestCert();
        var encKey = _crypto.GenerateRandomBytes(80); // encrypted group key
        var peers = new List<PeerInfo> { CreateTestPeer("Alice", 0), CreateTestPeer("Bob", 1) };
        ulong lamport = 42;

        var bytes = AdmissionPacket.SerializeAdmission(cert, encKey, peers, lamport);
        var result = AdmissionPacket.DeserializeAdmission(bytes);

        Assert.Equal(cert.GroupId, result.Certificate.GroupId);
        Assert.Equal(cert.AdmittedPeerId, result.Certificate.AdmittedPeerId);
        Assert.Equal(cert.AdmittedByPeerId, result.Certificate.AdmittedByPeerId);
        Assert.Equal(encKey, result.EncryptedGroupKey);
        Assert.Equal(lamport, result.LatestLamport);
        Assert.Equal(2, result.PeerList.Count);
    }

    [Fact]
    public void Admission_PeerInfo_PreservesDetails()
    {
        var cert = CreateTestCert();
        var peer = CreateTestPeer("Charlie", 5);
        var bytes = AdmissionPacket.SerializeAdmission(cert, new byte[48], [peer], 0);
        var result = AdmissionPacket.DeserializeAdmission(bytes);

        var p = result.PeerList[0];
        Assert.Equal("Charlie", p.Username);
        Assert.Equal(1005, p.Discriminator);
        Assert.Equal(PeerStatus.Online, p.Status);
        Assert.Equal(PeerCapabilities.Voice | PeerCapabilities.Relay, p.Capabilities);
        Assert.Single(p.Endpoints);
        Assert.Equal(IPAddress.Parse("10.0.0.6"), p.Endpoints[0].Address);
        Assert.Equal(5005, p.Endpoints[0].Port);
    }

    [Fact]
    public void Admission_EmptyPeerList_Roundtrips()
    {
        var cert = CreateTestCert();
        var bytes = AdmissionPacket.SerializeAdmission(cert, new byte[48], [], 100);
        var result = AdmissionPacket.DeserializeAdmission(bytes);

        Assert.Empty(result.PeerList);
        Assert.Equal(100UL, result.LatestLamport);
    }

    [Fact]
    public void Admission_PeerWithMultipleEndpoints()
    {
        var peer = new PeerInfo(
            new PeerId(_crypto.GenerateRandomBytes(32)),
            "Multi",
            2000,
            _crypto.GenerateRandomBytes(32),
            [
                new IPEndPoint(IPAddress.Parse("192.168.1.1"), 5000),
                new IPEndPoint(IPAddress.Parse("10.0.0.1"), 6000),
            ],
            PeerStatus.Online,
            PeerCapabilities.None);

        var cert = CreateTestCert();
        var bytes = AdmissionPacket.SerializeAdmission(cert, new byte[48], [peer], 0);
        var result = AdmissionPacket.DeserializeAdmission(bytes);

        Assert.Equal(2, result.PeerList[0].Endpoints.Count);
        Assert.Equal(IPAddress.Parse("192.168.1.1"), result.PeerList[0].Endpoints[0].Address);
        Assert.Equal(IPAddress.Parse("10.0.0.1"), result.PeerList[0].Endpoints[1].Address);
    }

    [Fact]
    public void AdmissionAck_Roundtrip()
    {
        var sig = _crypto.GenerateRandomBytes(64);
        var bytes = AdmissionPacket.SerializeAdmissionAck("TestUser", 1234, PeerCapabilities.Voice, sig);
        var result = AdmissionPacket.DeserializeAdmissionAck(bytes);

        Assert.Equal(0x01, result.Ack);
        Assert.Equal("TestUser", result.Username);
        Assert.Equal(1234, result.Discriminator);
        Assert.Equal(PeerCapabilities.Voice, result.Capabilities);
        Assert.Equal(sig, result.Signature);
    }

    [Fact]
    public void AdmissionAck_GetSignableSpan_ExcludesSignature()
    {
        var bytes = AdmissionPacket.SerializeAdmissionAck("User", 1000, PeerCapabilities.None,
            _crypto.GenerateRandomBytes(64));
        var signable = AdmissionPacket.GetAckSignableSpan(bytes);

        Assert.Equal(bytes.Length - AdmissionPacket.AckSignatureSize, signable.Length);
    }

    [Fact]
    public void AdmissionAck_SignAndVerify()
    {
        var (pub, priv) = _crypto.GenerateEd25519Keypair();

        var placeholder = AdmissionPacket.SerializeAdmissionAck("Joiner", 5555,
            PeerCapabilities.Voice | PeerCapabilities.Relay, new byte[64]);

        var signable = AdmissionPacket.GetAckSignableSpan(placeholder);
        var signature = _crypto.Sign(signable, priv);

        var final = AdmissionPacket.SerializeAdmissionAck("Joiner", 5555,
            PeerCapabilities.Voice | PeerCapabilities.Relay, signature);

        var verifySpan = AdmissionPacket.GetAckSignableSpan(final);
        Assert.True(_crypto.Verify(verifySpan, signature, pub));
    }

    [Fact]
    public void Admission_UnicodeUsername_Preserved()
    {
        var peer = new PeerInfo(
            new PeerId(_crypto.GenerateRandomBytes(32)),
            "日本語ユーザー",
            9999,
            _crypto.GenerateRandomBytes(32),
            [new IPEndPoint(IPAddress.Loopback, 5000)],
            PeerStatus.Away,
            PeerCapabilities.HighBandwidth);

        var cert = CreateTestCert();
        var bytes = AdmissionPacket.SerializeAdmission(cert, new byte[48], [peer], 0);
        var result = AdmissionPacket.DeserializeAdmission(bytes);

        Assert.Equal("日本語ユーザー", result.PeerList[0].Username);
        Assert.Equal(PeerStatus.Away, result.PeerList[0].Status);
    }
}
