using Vox.Core.Crypto;
using Vox.Core.Groups;
using Vox.Core.Identity;

namespace Vox.Core.Tests;

public class MembershipCertificateSerializerTests
{
    private readonly ICryptoService _crypto = new LibsodiumCryptoService();

    private (PeerId Id, byte[] PrivKey) GeneratePeer()
    {
        var (pub, priv) = _crypto.GenerateEd25519Keypair();
        return (new PeerId(pub), priv);
    }

    [Fact]
    public void FixedSize_Is168Bytes()
    {
        Assert.Equal(168, MembershipCertificateSerializer.FixedSize);
    }

    [Fact]
    public void Roundtrip_PreservesAllFields()
    {
        var (admitted, _) = GeneratePeer();
        var (admitter, _) = GeneratePeer();
        var groupId = new GroupId(_crypto.GenerateRandomBytes(32));
        var now = DateTimeOffset.UtcNow;

        var cert = new MembershipCertificate
        {
            GroupId = groupId,
            AdmittedPeerId = admitted,
            AdmittedByPeerId = admitter,
            AdmittedAt = now,
            Signature = _crypto.GenerateRandomBytes(64),
        };

        var bytes = MembershipCertificateSerializer.Serialize(cert);
        Assert.Equal(MembershipCertificateSerializer.FixedSize, bytes.Length);

        var result = MembershipCertificateSerializer.Deserialize(bytes);

        Assert.Equal(cert.GroupId, result.GroupId);
        Assert.Equal(cert.AdmittedPeerId, result.AdmittedPeerId);
        Assert.Equal(cert.AdmittedByPeerId, result.AdmittedByPeerId);
        Assert.Equal(cert.AdmittedAt.ToUnixTimeMilliseconds(), result.AdmittedAt.ToUnixTimeMilliseconds());
        Assert.Equal(cert.Signature, result.Signature);
    }

    [Fact]
    public void SignAndVerify_FullFlow()
    {
        var (admitted, _) = GeneratePeer();
        var (admitter, admitterPriv) = GeneratePeer();
        var groupId = new GroupId(_crypto.GenerateRandomBytes(32));

        // Create with placeholder signature
        var cert = new MembershipCertificate
        {
            GroupId = groupId,
            AdmittedPeerId = admitted,
            AdmittedByPeerId = admitter,
            AdmittedAt = DateTimeOffset.UtcNow,
            Signature = new byte[64],
        };

        var serialized = MembershipCertificateSerializer.Serialize(cert);
        var signable = MembershipCertificateSerializer.GetSignableSpan(serialized);
        var signature = _crypto.Sign(signable, admitterPriv);

        // Rebuild with real signature
        cert = new MembershipCertificate
        {
            GroupId = cert.GroupId,
            AdmittedPeerId = cert.AdmittedPeerId,
            AdmittedByPeerId = cert.AdmittedByPeerId,
            AdmittedAt = cert.AdmittedAt,
            Signature = signature,
        };

        var finalBytes = MembershipCertificateSerializer.Serialize(cert);
        var verifySpan = MembershipCertificateSerializer.GetSignableSpan(finalBytes);

        Assert.True(_crypto.Verify(verifySpan, signature, admitter.PublicKey));
    }

    [Fact]
    public void GetSignableSpan_ExcludesLast64Bytes()
    {
        var cert = new MembershipCertificate
        {
            GroupId = new GroupId(_crypto.GenerateRandomBytes(32)),
            AdmittedPeerId = new PeerId(_crypto.GenerateRandomBytes(32)),
            AdmittedByPeerId = new PeerId(_crypto.GenerateRandomBytes(32)),
            AdmittedAt = DateTimeOffset.UtcNow,
            Signature = _crypto.GenerateRandomBytes(64),
        };

        var bytes = MembershipCertificateSerializer.Serialize(cert);
        var signable = MembershipCertificateSerializer.GetSignableSpan(bytes);

        Assert.Equal(bytes.Length - 64, signable.Length);
    }

    [Fact]
    public void Deserialize_TooShort_Throws()
    {
        var data = new byte[100];
        Assert.Throws<InvalidDataException>(() =>
            MembershipCertificateSerializer.Deserialize(data));
    }

    [Fact]
    public void TamperedSignature_FailsVerification()
    {
        var (admitted, _) = GeneratePeer();
        var (admitter, admitterPriv) = GeneratePeer();

        var cert = new MembershipCertificate
        {
            GroupId = new GroupId(_crypto.GenerateRandomBytes(32)),
            AdmittedPeerId = admitted,
            AdmittedByPeerId = admitter,
            AdmittedAt = DateTimeOffset.UtcNow,
            Signature = new byte[64],
        };

        var serialized = MembershipCertificateSerializer.Serialize(cert);
        var signable = MembershipCertificateSerializer.GetSignableSpan(serialized);
        var signature = _crypto.Sign(signable, admitterPriv);

        cert = new MembershipCertificate
        {
            GroupId = cert.GroupId,
            AdmittedPeerId = cert.AdmittedPeerId,
            AdmittedByPeerId = cert.AdmittedByPeerId,
            AdmittedAt = cert.AdmittedAt,
            Signature = signature,
        };

        var finalBytes = MembershipCertificateSerializer.Serialize(cert);

        // Tamper with a field
        finalBytes[10] ^= 0xFF;

        var tampered = MembershipCertificateSerializer.GetSignableSpan(finalBytes);
        Assert.False(_crypto.Verify(tampered, signature, admitter.PublicKey));
    }
}
