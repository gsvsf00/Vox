using Vox.Core.Identity;

namespace Vox.Core.Tests;

public class PeerIdTests
{
    [Fact]
    public void Constructor_with_32_bytes_succeeds()
    {
        var key = new byte[32];
        key[0] = 0xAB;
        var id = new PeerId(key);

        Assert.Equal(32, id.PublicKey.Length);
        Assert.Equal(0xAB, id.PublicKey[0]);
    }

    [Fact]
    public void Constructor_with_wrong_size_throws()
    {
        Assert.Throws<ArgumentException>(() => new PeerId(new byte[16]));
        Assert.Throws<ArgumentException>(() => new PeerId(new byte[33]));
    }

    [Fact]
    public void Equality_same_bytes()
    {
        var bytes = new byte[32];
        bytes[5] = 42;

        var id1 = new PeerId((byte[])bytes.Clone());
        var id2 = new PeerId((byte[])bytes.Clone());

        Assert.Equal(id1, id2);
        Assert.True(id1 == id2);
        Assert.False(id1 != id2);
    }

    [Fact]
    public void Inequality_different_bytes()
    {
        var bytes1 = new byte[32];
        var bytes2 = new byte[32];
        bytes2[0] = 1;

        var id1 = new PeerId(bytes1);
        var id2 = new PeerId(bytes2);

        Assert.NotEqual(id1, id2);
        Assert.True(id1 != id2);
    }

    [Fact]
    public void GetHashCode_consistent_for_equal_ids()
    {
        var bytes = new byte[32];
        bytes[0] = 0xDE;
        bytes[1] = 0xAD;

        var id1 = new PeerId((byte[])bytes.Clone());
        var id2 = new PeerId((byte[])bytes.Clone());

        Assert.Equal(id1.GetHashCode(), id2.GetHashCode());
    }

    [Fact]
    public void ToHex_returns_uppercase_hex()
    {
        var bytes = new byte[32];
        bytes[0] = 0xAB;
        bytes[1] = 0xCD;

        var id = new PeerId(bytes);
        var hex = id.ToHex();

        Assert.Equal(64, hex.Length);
        Assert.StartsWith("ABCD", hex);
    }

    [Fact]
    public void Default_PeerId_has_empty_key()
    {
        var id = default(PeerId);
        Assert.True(id.PublicKey.IsEmpty);
    }

    [Fact]
    public void Works_as_dictionary_key()
    {
        var bytes1 = new byte[32]; bytes1[0] = 1;
        var bytes2 = new byte[32]; bytes2[0] = 2;
        var id1 = new PeerId(bytes1);
        var id2 = new PeerId(bytes2);

        var dict = new Dictionary<PeerId, string>
        {
            [id1] = "Alice",
            [id2] = "Bob",
        };

        Assert.Equal("Alice", dict[new PeerId((byte[])bytes1.Clone())]);
        Assert.Equal("Bob", dict[new PeerId((byte[])bytes2.Clone())]);
    }
}
