using ProcDomainSniffer.Core;

namespace ProcDomainSniffer.Tests;

public sealed class DomainUtilTests
{
    [Theory]
    [InlineData(" Example.COM. ", "example.com")]
    [InlineData(""Sub.Example.com"", "sub.example.com")]
    [InlineData("", "")]
    public void Normalize_CanonicalizesDomain(string input, string expected)
        => Assert.Equal(expected, DomainUtil.Normalize(input));

    [Theory]
    [InlineData("example.com:8443", "example.com")]
    [InlineData("[2001:db8::1]:443", "2001:db8::1")]
    [InlineData("example.com", "example.com")]
    public void NormalizeHttpHost_RemovesPort(string input, string expected)
        => Assert.Equal(expected, DomainUtil.NormalizeHttpHost(input));
}

public sealed class IpUtilTests
{
    [Theory]
    [InlineData("127.0.0.1", false)]
    [InlineData("10.0.0.1", false)]
    [InlineData("172.16.0.1", false)]
    [InlineData("192.168.1.1", false)]
    [InlineData("169.254.1.1", false)]
    [InlineData("100.64.0.1", false)]
    [InlineData("8.8.8.8", true)]
    [InlineData("2001:4860:4860::8888", true)]
    [InlineData("fe80::1", false)]
    public void IsPublic_FiltersNonPublicRanges(string ip, bool expected)
        => Assert.Equal(expected, IpUtil.IsPublic(ip));

    [Fact]
    public void ExtractPublicIps_DeduplicatesAndFiltersPrivateAddresses()
    {
        var result = IpUtil.ExtractPublicIps("8.8.8.8, 10.0.0.1; 8.8.8.8 | 1.1.1.1").ToArray();
        Assert.Equal(new[] { "8.8.8.8", "1.1.1.1" }, result);
    }
}
