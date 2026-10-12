using ProcDomainSniffer.Core;

namespace ProcDomainSniffer.Tests;

public sealed class CapturePrerequisiteTests
{
    [Fact]
    public void MissingTsharkBlocksCaptureEvenWithRunningNpcap()
    {
        var status = new CaptureDependencyStatus(null, true, true);
        Assert.False(status.CanCapture);
        Assert.Contains("TShark", status.BlockingReason);
    }

    [Fact]
    public void MissingNpcapBlocksCaptureEvenWithTshark()
    {
        var tshark = Path.GetTempFileName();
        try
        {
            var status = new CaptureDependencyStatus(tshark, false, false);
            Assert.False(status.CanCapture);
            Assert.Contains("Npcap", status.BlockingReason);
        }
        finally { File.Delete(tshark); }
    }

    [Fact]
    public void StoppedNpcapBlocksCaptureEvenWhenInstalled()
    {
        var tshark = Path.GetTempFileName();
        try
        {
            var status = new CaptureDependencyStatus(tshark, true, false);
            Assert.False(status.CanCapture);
            Assert.Contains("not running", status.BlockingReason);
        }
        finally { File.Delete(tshark); }
    }

    [Fact]
    public void AllInstalledAndRunningAllowsPrerequisiteCheck()
    {
        var tshark = Path.GetTempFileName();
        try
        {
            var status = new CaptureDependencyStatus(tshark, true, true);
            Assert.True(status.CanCapture);
        }
        finally { File.Delete(tshark); }
    }
}
