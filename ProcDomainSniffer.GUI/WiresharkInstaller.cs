using System.Diagnostics;

namespace ProcDomainSniffer.GUI;

/// <summary>
/// Installs the official Wireshark package via the Windows Package Manager.
/// Interactive mode is intentional: a silent Wireshark installation does not
/// install Npcap, and users must be able to opt into the capture driver.
/// </summary>
internal static class WiresharkInstaller
{
    internal sealed record InstallResult(int ExitCode, string Output);

    public static async Task<InstallResult> InstallAsync()
    {
        var start = new ProcessStartInfo("winget.exe")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        foreach (var argument in new[]
        {
            "install",
            "--id", "WiresharkFoundation.Wireshark",
            "--exact",
            "--source", "winget",
            "--architecture", "x64",
            "--interactive",
            "--accept-source-agreements",
            "--accept-package-agreements"
        })
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start)
            ?? throw new InvalidOperationException("Windows Package Manager (winget) could not be started.");

        // Drain both streams concurrently to avoid process-output pipe deadlocks.
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();

        var stdout = await stdoutTask;
        var stderr = await stderrTask;
        return new InstallResult(process.ExitCode, (stdout + "\n" + stderr).Trim());
    }
}
