using System.IO;
using System.Diagnostics;
using System.Text;

namespace ProcDomainSniffer.GUI;

/// <summary>
/// Streams real output from winget. The Wireshark installer itself is launched
/// interactively and may display its own setup wizard outside this process.
/// </summary>
internal static class WiresharkInstaller
{
    internal sealed record InstallResult(int ExitCode, string Output);

    internal const string CommandDescription =
        "winget install --id WiresharkFoundation.Wireshark --exact --source winget " +
        "--architecture x64 --interactive --accept-source-agreements --accept-package-agreements";

    public static async Task<InstallResult> InstallAsync(Action<string, bool> onOutput)
    {
        ArgumentNullException.ThrowIfNull(onOutput);

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

        // Read both redirected pipes concurrently; ReadToEndAsync only delivered
        // output after completion and hid download / installation progress.
        var stdoutTask = StreamOutputAsync(process.StandardOutput, false, onOutput);
        var stderrTask = StreamOutputAsync(process.StandardError, true, onOutput);

        await process.WaitForExitAsync();
        var stdout = await stdoutTask;
        var stderr = await stderrTask;
        return new InstallResult(process.ExitCode, (stdout + Environment.NewLine + stderr).Trim());
    }

    private static async Task<string> StreamOutputAsync(
        StreamReader reader, bool isError, Action<string, bool> onOutput)
    {
        var capture = new StringBuilder();
        var pending = new StringBuilder();
        var buffer = new char[512];
        int count;

        // Winget sometimes uses carriage returns (not newlines) to update
        // progress. Treat CR as an output boundary as well as LF.
        while ((count = await reader.ReadAsync(buffer.AsMemory())) > 0)
        {
            for (var i = 0; i < count; i++)
            {
                var c = buffer[i];
                if (c == '\r' || c == '\n')
                {
                    Flush();
                }
                else if (!char.IsControl(c) || c == '\t')
                {
                    pending.Append(c);
                    if (pending.Length >= 1024) Flush();
                }
            }
        }

        Flush();
        return capture.ToString();

        void Flush()
        {
            if (pending.Length == 0) return;
            var line = pending.ToString();
            pending.Clear();
            if (capture.Length < 128_000)
                capture.AppendLine(line);
            onOutput(line, isError);
        }
    }
}
