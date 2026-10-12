using System.Runtime.InteropServices;

namespace ProcDomainSniffer.Core;

/// <summary>
/// Capture must not start unless both TShark and the Npcap packet driver are
/// installed. Nmap (the scanner) is not a dependency.
/// </summary>
public sealed record CaptureDependencyStatus(string? TsharkPath, bool NpcapInstalled, bool NpcapRunning)
{
    public bool TsharkReady => TsharkPath is not null && File.Exists(TsharkPath);
    public bool NpcapReady => NpcapInstalled && NpcapRunning;
    public bool CanCapture => TsharkReady && NpcapReady;

    public string BlockingReason
    {
        get
        {
            var missing = new List<string>();
            if (!TsharkReady)
                missing.Add("TShark is missing (install Wireshark using winget --interactive).");
            if (!NpcapInstalled)
                missing.Add("Npcap is not installed (install the Npcap capture driver).");
            else if (!NpcapRunning)
                missing.Add("The Npcap driver is not running (repair/start Npcap).");

            return missing.Count == 0
                ? "Capture dependencies are available."
                : "Capture blocked: " + string.Join(" ", missing);
        }
    }
}

public static class CapturePrerequisites
{
    public static CaptureDependencyStatus Check(string? requestedTsharkPath = null)
    {
        var tshark = DomainSnifferService.FindTshark(requestedTsharkPath);
        var (installed, running) = NpcapDriverState.Check();
        return new CaptureDependencyStatus(tshark, installed, running);
    }
}

internal static class NpcapDriverState
{
    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceQueryStatus = 0x0004;
    private const uint ServiceRunning = 0x00000004;

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeServiceStatus
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
    }

    [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenScManager(string? machineName, string? databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", EntryPoint = "OpenServiceW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenService(IntPtr scManager, string serviceName, uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatus(IntPtr service, out NativeServiceStatus status);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr handle);

    internal static (bool Installed, bool Running) Check()
    {
        if (!OperatingSystem.IsWindows()) return (false, false);

        var manager = OpenScManager(null, null, ScManagerConnect);
        if (manager == IntPtr.Zero) return (false, false);

        try
        {
            var service = OpenService(manager, "npcap", ServiceQueryStatus);
            if (service == IntPtr.Zero) return (false, false);

            try
            {
                if (!QueryServiceStatus(service, out var status)) return (true, false);
                return (true, status.CurrentState == ServiceRunning);
            }
            finally
            {
                CloseServiceHandle(service);
            }
        }
        finally
        {
            CloseServiceHandle(manager);
        }
    }
}
