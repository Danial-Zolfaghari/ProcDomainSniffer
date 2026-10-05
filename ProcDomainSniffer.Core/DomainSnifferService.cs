using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Tracing;
using System.Globalization;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace ProcDomainSniffer.Core;

public sealed class DomainSnifferService : IAsyncDisposable
{
    private TargetTracker? _targets;
    private FlowTracker? _flows;
    private DomainSink? _sink;
    private TraceEventSession? _kernelSession;
    private TraceEventSession? _dnsSession;
    private Task? _kernelTask;
    private Task? _dnsTask;
    private TsharkCollector? _tshark;
    private CancellationTokenSource? _runCts;
    private string? _tsharkPath;
    private bool _isRunning;

    public bool IsRunning => _isRunning;
    public int UniqueCount => _sink?.UniqueCount ?? 0;
    public IReadOnlyCollection<int> CurrentPids => _targets?.CurrentPids.OrderBy(x => x).ToArray() ?? Array.Empty<int>();

    public event Action<LogMessage>? Log;
    public event Action<DomainObservation>? Observation;
    public event Action<NetworkPacketObservation>? NetworkPacket;
    public event Action<IReadOnlyCollection<int>>? TargetsChanged;

    public async Task StartAsync(SnifferOptions options, CancellationToken externalToken = default)
    {
        if (_isRunning) throw new InvalidOperationException("Capture is already running.");
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("This tool is Windows-only.");
        if (!Privilege.IsAdministrator()) throw new InvalidOperationException("The GUI must be run as Administrator.");
        if (options.Pid is null && string.IsNullOrWhiteSpace(options.ProcessName))
            throw new InvalidOperationException("Either PID or process name must be specified.");

        _isRunning = true;
        _runCts = CancellationTokenSource.CreateLinkedTokenSource(externalToken);

        try
        {
            _tsharkPath = TsharkLocator.Find(options.TsharkPath);
            Directory.CreateDirectory(options.OutputDirectory);

            _targets = new TargetTracker(options.Pid, options.ProcessName, options.IncludeChildren, EmitTargetsChanged);
            _flows = new FlowTracker(_targets);
            _sink = new DomainSink(options.OutputDirectory, options.ShowRepeats, OnObservation, WriteLog);

            WriteLog("INFO", "=== ProcDomainSniffer GUI ===");
            WriteLog("INFO", $"Output: {options.OutputDirectory}");
            WriteLog("INFO", $"Target: {(options.Pid is not null ? $"PID {options.Pid}" : options.ProcessName)}");
            WriteLog("INFO", $"Children: {(options.IncludeChildren ? "yes" : "no")}");

            _targets.InitializeFromCurrentProcesses();
            EmitTargetsChanged();

            StartKernelEtw();
            StartDnsEtw();

            if (_tsharkPath is null)
            {
                WriteLog("WARN", "tshark.exe پیدا نشد؛ فعلاً فقط DNS ETW فعال است. TLS SNI / direct DNS packet fallback غیرفعال است.");
            }
            else
            {
                _tshark = new TsharkCollector(_tsharkPath, options, _flows, _sink, WriteLog, OnNetworkPacket);
                await _tshark.StartAsync(_runCts.Token);
            }

            _ = Task.Run(() => MaintenanceLoopAsync(_runCts.Token));
            WriteLog("INFO", "[READY] Capturing started.");
        }
        catch
        {
            await CleanupAfterFailedStartAsync();
            throw;
        }
    }

    private async Task MaintenanceLoopAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                _targets?.RefreshDescendantsFromSnapshot();
                _flows?.Cleanup();
                EmitTargetsChanged();
                await Task.Delay(1000, ct);
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    private async Task CleanupAfterFailedStartAsync()
    {
        _isRunning = false;

        try { _runCts?.Cancel(); } catch { }

        if (_tshark is not null)
        {
            try { await _tshark.StopAsync(); } catch { }
            _tshark = null;
        }

        try { _dnsSession?.Dispose(); } catch { }
        try { _kernelSession?.Dispose(); } catch { }
        _dnsSession = null;
        _kernelSession = null;

        if (_dnsTask is not null)
        {
            try { await Task.WhenAny(_dnsTask, Task.Delay(500)); } catch { }
            _dnsTask = null;
        }

        if (_kernelTask is not null)
        {
            try { await Task.WhenAny(_kernelTask, Task.Delay(500)); } catch { }
            _kernelTask = null;
        }

        try { _sink?.Dispose(); } catch { }

        _runCts?.Dispose();
        _runCts = null;
    }

    public async Task StopAsync()
    {
        if (!_isRunning) return;
        _isRunning = false;

        try { _runCts?.Cancel(); } catch { }

        if (_tshark is not null)
        {
            await _tshark.StopAsync();
            _tshark = null;
        }

        try { _dnsSession?.Dispose(); } catch { }
        try { _kernelSession?.Dispose(); } catch { }

        if (_dnsTask is not null) await Task.WhenAny(_dnsTask, Task.Delay(1500));
        if (_kernelTask is not null) await Task.WhenAny(_kernelTask, Task.Delay(1500));

        _sink?.Dispose();
        WriteLog("INFO", $"[DONE] {UniqueCount} unique domains");

        _runCts?.Dispose();
        _runCts = null;
    }

    private void StartKernelEtw()
    {
        if (_targets is null || _flows is null) throw new InvalidOperationException();

        var sessionName = $"ProcDomain-Kernel-{Environment.ProcessId}-{Guid.NewGuid():N}";
        _kernelSession = new TraceEventSession(sessionName) { StopOnDispose = true };

        // IMPORTANT: TraceEvent requires the kernel provider to be enabled before
        // the session Source is touched. Accessing Source first starts a regular
        // ETW session, after which EnableKernelProvider throws:
        // "The kernel provider must be enabled first and only once in a session."
        _kernelSession.EnableKernelProvider(
            KernelTraceEventParser.Keywords.Process |
            KernelTraceEventParser.Keywords.NetworkTCPIP);

        var source = _kernelSession.Source;

        source.Kernel.ProcessStart += data =>
        {
            if (_targets.OnProcessStart(data.ProcessID, data.ParentID, data.ProcessName))
                WriteLog("INFO", $"[TRACK] PID {data.ProcessID} {data.ProcessName} parent={data.ParentID}");
        };

        source.Kernel.ProcessStop += data =>
        {
            _targets.OnProcessStop(data.ProcessID);
            _flows.RemovePid(data.ProcessID);
        };

        source.Kernel.TcpIpConnect += data => _flows.Register("tcp", data.ProcessID, data.saddr, data.sport, data.daddr, data.dport);
        source.Kernel.TcpIpSend += data => _flows.Register("tcp", data.ProcessID, data.saddr, data.sport, data.daddr, data.dport);
        source.Kernel.TcpIpConnectIPV6 += data => _flows.Register("tcp", data.ProcessID, data.saddr, data.sport, data.daddr, data.dport);
        source.Kernel.TcpIpSendIPV6 += data => _flows.Register("tcp", data.ProcessID, data.saddr, data.sport, data.daddr, data.dport);
        source.Kernel.UdpIpSend += data => _flows.Register("udp", data.ProcessID, data.saddr, data.sport, data.daddr, data.dport);
        source.Kernel.UdpIpSendIPV6 += data => _flows.Register("udp", data.ProcessID, data.saddr, data.sport, data.daddr, data.dport);

        _kernelTask = Task.Run(() =>
        {
            try { source.Process(); }
            catch (Exception ex) { WriteLog("ERROR", "[Kernel ETW stopped] " + ex.Message); }
        });
    }

    private void StartDnsEtw()
    {
        if (_targets is null || _sink is null) throw new InvalidOperationException();

        var sessionName = $"ProcDomain-DNS-{Environment.ProcessId}-{Guid.NewGuid():N}";
        _dnsSession = new TraceEventSession(sessionName) { StopOnDispose = true };
        var source = _dnsSession.Source;

        source.Dynamic.All += data =>
        {
            try
            {
                if (!string.Equals(data.ProviderName, "Microsoft-Windows-DNS-Client", StringComparison.OrdinalIgnoreCase))
                    return;

                var queryName = PayloadString(data, "QueryName");
                if (string.IsNullOrWhiteSpace(queryName)) return;

                var pid = data.ProcessID;
                if (!_targets.IsTarget(pid)) return;

                var resolvedIps = ExtractPublicIpsFromDnsEvent(data);

                _sink.Observe(new DomainObservation(
                    DateTimeOffset.Now,
                    DomainUtil.Normalize(queryName),
                    "DNS-ETW",
                    pid,
                    null,
                    null,
                    null,
                    resolvedIps));
            }
            catch
            {
            }
        };

        _dnsSession.EnableProvider("Microsoft-Windows-DNS-Client", TraceEventLevel.Verbose, ulong.MaxValue);
        _dnsTask = Task.Run(() =>
        {
            try { source.Process(); }
            catch (Exception ex) { WriteLog("ERROR", "[DNS ETW stopped] " + ex.Message); }
        });
    }

    private static string? PayloadString(TraceEvent data, string name)
    {
        foreach (var payloadName in data.PayloadNames)
        {
            if (!string.Equals(payloadName, name, StringComparison.OrdinalIgnoreCase)) continue;
            return data.PayloadByName(payloadName)?.ToString();
        }
        return null;
    }

    private static IReadOnlyList<string> ExtractPublicIpsFromDnsEvent(TraceEvent data)
    {
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var payloadName in data.PayloadNames)
        {
            if (!payloadName.Contains("result", StringComparison.OrdinalIgnoreCase) &&
                !payloadName.Contains("address", StringComparison.OrdinalIgnoreCase) &&
                !payloadName.Contains("answer", StringComparison.OrdinalIgnoreCase))
                continue;

            var raw = data.PayloadByName(payloadName)?.ToString();
            foreach (var ip in IpUtil.ExtractPublicIps(raw))
                result.Add(ip);
        }

        return result.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private void OnObservation(DomainObservation observation) => Observation?.Invoke(observation);

    private void OnNetworkPacket(NetworkPacketObservation packet) => NetworkPacket?.Invoke(packet);

    private void EmitTargetsChanged() => TargetsChanged?.Invoke(CurrentPids);

    private void WriteLog(string level, string message) => Log?.Invoke(new LogMessage(DateTimeOffset.Now, level, message));

    public async ValueTask DisposeAsync()
    {
        await StopAsync();
    }

    public static bool IsAdministrator() => Privilege.IsAdministrator();

    public static string? FindTshark(string? requested = null) => TsharkLocator.Find(requested);

    public static async Task<IReadOnlyList<TsharkInterface>> GetInterfacesAsync(string? tsharkPath = null)
    {
        var path = TsharkLocator.Find(tsharkPath);
        if (path is null) return Array.Empty<TsharkInterface>();
        return await TsharkLocator.GetInterfacesAsync(path);
    }

    public static IReadOnlyList<ProcessDescriptor> GetRunningProcesses()
    {
        var result = new List<ProcessDescriptor>();
        foreach (var p in Process.GetProcesses())
        {
            try
            {
                string? path = null;
                try { path = p.MainModule?.FileName; } catch { }
                result.Add(new ProcessDescriptor(p.Id, p.ProcessName, path));
            }
            catch
            {
            }
            finally
            {
                p.Dispose();
            }
        }

        return result
            .OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .ThenBy(x => x.Pid)
            .ToArray();
    }
}

internal sealed class TargetTracker
{
    private readonly int? _rootPid;
    private readonly string? _processNameNormalized;
    private readonly bool _includeChildren;
    private readonly ConcurrentDictionary<int, byte> _targets = new();
    private readonly Action _onChanged;

    public TargetTracker(int? rootPid, string? processName, bool includeChildren, Action onChanged)
    {
        _rootPid = rootPid;
        _processNameNormalized = string.IsNullOrWhiteSpace(processName) ? null : NormalizeProcessName(processName);
        _includeChildren = includeChildren;
        _onChanged = onChanged;
    }

    public IEnumerable<int> CurrentPids => _targets.Keys;
    public bool IsTarget(int pid) => pid > 0 && _targets.ContainsKey(pid);

    public void InitializeFromCurrentProcesses()
    {
        if (_rootPid is int pid)
        {
            try
            {
                using var p = Process.GetProcessById(pid);
                _targets[pid] = 0;
            }
            catch { }
        }

        if (_processNameNormalized is not null)
        {
            foreach (var p in Process.GetProcesses())
            {
                try
                {
                    if (NormalizeProcessName(p.ProcessName) == _processNameNormalized)
                        _targets[p.Id] = 0;
                }
                catch { }
                finally { p.Dispose(); }
            }
        }

        RefreshDescendantsFromSnapshot();
        _onChanged();
    }

    public bool OnProcessStart(int pid, int parentPid, string? processName)
    {
        var isRootByName = _processNameNormalized is not null && NormalizeProcessName(processName ?? "") == _processNameNormalized;
        var isChild = _includeChildren && IsTarget(parentPid);
        var isExactRoot = _rootPid == pid;

        if (!isRootByName && !isChild && !isExactRoot) return false;
        var added = _targets.TryAdd(pid, 0);
        if (added) _onChanged();
        return added;
    }

    public void OnProcessStop(int pid)
    {
        if (_targets.TryRemove(pid, out _)) _onChanged();
    }

    public void RefreshDescendantsFromSnapshot()
    {
        if (!_includeChildren || _targets.IsEmpty) return;

        var parents = ProcessSnapshot.ParentMap();
        var changed = false;
        var keepWalking = true;
        while (keepWalking)
        {
            keepWalking = false;
            foreach (var (pid, ppid) in parents)
            {
                if (_targets.ContainsKey(pid)) continue;
                if (!_targets.ContainsKey(ppid)) continue;
                _targets[pid] = 0;
                changed = true;
                keepWalking = true;
            }
        }

        if (changed) _onChanged();
    }

    private static string NormalizeProcessName(string name)
    {
        var file = Path.GetFileName(name.Trim());
        return Path.GetFileNameWithoutExtension(file).ToLowerInvariant();
    }
}

internal static class ProcessSnapshot
{
    private const uint TH32CS_SNAPPROCESS = 0x00000002;
    private static readonly IntPtr InvalidHandleValue = new(-1);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct PROCESSENTRY32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExeFile;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool Process32FirstW(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool Process32NextW(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr hObject);

    public static Dictionary<int, int> ParentMap()
    {
        var result = new Dictionary<int, int>();
        var snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == InvalidHandleValue) return result;

        try
        {
            var pe = new PROCESSENTRY32 { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32>() };
            if (!Process32FirstW(snap, ref pe)) return result;

            do
            {
                result[(int)pe.th32ProcessID] = (int)pe.th32ParentProcessID;
                pe.dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32>();
            }
            while (Process32NextW(snap, ref pe));
        }
        finally
        {
            CloseHandle(snap);
        }

        return result;
    }
}

internal readonly record struct FlowKey(string Protocol, string SourceIp, int SourcePort, string DestinationIp, int DestinationPort)
{
    public static FlowKey Create(string protocol, IPAddress src, int sport, IPAddress dst, int dport) =>
        new(protocol.ToLowerInvariant(), Normalize(src), sport, Normalize(dst), dport);

    public static FlowKey? Create(string protocol, string src, int sport, string dst, int dport)
    {
        if (!IPAddress.TryParse(src, out var s) || !IPAddress.TryParse(dst, out var d)) return null;
        return Create(protocol, s, sport, d, dport);
    }

    public FlowKey Reverse() => new(Protocol, DestinationIp, DestinationPort, SourceIp, SourcePort);

    private static string Normalize(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        return ip.ToString().ToLowerInvariant();
    }
}

internal sealed record FlowInfo(int Pid, DateTimeOffset LastSeen);

internal sealed class FlowTracker
{
    private readonly TargetTracker _targets;
    private readonly ConcurrentDictionary<FlowKey, FlowInfo> _flows = new();
    private readonly TimeSpan _ttl = TimeSpan.FromMinutes(10);

    public FlowTracker(TargetTracker targets) => _targets = targets;

    public void Register(string protocol, int pid, IPAddress src, int sport, IPAddress dst, int dport)
    {
        if (!_targets.IsTarget(pid)) return;
        if (sport <= 0 || dport <= 0) return;
        var key = FlowKey.Create(protocol, src, sport, dst, dport);
        _flows[key] = new FlowInfo(pid, DateTimeOffset.UtcNow);
    }

    public bool TryMatch(FlowKey key, out FlowInfo info)
    {
        if (_flows.TryGetValue(key, out info!))
        {
            if (DateTimeOffset.UtcNow - info.LastSeen <= _ttl && _targets.IsTarget(info.Pid))
                return true;
            _flows.TryRemove(key, out _);
        }
        info = null!;
        return false;
    }

    public bool TryMatchPacket(FlowKey key, out FlowInfo info, out bool reversed)
    {
        if (TryMatch(key, out info))
        {
            reversed = false;
            return true;
        }

        if (TryMatch(key.Reverse(), out info))
        {
            reversed = true;
            return true;
        }

        reversed = false;
        return false;
    }

    public async Task<(FlowInfo? Info, bool Reversed)> WaitForPacketMatchAsync(FlowKey key, TimeSpan timeout, CancellationToken ct)
    {
        var until = Stopwatch.GetTimestamp() + (long)(timeout.TotalSeconds * Stopwatch.Frequency);
        do
        {
            if (TryMatchPacket(key, out var info, out var reversed)) return (info, reversed);
            try { await Task.Delay(10, ct); } catch (OperationCanceledException) { return (null, false); }
        }
        while (Stopwatch.GetTimestamp() < until);
        return (null, false);
    }

    public void RemovePid(int pid)
    {
        foreach (var pair in _flows)
            if (pair.Value.Pid == pid)
                _flows.TryRemove(pair.Key, out _);
    }

    public void Cleanup()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var pair in _flows)
            if (now - pair.Value.LastSeen > _ttl || !_targets.IsTarget(pair.Value.Pid))
                _flows.TryRemove(pair.Key, out _);
    }
}

internal sealed class TsharkCollector
{
    private readonly string _tshark;
    private readonly SnifferOptions _options;
    private readonly FlowTracker _flows;
    private readonly DomainSink _sink;
    private readonly Action<string, string> _log;
    private readonly Action<NetworkPacketObservation> _networkPacket;
    private readonly ConcurrentDictionary<string, string> _ipToDomain = new(StringComparer.OrdinalIgnoreCase);
    private Process? _process;
    private CancellationTokenSource? _localCts;
    private Task? _stdoutTask;
    private Task? _stderrTask;

    public TsharkCollector(
        string tshark,
        SnifferOptions options,
        FlowTracker flows,
        DomainSink sink,
        Action<string, string> log,
        Action<NetworkPacketObservation> networkPacket)
    {
        _tshark = tshark;
        _options = options;
        _flows = flows;
        _sink = sink;
        _log = log;
        _networkPacket = networkPacket;
    }

    public async Task StartAsync(CancellationToken parentCt)
    {
        var interfaces = await ResolveInterfacesAsync();
        var psi = new ProcessStartInfo(_tshark)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        psi.ArgumentList.Add("-l");
        psi.ArgumentList.Add("-n");
        psi.ArgumentList.Add("-B");
        psi.ArgumentList.Add("64");
        psi.ArgumentList.Add("-f");
        psi.ArgumentList.Add("tcp or udp");

        foreach (var iface in interfaces)
        {
            psi.ArgumentList.Add("-i");
            psi.ArgumentList.Add(iface);
        }

        foreach (var port in _options.ExtraTlsPorts)
        {
            psi.ArgumentList.Add("-d");
            psi.ArgumentList.Add($"tcp.port=={port},tls");
        }

        psi.ArgumentList.Add("-T");
        psi.ArgumentList.Add("fields");
        psi.ArgumentList.Add("-E"); psi.ArgumentList.Add("separator=/t");
        psi.ArgumentList.Add("-E"); psi.ArgumentList.Add("quote=n");
        psi.ArgumentList.Add("-E"); psi.ArgumentList.Add("occurrence=a");
        psi.ArgumentList.Add("-E"); psi.ArgumentList.Add("aggregator=,");

        string[] fields =
        [
            "frame.time_epoch",
            "ip.src", "ipv6.src",
            "tcp.srcport", "udp.srcport",
            "ip.dst", "ipv6.dst",
            "tcp.dstport", "udp.dstport",
            "dns.qry.name",
            "tls.handshake.extensions_server_name",
            "http.host",
            "dns.a",
            "dns.aaaa"
        ];

        foreach (var field in fields)
        {
            psi.ArgumentList.Add("-e");
            psi.ArgumentList.Add(field);
        }

        _process = Process.Start(psi) ?? throw new InvalidOperationException("Failed to start tshark.exe");
        _localCts = CancellationTokenSource.CreateLinkedTokenSource(parentCt);
        _log("INFO", "[TSHARK] interfaces: " + (interfaces.Count == 0 ? "auto" : string.Join(", ", interfaces)));

        _stdoutTask = Task.Run(() => ReadStdoutAsync(_process.StandardOutput, _localCts.Token));
        _stderrTask = Task.Run(() => DrainStderrAsync(_process.StandardError, _localCts.Token));
    }

    private async Task<List<string>> ResolveInterfacesAsync()
    {
        if (_options.Interfaces.Count == 1 && string.Equals(_options.Interfaces[0], "auto", StringComparison.OrdinalIgnoreCase))
            return [];

        if (_options.Interfaces.Any(x => string.Equals(x, "all", StringComparison.OrdinalIgnoreCase)))
        {
            var all = await TsharkLocator.GetNpcapInterfaceNumbersAsync(_tshark);
            if (all.Count == 0)
            {
                _log("WARN", "Npcap interfaces از `tshark -D` تشخیص داده نشد؛ TShark از interface پیش‌فرض استفاده می‌کند.");
                return [];
            }
            return all;
        }

        return _options.Interfaces.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private async Task ReadStdoutAsync(StreamReader reader, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            string? line;
            try { line = await reader.ReadLineAsync(ct); }
            catch (OperationCanceledException) { break; }
            if (line is null) break;
            if (line.Length == 0) continue;

            try { await HandleTsharkLineAsync(line, ct); }
            catch (Exception ex) { _log("ERROR", "[TSHARK parse] " + ex.Message); }
        }
    }

    private async Task HandleTsharkLineAsync(string line, CancellationToken ct)
    {
        var f = line.Split('\t');
        if (f.Length < 14) Array.Resize(ref f, 14);

        var srcIp = FirstNonEmpty(f[1], f[2]);
        var dstIp = FirstNonEmpty(f[5], f[6]);
        if (string.IsNullOrWhiteSpace(srcIp) || string.IsNullOrWhiteSpace(dstIp)) return;

        string protocol;
        int sport, dport;
        if (int.TryParse(f[3], out sport) && int.TryParse(f[7], out dport)) protocol = "tcp";
        else if (int.TryParse(f[4], out sport) && int.TryParse(f[8], out dport)) protocol = "udp";
        else return;

        var key = FlowKey.Create(protocol, srcIp, sport, dstIp, dport);
        if (key is null) return;

        var dnsDomains = SplitField(f[9]).Select(DomainUtil.Normalize).Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var tlsDomains = SplitField(f[10]).Select(DomainUtil.Normalize).Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var httpDomains = SplitField(f[11]).Select(DomainUtil.NormalizeHttpHost).Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        // Do not block the TShark reader while looking at traffic from unrelated processes.
        // Kernel ETW registers target flows before/around the packet emission in normal cases;
        // unmatched packets are skipped immediately so a busy adapter cannot backlog the UI.
        if (!_flows.TryMatchPacket(key.Value, out var flow, out var reversed)) return;

        var timestamp = ParseFrameTimestamp(f[0]);
        var localIp = reversed ? dstIp : srcIp;
        var localPort = reversed ? dport : sport;
        var remoteIp = reversed ? srcIp : dstIp;
        var remotePort = reversed ? sport : dport;
        var local = $"{localIp}:{localPort}";
        var remote = $"{remoteIp}:{remotePort}";

        var dnsAnswers = SplitField(f[12])
            .Concat(SplitField(f[13]))
            .SelectMany(IpUtil.ExtractPublicIps)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        foreach (var domain in dnsDomains)
        {
            foreach (var answer in dnsAnswers) RememberIpDomain(answer, domain);
            _sink.Observe(new DomainObservation(timestamp, domain, "DNS-PCAP", flow.Pid, protocol, local, remote, dnsAnswers));
        }

        var remoteResolvableIp = IpUtil.IsPublic(remoteIp) ? new[] { IPAddress.Parse(remoteIp).ToString() } : Array.Empty<string>();
        foreach (var domain in tlsDomains)
        {
            if (remoteResolvableIp.Length > 0) RememberIpDomain(remoteResolvableIp[0], domain);
            _sink.Observe(new DomainObservation(timestamp, domain, "TLS-SNI", flow.Pid, protocol, local, remote, remoteResolvableIp));
        }
        foreach (var domain in httpDomains)
        {
            if (remoteResolvableIp.Length > 0) RememberIpDomain(remoteResolvableIp[0], domain);
            _sink.Observe(new DomainObservation(timestamp, domain, "HTTP-HOST", flow.Pid, protocol, local, remote, remoteResolvableIp));
        }

        var directDomain = tlsDomains.FirstOrDefault()
                           ?? httpDomains.FirstOrDefault()
                           ?? dnsDomains.FirstOrDefault();

        var packetDomain = directDomain;
        if (string.IsNullOrWhiteSpace(packetDomain))
            _ipToDomain.TryGetValue(remoteIp, out packetDomain);

        // Network Log intentionally uses the time the packet reaches the collector,
        // not frame.time_epoch. On very busy adapters TShark can deliver decoded
        // frames later than capture time; showing collector time keeps new UI rows
        // aligned with the moment they actually arrive in the application.
        _networkPacket(new NetworkPacketObservation(
            DateTimeOffset.Now,
            flow.Pid,
            protocol.ToUpperInvariant(),
            srcIp,
            dstIp,
            dport,
            string.IsNullOrWhiteSpace(packetDomain) ? null : packetDomain,
            remoteIp,
            remotePort));
    }

    private void RememberIpDomain(string? ip, string? domain)
    {
        if (string.IsNullOrWhiteSpace(ip) || string.IsNullOrWhiteSpace(domain)) return;
        _ipToDomain[ip.Trim()] = domain.Trim();
    }

    private static DateTimeOffset ParseFrameTimestamp(string? raw)
    {
        if (double.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var seconds) && seconds > 0)
        {
            try
            {
                var whole = (long)Math.Truncate(seconds);
                var fractionTicks = (long)((seconds - whole) * TimeSpan.TicksPerSecond);
                return DateTimeOffset.FromUnixTimeSeconds(whole).AddTicks(fractionTicks).ToLocalTime();
            }
            catch
            {
            }
        }

        return DateTimeOffset.Now;
    }

    private static IEnumerable<string> SplitField(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) yield break;
        foreach (var part in value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            if (!string.IsNullOrWhiteSpace(part)) yield return part;
    }

    private static string FirstNonEmpty(string? a, string? b) => !string.IsNullOrWhiteSpace(a) ? a : (b ?? "");

    private async Task DrainStderrAsync(StreamReader reader, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            string? line;
            try { line = await reader.ReadLineAsync(ct); }
            catch (OperationCanceledException) { break; }
            if (line is null) break;
            if (line.Contains("Capturing on", StringComparison.OrdinalIgnoreCase))
                _log("INFO", "[TSHARK] " + line.Trim());
            else if (line.Contains("error", StringComparison.OrdinalIgnoreCase) || line.Contains("denied", StringComparison.OrdinalIgnoreCase))
                _log("ERROR", "[TSHARK] " + line.Trim());
        }
    }

    public async Task StopAsync()
    {
        try { _localCts?.Cancel(); } catch { }

        if (_process is { HasExited: false })
        {
            try { _process.Kill(entireProcessTree: true); } catch { }
        }

        var tasks = new[] { _stdoutTask, _stderrTask }.Where(t => t is not null).Cast<Task>().ToArray();
        if (tasks.Length > 0) await Task.WhenAny(Task.WhenAll(tasks), Task.Delay(1000));

        _process?.Dispose();
        _localCts?.Dispose();
    }
}

internal sealed class DomainSink : IDisposable
{
    private sealed class DomainStats
    {
        public DateTimeOffset FirstSeen { get; init; }
        public DateTimeOffset LastSeen { get; set; }
        public long Count { get; set; }
        public HashSet<string> Sources { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<int> Pids { get; } = [];
        public HashSet<string> PublicIps { get; } = new(StringComparer.OrdinalIgnoreCase);
    }

    private readonly object _gate = new();
    private readonly Dictionary<string, DomainStats> _domains = new(StringComparer.OrdinalIgnoreCase);
    private readonly StreamWriter _domainWriter;
    private readonly StreamWriter _eventWriter;
    private readonly string _summaryPath;
    private readonly bool _showRepeats;
    private readonly Action<DomainObservation> _observationCallback;
    private readonly Action<string, string> _log;
    private bool _disposed;

    public DomainSink(string outputDirectory, bool showRepeats, Action<DomainObservation> observationCallback, Action<string, string> log)
    {
        Directory.CreateDirectory(outputDirectory);
        _domainWriter = new StreamWriter(Path.Combine(outputDirectory, "domains.txt"), append: false, new UTF8Encoding(false)) { AutoFlush = true };
        _eventWriter = new StreamWriter(Path.Combine(outputDirectory, "events.jsonl"), append: false, new UTF8Encoding(false)) { AutoFlush = true };
        _summaryPath = Path.Combine(outputDirectory, "summary.json");
        _showRepeats = showRepeats;
        _observationCallback = observationCallback;
        _log = log;
    }

    public int UniqueCount
    {
        get { lock (_gate) return _domains.Count; }
    }

    public void Observe(DomainObservation observation)
    {
        if (string.IsNullOrWhiteSpace(observation.Domain)) return;
        if (IPAddress.TryParse(observation.Domain, out _)) return;

        bool isNew;
        lock (_gate)
        {
            if (_disposed) return;

            var json = JsonSerializer.Serialize(observation);
            _eventWriter.WriteLine(json);

            isNew = !_domains.TryGetValue(observation.Domain, out var stats);
            if (isNew)
            {
                stats = new DomainStats
                {
                    FirstSeen = observation.Timestamp,
                    LastSeen = observation.Timestamp,
                    Count = 0
                };
                _domains[observation.Domain] = stats;
                _domainWriter.WriteLine(observation.Domain);
            }

            stats!.LastSeen = observation.Timestamp;
            stats.Count++;
            stats.Sources.Add(observation.Source);
            stats.Pids.Add(observation.Pid);
            if (observation.ResolvedIps is not null)
            {
                foreach (var ip in observation.ResolvedIps)
                    if (IpUtil.IsPublic(ip)) stats.PublicIps.Add(ip);
            }
        }

        _observationCallback(observation);

        if (isNew || _showRepeats)
        {
            var flow = observation.Remote is null ? "" : $"  {observation.Local} -> {observation.Remote}";
            _log("INFO", $"[{observation.Timestamp:HH:mm:ss.fff}] {observation.Source,-9} PID={observation.Pid,-6} {observation.Domain}{flow}");
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;

            var summary = _domains
                .OrderBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(
                    kv => kv.Key,
                    kv => new
                    {
                        kv.Value.Count,
                        FirstSeen = kv.Value.FirstSeen,
                        LastSeen = kv.Value.LastSeen,
                        Sources = kv.Value.Sources.OrderBy(x => x).ToArray(),
                        Pids = kv.Value.Pids.OrderBy(x => x).ToArray(),
                        PublicIps = kv.Value.PublicIps.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray()
                    },
                    StringComparer.OrdinalIgnoreCase);

            File.WriteAllText(_summaryPath, JsonSerializer.Serialize(summary, new JsonSerializerOptions { WriteIndented = true }), new UTF8Encoding(false));
            _domainWriter.Dispose();
            _eventWriter.Dispose();
        }
    }
}

internal static class IpUtil
{
    public static IEnumerable<string> ExtractPublicIps(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) yield break;

        var tokens = Regex.Split(raw, "[\\s,;|=\\[\\]\\(\\)\\{\\}<>\"']+");
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var tokenRaw in tokens)
        {
            var token = tokenRaw.Trim().TrimEnd('.');
            if (string.IsNullOrWhiteSpace(token)) continue;
            if (!IPAddress.TryParse(token, out var ip)) continue;
            if (!IsPublic(ip)) continue;

            if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
            var normalized = ip.ToString().ToLowerInvariant();
            if (seen.Add(normalized)) yield return normalized;
        }
    }

    public static bool IsPublic(string? value) => IPAddress.TryParse(value, out var ip) && IsPublic(ip);

    public static bool IsPublic(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (IPAddress.IsLoopback(ip)) return false;
        if (ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.None) || ip.Equals(IPAddress.IPv6Any) || ip.Equals(IPAddress.IPv6None)) return false;
        if (ip.IsIPv6LinkLocal || ip.IsIPv6Multicast || ip.IsIPv6SiteLocal) return false;

        var b = ip.GetAddressBytes();
        if (b.Length == 4)
        {
            // RFC1918 private ranges.
            if (b[0] == 10) return false;
            if (b[0] == 172 && b[1] is >= 16 and <= 31) return false;
            if (b[0] == 192 && b[1] == 168) return false;

            // Loopback, link-local and carrier-grade NAT.
            if (b[0] == 127) return false;
            if (b[0] == 169 && b[1] == 254) return false;
            if (b[0] == 100 && b[1] is >= 64 and <= 127) return false;

            // "This network", multicast/reserved and limited broadcast.
            if (b[0] == 0) return false;
            if (b[0] >= 224) return false;
            if (b[0] == 255) return false;
            return true;
        }

        if (b.Length == 16)
        {
            // Unique-local fc00::/7.
            if ((b[0] & 0xFE) == 0xFC) return false;
            // Link-local fe80::/10.
            if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) return false;
            // Multicast ff00::/8.
            if (b[0] == 0xFF) return false;
            return true;
        }

        return false;
    }
}

internal static class DomainUtil
{
    private static readonly Regex NumericPort = new(@":\d+$", RegexOptions.Compiled);

    public static string Normalize(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "";
        var s = value.Trim().Trim('"', '\'', ' ', '\t', '\r', '\n').TrimEnd('.');
        return s.ToLowerInvariant();
    }

    public static string NormalizeHttpHost(string? value)
    {
        var s = Normalize(value);
        if (s.StartsWith('['))
        {
            var end = s.IndexOf(']');
            return end > 0 ? s[1..end] : s;
        }
        return NumericPort.Replace(s, "");
    }
}

internal static class TsharkLocator
{
    public static string? Find(string? requested)
    {
        if (!string.IsNullOrWhiteSpace(requested))
            return File.Exists(requested) ? Path.GetFullPath(requested) : requested;

        var env = Environment.GetEnvironmentVariable("TSHARK");
        if (!string.IsNullOrWhiteSpace(env) && File.Exists(env)) return env;

        var candidates = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Wireshark", "tshark.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Wireshark", "tshark.exe")
        };
        foreach (var p in candidates)
            if (File.Exists(p)) return p;

        try
        {
            var psi = new ProcessStartInfo("where.exe", "tshark.exe")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            if (p is null) return null;
            var first = p.StandardOutput.ReadLine();
            p.WaitForExit(1500);
            if (!string.IsNullOrWhiteSpace(first) && File.Exists(first.Trim())) return first.Trim();
        }
        catch { }

        return null;
    }

    public static async Task<List<TsharkInterface>> GetInterfacesAsync(string tshark)
    {
        var result = await RunCaptureAsync(tshark, "-D");
        var list = new List<TsharkInterface>();
        foreach (var raw in result.Stdout.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var m = Regex.Match(raw, @"^\s*(\d+)\.\s+(.+)$");
            if (!m.Success) continue;
            var id = m.Groups[1].Value;
            var description = m.Groups[2].Value.Trim();
            var isNpcap = description.Contains(@"\Device\NPF_", StringComparison.OrdinalIgnoreCase);
            list.Add(new TsharkInterface(id, description, isNpcap));
        }
        return list;
    }

    public static async Task<List<string>> GetNpcapInterfaceNumbersAsync(string tshark)
    {
        var interfaces = await GetInterfacesAsync(tshark);
        return interfaces.Where(x => x.IsNpcap).Select(x => x.Id).Distinct().ToList();
    }

    private static async Task<(int ExitCode, string Stdout, string Stderr)> RunCaptureAsync(string file, string arg)
    {
        var psi = new ProcessStartInfo(file, arg)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        using var p = Process.Start(psi) ?? throw new InvalidOperationException("Unable to launch tshark.exe");
        var stdout = await p.StandardOutput.ReadToEndAsync();
        var stderr = await p.StandardError.ReadToEndAsync();
        await p.WaitForExitAsync();
        return (p.ExitCode, stdout, stderr);
    }
}

internal static class Privilege
{
    public static bool IsAdministrator()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }
}
