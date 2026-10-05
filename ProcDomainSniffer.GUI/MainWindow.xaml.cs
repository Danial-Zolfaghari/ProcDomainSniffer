using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Data;
using System.Windows.Threading;
using Microsoft.Win32;
using ProcDomainSniffer.Core;
using ProcDomainSniffer.GUI.Models;

namespace ProcDomainSniffer.GUI;

public partial class MainWindow : Window
{
    private readonly ObservableCollection<ProcessDescriptor> _allProcesses = [];
    private readonly ObservableCollection<ObservationRow> _eventRows = [];
    private readonly ObservableCollection<DomainCountRow> _domainRows = [];
    private readonly ObservableCollection<DomainIpRow> _domainIpRows = [];
    private readonly ObservableCollection<NetworkPacketRow> _networkRows = [];
    private readonly ObservableCollection<NetworkPacketRow> _networkUniqueRows = [];
    private readonly Dictionary<string, NetworkPacketRow> _networkUniqueIndex = new(StringComparer.OrdinalIgnoreCase);
    private readonly ObservableCollection<LogRow> _logRows = [];
    private readonly ConcurrentQueue<NetworkPacketObservation> _networkPacketQueue = new();

    private readonly Dictionary<string, DomainCountRow> _domainIndex = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, HashSet<string>> _domainSources = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DomainIpRow> _domainIpIndex = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, HashSet<string>> _domainIpAddresses = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, HashSet<string>> _domainIpSources = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _ipDomainLookup = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTimeOffset> _lastActiveDnsResolve = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _activeDnsResolveInProgress = new(StringComparer.OrdinalIgnoreCase);

    private readonly CollectionViewSource _processesViewSource = new();
    private readonly CollectionViewSource _eventsViewSource = new();
    private readonly CollectionViewSource _domainsViewSource = new();
    private readonly CollectionViewSource _domainIpsViewSource = new();
    private readonly CollectionViewSource _networkViewSource = new();
    private readonly CollectionViewSource _logsViewSource = new();
    private readonly DispatcherTimer _processRefreshTimer;
    private readonly DispatcherTimer _networkUiTimer;
    private CancellationTokenSource? _toastCts;

    private DomainSnifferService? _service;
    private bool _uiReady;
    private bool _processRefreshInProgress;
    private bool _isClosing;
    private string _lastProcessSnapshotSignature = string.Empty;
    private string? _activeCaptureTargetName;

    public MainWindow()
    {
        InitializeComponent();
        ConfigureCollections();
        InitializeDefaults();

        _processRefreshTimer = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = TimeSpan.FromSeconds(2)
        };
        _processRefreshTimer.Tick += ProcessRefreshTimer_OnTick;

        _networkUiTimer = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = TimeSpan.FromMilliseconds(120)
        };
        _networkUiTimer.Tick += NetworkUiTimer_OnTick;

        _uiReady = true;
        Loaded += MainWindow_Loaded;
        Closing += MainWindow_Closing;
    }

    private void ConfigureCollections()
    {
        _processesViewSource.Source = _allProcesses;
        _processesViewSource.Filter += ProcessesViewSource_Filter;
        ProcessesGrid.ItemsSource = _processesViewSource.View;

        _eventsViewSource.Source = _eventRows;
        _eventsViewSource.Filter += EventsViewSource_Filter;
        EventsGrid.ItemsSource = _eventsViewSource.View;

        _domainsViewSource.Source = _domainRows;
        _domainsViewSource.Filter += DomainsViewSource_Filter;
        DomainsGrid.ItemsSource = _domainsViewSource.View;

        _domainIpsViewSource.Source = _domainIpRows;
        _domainIpsViewSource.Filter += DomainIpsViewSource_Filter;
        DomainIpsGrid.ItemsSource = _domainIpsViewSource.View;

        _networkViewSource.Source = _networkRows;
        _networkViewSource.Filter += NetworkViewSource_Filter;
        NetworkGrid.ItemsSource = _networkViewSource.View;

        _logsViewSource.Source = _logRows;
        _logsViewSource.Filter += LogsViewSource_Filter;
        LogGrid.ItemsSource = _logsViewSource.View;
    }

    private void InitializeDefaults()
    {
        var defaultOut = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            "ProcDomainSniffer",
            DateTime.Now.ToString("yyyyMMdd-HHmmss"));

        OutputDirectoryTextBox.Text = defaultOut;
        TsharkPathTextBox.Text = DomainSnifferService.FindTshark() ?? string.Empty;
        UpdateTsharkStatus();

        StatusTextBlock.Text = "Ready.";
        TargetCaptureTextBlock.Text = "Not selected";
        UniqueDomainsTextBlock.Text = "Unique domains: 0 shown / 0 total";
        TrackedPidsTextBlock.Text = "Tracked PIDs: -";
        OutputFolderStatusTextBlock.Text = defaultOut;

        HideLocalhostInSummaryCheckBox.IsChecked = true;
        DomainsHideLocalhostCheckBoxMirror.IsChecked = true;
        ShowLocalhostInLiveCheckBox.IsChecked = false;
        LiveShowLocalhostCheckBoxMirror.IsChecked = false;
        HideLoopbackNetworkCheckBox.IsChecked = true;
        HideInternalNetworkCheckBox.IsChecked = false;
        UniqueNetworkCheckBox.IsChecked = false;
        IgnoreSourceIpNetworkCheckBox.IsChecked = false;
        IgnoreDestinationPortNetworkCheckBox.IsChecked = false;
    }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        UpdateAdminBadge();
        await RefreshProcessListAsync(force: true);
        await LoadInterfacesAsync();
        RefreshFilteredViews();
        UpdateTargetCaptureDisplay();
        SetProcessRefreshInterval();
        _processRefreshTimer.Start();
        _networkUiTimer.Start();
    }

    private async void MainWindow_Closing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        _isClosing = true;
        _processRefreshTimer.Stop();
        _networkUiTimer.Stop();
        _toastCts?.Cancel();

        if (_service is not null)
        {
            try { await _service.StopAsync(); } catch { }
            await _service.DisposeAsync();
        }
    }

    private void UpdateAdminBadge()
    {
        if (DomainSnifferService.IsAdministrator())
        {
            AdminBadge.Background = (System.Windows.Media.Brush)FindResource("SuccessSurfaceBrush");
            AdminBadge.BorderBrush = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x24, 0x54, 0x3A));
            AdminBadgeText.Text = "Administrator";
            AdminBadgeText.Foreground = (System.Windows.Media.Brush)FindResource("SuccessTextBrush");
        }
        else
        {
            AdminBadge.Background = (System.Windows.Media.Brush)FindResource("DangerSurfaceBrush");
            AdminBadge.BorderBrush = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x69, 0x31, 0x3C));
            AdminBadgeText.Text = "Administrator required";
            AdminBadgeText.Foreground = (System.Windows.Media.Brush)FindResource("DangerTextBrush");
        }
    }

    private void UpdateTsharkStatus()
    {
        var path = DomainSnifferService.FindTshark(TsharkPathTextBox.Text);
        TsharkStatusText.Text = path is null ? "TShark: not found" : $"TShark: {path}";
    }

    private async Task LoadInterfacesAsync()
    {
        InterfacesListBox.Items.Clear();
        InterfacesListBox.Items.Add(new TsharkInterface("all", "All Npcap interfaces", true));

        try
        {
            var interfaces = await DomainSnifferService.GetInterfacesAsync(TsharkPathTextBox.Text);
            foreach (var iface in interfaces)
                InterfacesListBox.Items.Add(iface);
        }
        catch (Exception ex)
        {
            AddLog("WARN", "Failed to enumerate interfaces: " + ex.Message);
        }

        InterfacesListBox.SelectedIndex = 0;
    }

    private void SetProcessRefreshInterval()
    {
        _processRefreshTimer.Interval = _service?.IsRunning == true
            ? TimeSpan.FromSeconds(5)
            : TimeSpan.FromSeconds(2);
    }

    private async void ProcessRefreshTimer_OnTick(object? sender, EventArgs e)
    {
        _processRefreshTimer.Stop();
        try
        {
            await RefreshProcessListAsync();
        }
        finally
        {
            if (!_isClosing)
            {
                SetProcessRefreshInterval();
                _processRefreshTimer.Start();
            }
        }
    }

    private async Task RefreshProcessListAsync(bool force = false)
    {
        if (_processRefreshInProgress || _isClosing) return;
        _processRefreshInProgress = true;

        try
        {
            var snapshot = await Task.Run(DomainSnifferService.GetRunningProcesses);
            if (_isClosing) return;

            var signature = string.Join('|', snapshot.Select(x => $"{x.Pid}:{x.Name}:{x.Path}"));
            if (!force && string.Equals(signature, _lastProcessSnapshotSignature, StringComparison.Ordinal))
                return;

            _lastProcessSnapshotSignature = signature;
            var selectedPid = (ProcessesGrid.SelectedItem as ProcessDescriptor)?.Pid;

            _allProcesses.Clear();
            foreach (var process in snapshot)
                _allProcesses.Add(process);

            _processesViewSource.View.Refresh();

            if (selectedPid is int pid)
            {
                var selected = _allProcesses.FirstOrDefault(x => x.Pid == pid);
                if (selected is not null)
                    ProcessesGrid.SelectedItem = selected;
            }
        }
        catch (Exception ex)
        {
            AddLog("WARN", "Process refresh failed: " + ex.Message);
        }
        finally
        {
            _processRefreshInProgress = false;
        }
    }

    private void ProcessesViewSource_Filter(object sender, FilterEventArgs e)
    {
        if (e.Item is not ProcessDescriptor proc)
        {
            e.Accepted = false;
            return;
        }

        var q = ProcessSearchTextBox.Text?.Trim();
        if (string.IsNullOrWhiteSpace(q))
        {
            e.Accepted = true;
            return;
        }

        e.Accepted = proc.Name.Contains(q, StringComparison.OrdinalIgnoreCase)
                     || proc.Pid.ToString().Contains(q, StringComparison.OrdinalIgnoreCase)
                     || (!string.IsNullOrWhiteSpace(proc.Path) && proc.Path.Contains(q, StringComparison.OrdinalIgnoreCase));
    }

    private void EventsViewSource_Filter(object sender, FilterEventArgs e)
    {
        if (e.Item is not ObservationRow row)
        {
            e.Accepted = false;
            return;
        }

        if (!ShouldShowLiveRow(row))
        {
            e.Accepted = false;
            return;
        }

        var q = LiveSearchTextBox?.Text?.Trim();
        e.Accepted = string.IsNullOrWhiteSpace(q) || ContainsAny(q, row.Time, row.Source, row.Pid.ToString(), row.Domain, row.Protocol, row.Local, row.Remote);
    }

    private void DomainsViewSource_Filter(object sender, FilterEventArgs e)
    {
        if (e.Item is not DomainCountRow row)
        {
            e.Accepted = false;
            return;
        }

        if (!ShouldShowDomainRow(row))
        {
            e.Accepted = false;
            return;
        }

        var q = DomainsSearchTextBox?.Text?.Trim();
        e.Accepted = string.IsNullOrWhiteSpace(q) || ContainsAny(q, row.Domain, row.Count.ToString(), row.Sources);
    }

    private void DomainIpsViewSource_Filter(object sender, FilterEventArgs e)
    {
        if (e.Item is not DomainIpRow row)
        {
            e.Accepted = false;
            return;
        }

        var q = DomainIpSearchTextBox?.Text?.Trim();
        e.Accepted = string.IsNullOrWhiteSpace(q) || ContainsAny(q, row.Domain, row.ResolvedIps, row.IpCount.ToString(), row.Status, row.Sources);
    }

    private void NetworkViewSource_Filter(object sender, FilterEventArgs e)
    {
        if (e.Item is not NetworkPacketRow row)
        {
            e.Accepted = false;
            return;
        }

        if (HideLoopbackNetworkCheckBox?.IsChecked == true && IsLoopbackNetworkRow(row))
        {
            e.Accepted = false;
            return;
        }

        if (HideInternalNetworkCheckBox?.IsChecked == true && IsInternalNetworkRow(row))
        {
            e.Accepted = false;
            return;
        }

        var q = NetworkSearchTextBox?.Text?.Trim();
        e.Accepted = string.IsNullOrWhiteSpace(q) || ContainsAny(q, row.Time, row.SourceIp, row.DestinationIp, row.DestinationPort.ToString(), row.Protocol, row.Domain, row.Requests.ToString());
    }

    private void LogsViewSource_Filter(object sender, FilterEventArgs e)
    {
        if (e.Item is not LogRow row)
        {
            e.Accepted = false;
            return;
        }

        var q = LogSearchTextBox?.Text?.Trim();
        e.Accepted = string.IsNullOrWhiteSpace(q) || ContainsAny(q, row.Time, row.Level, row.Message);
    }

    private static bool IsLoopbackNetworkRow(NetworkPacketRow row)
    {
        if (IsLoopbackIp(row.SourceIp) || IsLoopbackIp(row.DestinationIp)) return true;
        var domain = row.Domain?.Trim().Trim('.');
        return !string.IsNullOrWhiteSpace(domain) &&
               (domain.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
                domain.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsLoopbackIp(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        return IPAddress.TryParse(value, out var ip) && IPAddress.IsLoopback(ip);
    }

    private static bool IsInternalNetworkRow(NetworkPacketRow row)
    {
        // Use the normalized remote endpoint from the target process point of view.
        // Checking SourceIp would hide almost every Internet request because the
        // machine's own source address is normally RFC1918/private.
        var candidate = !string.IsNullOrWhiteSpace(row.RemoteIp)
            ? row.RemoteIp
            : row.DestinationIp;
        return IsInternalIp(candidate);
    }

    private static bool IsInternalIp(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || !IPAddress.TryParse(value, out var ip))
            return false;

        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (IPAddress.IsLoopback(ip)) return false; // controlled by the separate loopback toggle

        var bytes = ip.GetAddressBytes();
        if (bytes.Length == 4)
        {
            // RFC1918 + link-local + carrier-grade NAT.
            if (bytes[0] == 10) return true;
            if (bytes[0] == 172 && bytes[1] is >= 16 and <= 31) return true;
            if (bytes[0] == 192 && bytes[1] == 168) return true;
            if (bytes[0] == 169 && bytes[1] == 254) return true;
            if (bytes[0] == 100 && bytes[1] is >= 64 and <= 127) return true;
            return false;
        }

        if (bytes.Length == 16)
        {
            // IPv6 unique-local fc00::/7 and link-local fe80::/10.
            if ((bytes[0] & 0xFE) == 0xFC) return true;
            if (bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80) return true;
        }

        return false;
    }

    private IEnumerable<NetworkPacketRow> GetVisibleNetworkRows()
    {
        var source = UniqueNetworkCheckBox?.IsChecked == true ? _networkUniqueRows : _networkRows;
        var q = NetworkSearchTextBox?.Text?.Trim();
        foreach (var row in source)
        {
            if (HideLoopbackNetworkCheckBox?.IsChecked == true && IsLoopbackNetworkRow(row))
                continue;
            if (HideInternalNetworkCheckBox?.IsChecked == true && IsInternalNetworkRow(row))
                continue;
            if (!string.IsNullOrWhiteSpace(q) && !ContainsAny(q, row.Time, row.SourceIp, row.DestinationIp, row.DestinationPort.ToString(), row.Protocol, row.Domain, row.Requests.ToString()))
                continue;
            yield return row;
        }
    }

    private static bool ContainsAny(string query, params string?[] values) =>
        values.Any(value => !string.IsNullOrWhiteSpace(value) && value.Contains(query, StringComparison.OrdinalIgnoreCase));

    private void FillTargetFields(ProcessDescriptor proc)
    {
        ProcessNameTextBox.Text = proc.Name + ".exe";
        PidTextBox.Text = proc.Pid.ToString();
        UpdateTargetCaptureDisplay();
    }

    private void ResetCaptureViews()
    {
        _eventRows.Clear();
        _domainRows.Clear();
        _domainIpRows.Clear();
        _networkRows.Clear();
        _networkUniqueRows.Clear();
        _networkUniqueIndex.Clear();
        while (_networkPacketQueue.TryDequeue(out _)) { }
        _logRows.Clear();
        _domainIndex.Clear();
        _domainSources.Clear();
        _domainIpIndex.Clear();
        _domainIpAddresses.Clear();
        _domainIpSources.Clear();
        _ipDomainLookup.Clear();
        _lastActiveDnsResolve.Clear();
        _activeDnsResolveInProgress.Clear();
        RefreshFilteredViews();
        UniqueDomainsTextBlock.Text = "Unique domains: 0 shown / 0 total";
    }

    private async void StartButton_OnClick(object sender, RoutedEventArgs e)
    {
        try
        {
            if (!DomainSnifferService.IsAdministrator())
            {
                MessageBox.Show(this, "GUI را با Run as administrator اجرا کن تا ETW و Npcap درست کار کنند.", "Administrator required", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var options = BuildOptions();
            ResetCaptureViews();

            _activeCaptureTargetName = GetCurrentTargetName();
            UpdateTargetCaptureDisplay();

            _service = new DomainSnifferService();
            _service.Log += ServiceOnLog;
            _service.Observation += ServiceOnObservation;
            _service.NetworkPacket += ServiceOnNetworkPacket;
            _service.TargetsChanged += ServiceOnTargetsChanged;

            await _service.StartAsync(options);

            StartButton.IsEnabled = false;
            StopButton.IsEnabled = true;
            StatusTextBlock.Text = "Capturing...";
            OutputFolderStatusTextBlock.Text = options.OutputDirectory;
            WorkspaceTabs.SelectedIndex = 3;
            SetProcessRefreshInterval();
            AddLog("INFO", "Capture session started.");
        }
        catch (Exception ex)
        {
            if (_service is not null)
            {
                try { await _service.DisposeAsync(); } catch { }
                _service.Log -= ServiceOnLog;
                _service.Observation -= ServiceOnObservation;
                _service.NetworkPacket -= ServiceOnNetworkPacket;
                _service.TargetsChanged -= ServiceOnTargetsChanged;
                _service = null;
            }

            StartButton.IsEnabled = true;
            StopButton.IsEnabled = false;
            StatusTextBlock.Text = "Start failed.";
            SetProcessRefreshInterval();

            MessageBox.Show(this, ex.Message, "Start failed", MessageBoxButton.OK, MessageBoxImage.Error);
            AddLog("ERROR", ex.Message);
        }
    }

    private async void StopButton_OnClick(object sender, RoutedEventArgs e)
    {
        await StopCaptureAsync();
    }

    private async Task StopCaptureAsync()
    {
        if (_service is null) return;

        try
        {
            await _service.StopAsync();
            await _service.DisposeAsync();
        }
        catch (Exception ex)
        {
            AddLog("ERROR", ex.Message);
        }
        finally
        {
            _service.Log -= ServiceOnLog;
            _service.Observation -= ServiceOnObservation;
            _service.NetworkPacket -= ServiceOnNetworkPacket;
            _service.TargetsChanged -= ServiceOnTargetsChanged;
            _service = null;
            StartButton.IsEnabled = true;
            StopButton.IsEnabled = false;
            StatusTextBlock.Text = "Stopped.";
            SetProcessRefreshInterval();
        }
    }

    private SnifferOptions BuildOptions()
    {
        int? pid = null;
        string? processName = null;

        if (TrackByPidRadio.IsChecked == true)
        {
            if (!int.TryParse(PidTextBox.Text.Trim(), out var parsedPid) || parsedPid <= 0)
                throw new InvalidOperationException("A valid PID is required.");
            pid = parsedPid;
        }
        else
        {
            processName = ProcessNameTextBox.Text.Trim();
            if (string.IsNullOrWhiteSpace(processName))
                throw new InvalidOperationException("A process name is required.");
        }

        var selectedInterfaces = InterfacesListBox.SelectedItems.Cast<TsharkInterface>().Select(x => x.Id).ToList();
        if (selectedInterfaces.Count == 0) selectedInterfaces.Add("all");
        if (selectedInterfaces.Contains("all", StringComparer.OrdinalIgnoreCase)) selectedInterfaces = ["all"];

        var ports = new List<int>();
        var rawPorts = ExtraTlsPortsTextBox.Text.Trim();
        if (!string.IsNullOrWhiteSpace(rawPorts))
        {
            foreach (var part in rawPorts.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (!int.TryParse(part, out var port) || port is < 1 or > 65535)
                    throw new InvalidOperationException($"Invalid TLS port: {part}");
                ports.Add(port);
            }
        }

        var outDir = OutputDirectoryTextBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(outDir))
            throw new InvalidOperationException("Output directory is required.");

        return new SnifferOptions(
            pid,
            processName,
            IncludeChildrenCheckBox.IsChecked == true,
            selectedInterfaces,
            string.IsNullOrWhiteSpace(TsharkPathTextBox.Text) ? null : TsharkPathTextBox.Text.Trim(),
            outDir,
            ShowRepeatsCheckBox.IsChecked == true,
            ports.Distinct().ToArray());
    }

    private void ServiceOnLog(LogMessage log)
    {
        Dispatcher.Invoke(() => AddLog(log.Level, log.Message, log.Timestamp));
    }

    private void ServiceOnObservation(DomainObservation observation)
    {
        Dispatcher.Invoke(() =>
        {
            AddWithCap(_eventRows, new ObservationRow
            {
                Time = observation.Timestamp.ToString("HH:mm:ss"),
                Source = observation.Source,
                Pid = observation.Pid,
                Domain = observation.Domain,
                Protocol = observation.Protocol ?? "-",
                Local = observation.Local ?? "-",
                Remote = observation.Remote ?? "-"
            }, 4000);

            if (!_domainIndex.TryGetValue(observation.Domain, out var row))
            {
                row = new DomainCountRow { Domain = observation.Domain, Count = 0, Sources = observation.Source };
                _domainIndex[observation.Domain] = row;
                _domainSources[observation.Domain] = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { observation.Source };
                _domainRows.Add(row);
            }

            row.Count++;
            _domainSources[observation.Domain].Add(observation.Source);
            row.Sources = string.Join(", ", _domainSources[observation.Domain].OrderBy(x => x));

            UpdateDomainIpRow(observation);
            RefreshFilteredViews();
        });
    }

    private void ServiceOnNetworkPacket(NetworkPacketObservation packet)
    {
        _networkPacketQueue.Enqueue(packet);
    }

    private void NetworkUiTimer_OnTick(object? sender, EventArgs e)
    {
        if (_isClosing) return;

        var added = 0;
        while (added < 600 && _networkPacketQueue.TryDequeue(out var packet))
        {
            var row = new NetworkPacketRow
            {
                // Show the moment the row reaches the UI. This avoids visually stale
                // timestamps when TShark/ETW decoding or the UI queue is briefly busy.
                Time = DateTimeOffset.Now.ToString("HH:mm:ss"),
                SourceIp = packet.SourceIp,
                DestinationIp = packet.DestinationIp,
                DestinationPort = packet.DestinationPort,
                Protocol = packet.Protocol,
                Domain = ResolvePacketDomain(packet),
                Requests = 1,
                RemoteIp = packet.RemoteIp,
                RemotePort = packet.RemotePort
            };

            AddWithCap(_networkRows, row, 100000);
            UpsertUniqueNetworkRow(row);
            added++;
        }

        if (added > 0)
        {
            NetworkGrid.Items.Refresh();
            _networkViewSource.View.Refresh();
        }
    }

    private void UpsertUniqueNetworkRow(NetworkPacketRow row)
    {
        var key = GetNetworkUniqueKey(row);
        if (_networkUniqueIndex.TryGetValue(key, out var existing))
        {
            existing.Time = row.Time;
            existing.Requests += row.Requests;
            return;
        }

        var ignoreSource = IgnoreSourceIpNetworkCheckBox?.IsChecked == true;
        var copy = new NetworkPacketRow
        {
            Time = row.Time,
            SourceIp = row.SourceIp,
            // In source-ignored unique mode, display the normalized remote endpoint
            // instead of whichever raw packet direction happened to arrive first.
            DestinationIp = ignoreSource && !string.IsNullOrWhiteSpace(row.RemoteIp) ? row.RemoteIp : row.DestinationIp,
            DestinationPort = ignoreSource && row.RemotePort > 0 ? row.RemotePort : row.DestinationPort,
            Protocol = row.Protocol,
            Domain = row.Domain,
            Requests = row.Requests,
            RemoteIp = row.RemoteIp,
            RemotePort = row.RemotePort
        };

        _networkUniqueIndex[key] = copy;
        AddWithCap(_networkUniqueRows, copy, 100000);
    }

    private string GetNetworkUniqueKey(NetworkPacketRow row)
    {
        var ignoreSource = IgnoreSourceIpNetworkCheckBox?.IsChecked == true;
        var ignorePort = IgnoreDestinationPortNetworkCheckBox?.IsChecked == true;
        var protocol = row.Protocol.ToLowerInvariant();
        var domain = row.Domain.ToLowerInvariant();

        if (ignoreSource)
        {
            // RemoteIp/RemotePort are normalized by the core regardless of packet direction.
            var remoteIp = row.RemoteIp.ToLowerInvariant();
            return ignorePort
                ? $"{remoteIp}|{protocol}|{domain}"
                : $"{remoteIp}|{row.RemotePort}|{protocol}|{domain}";
        }

        var sourceIp = row.SourceIp.ToLowerInvariant();
        var destinationIp = row.DestinationIp.ToLowerInvariant();
        return ignorePort
            ? $"{sourceIp}|{destinationIp}|{protocol}|{domain}"
            : $"{sourceIp}|{destinationIp}|{row.DestinationPort}|{protocol}|{domain}";
    }

    private void RebuildUniqueNetworkRows()
    {
        _networkUniqueRows.Clear();
        _networkUniqueIndex.Clear();
        foreach (var row in _networkRows)
            UpsertUniqueNetworkRow(row);
    }

    private void ApplyNetworkSource()
    {
        _networkViewSource.Source = UniqueNetworkCheckBox?.IsChecked == true ? _networkUniqueRows : _networkRows;
        NetworkGrid.ItemsSource = _networkViewSource.View;
        _networkViewSource.View.Refresh();
    }

    private void RememberGuiIpDomain(string ip, string domain)
    {
        _ipDomainLookup[ip] = domain;

        var changed = false;
        foreach (var row in _networkRows)
        {
            if (row.Domain != "—") continue;
            if (!string.Equals(row.SourceIp, ip, StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(row.DestinationIp, ip, StringComparison.OrdinalIgnoreCase)) continue;
            row.Domain = domain;
            changed = true;
        }

        if (changed)
        {
            RebuildUniqueNetworkRows();
            NetworkGrid.Items.Refresh();
            _networkViewSource.View.Refresh();
        }
    }

    private string ResolvePacketDomain(NetworkPacketObservation packet)
    {
        if (!string.IsNullOrWhiteSpace(packet.Domain)) return packet.Domain!;
        if (_ipDomainLookup.TryGetValue(packet.DestinationIp, out var domain)) return domain;
        if (_ipDomainLookup.TryGetValue(packet.SourceIp, out domain)) return domain;
        return "—";
    }

    private void UpdateDomainIpRow(DomainObservation observation)
    {
        if (string.IsNullOrWhiteSpace(observation.Domain) || IsLocalLikeDomain(observation.Domain))
            return;

        if (!_domainIpIndex.TryGetValue(observation.Domain, out var row))
        {
            row = new DomainIpRow
            {
                Domain = observation.Domain,
                ResolvedIps = "—",
                IpCount = 0,
                Status = "UNRESOLVED",
                Sources = observation.Source
            };
            _domainIpIndex[observation.Domain] = row;
            _domainIpAddresses[observation.Domain] = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _domainIpSources[observation.Domain] = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _domainIpRows.Add(row);
        }

        _domainIpSources[observation.Domain].Add(observation.Source);

        if (observation.ResolvedIps is not null)
        {
            foreach (var rawIp in observation.ResolvedIps)
            {
                if (TryNormalizeRelevantIp(rawIp, out var normalized))
                {
                    _domainIpAddresses[observation.Domain].Add(normalized);
                    RememberGuiIpDomain(normalized, observation.Domain);
                }
            }
        }

        RefreshDomainIpRow(observation.Domain);

        // Telemetry can legitimately miss the DNS answer (cache, race, encrypted DNS, etc.).
        // Actively resolve the observed hostname as a fallback. The per-domain cooldown avoids
        // hammering the resolver when the same hostname is observed repeatedly.
        ScheduleActiveDnsResolve(observation.Domain);
    }

    private void RefreshDomainIpRow(string domain)
    {
        if (!_domainIpIndex.TryGetValue(domain, out var row)) return;

        var ips = _domainIpAddresses[domain]
            .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        row.ResolvedIps = ips.Length == 0 ? "—" : string.Join(", ", ips);
        row.IpCount = ips.Length;
        row.Status = ips.Length > 0 ? "RESOLVED" : "UNRESOLVED";
        row.Sources = string.Join(", ", _domainIpSources[domain].OrderBy(x => x));
        _domainIpsViewSource.View.Refresh();
    }

    private void ScheduleActiveDnsResolve(string domain)
    {
        if (_isClosing || string.IsNullOrWhiteSpace(domain) || IsLocalLikeDomain(domain)) return;

        var now = DateTimeOffset.UtcNow;
        if (_activeDnsResolveInProgress.Contains(domain)) return;
        if (_lastActiveDnsResolve.TryGetValue(domain, out var last) && now - last < TimeSpan.FromSeconds(30)) return;

        _lastActiveDnsResolve[domain] = now;
        _activeDnsResolveInProgress.Add(domain);
        _ = ResolveDomainFallbackAsync(domain);
    }

    private async Task ResolveDomainFallbackAsync(string domain)
    {
        try
        {
            var addresses = await Dns.GetHostAddressesAsync(domain)
                .WaitAsync(TimeSpan.FromSeconds(3));
            if (_isClosing) return;

            await Dispatcher.InvokeAsync(() =>
            {
                if (!_domainIpIndex.ContainsKey(domain)) return;

                var added = false;
                foreach (var ip in addresses)
                {
                    if (!TryNormalizeRelevantIp(ip.ToString(), out var normalized)) continue;
                    if (_domainIpAddresses[domain].Add(normalized)) added = true;
                    RememberGuiIpDomain(normalized, domain);
                }

                if (addresses.Length > 0)
                    _domainIpSources[domain].Add("ACTIVE-DNS");

                if (added || addresses.Length > 0)
                    RefreshDomainIpRow(domain);
            });
        }
        catch (Exception ex) when (ex is System.Net.Sockets.SocketException or ArgumentException or TimeoutException)
        {
            // Resolution failures are expected for transient/non-resolvable names. Keep the row as UNRESOLVED.
        }
        finally
        {
            if (!_isClosing)
            {
                await Dispatcher.InvokeAsync(() => _activeDnsResolveInProgress.Remove(domain));
            }
        }
    }

    private void ServiceOnTargetsChanged(IReadOnlyCollection<int> pids)
    {
        Dispatcher.Invoke(() =>
        {
            TrackedPidsTextBlock.Text = pids.Count == 0
                ? "Tracked PIDs: waiting..."
                : $"Tracked PIDs: {string.Join(", ", pids)}";
        });
    }

    private void AddLog(string level, string message, DateTimeOffset? timestamp = null)
    {
        AddWithCap(_logRows, new LogRow
        {
            Time = (timestamp ?? DateTimeOffset.Now).ToString("HH:mm:ss"),
            Level = level,
            Message = message
        }, 3000);
    }

    private static void AddWithCap<T>(ObservableCollection<T> collection, T item, int max)
    {
        collection.Add(item);
        while (collection.Count > max)
            collection.RemoveAt(0);
    }

    private void RefreshFilteredViews()
    {
        _eventsViewSource.View.Refresh();
        _domainsViewSource.View.Refresh();
        _domainIpsViewSource.View.Refresh();
        _networkViewSource.View.Refresh();
        _logsViewSource.View.Refresh();
        UpdateDomainCounts();
    }

    private void UpdateDomainCounts()
    {
        var total = _domainRows.Count;
        var shown = GetVisibleDomainRows().Count();
        UniqueDomainsTextBlock.Text = $"Unique domains: {shown} shown / {total} total";
    }

    private IEnumerable<ObservationRow> GetVisibleLiveRows() => _eventRows.Where(ShouldShowLiveRow);

    private IEnumerable<DomainCountRow> GetVisibleDomainRows() => _domainRows.Where(ShouldShowDomainRow);

    private bool ShouldShowLiveRow(ObservationRow row)
    {
        var showLocal = ShowLocalhostInLiveCheckBox.IsChecked == true;
        return showLocal || !IsLocalLikeDomain(row.Domain);
    }

    private bool ShouldShowDomainRow(DomainCountRow row)
    {
        var hideLocal = HideLocalhostInSummaryCheckBox.IsChecked == true;
        return !hideLocal || !IsLocalLikeDomain(row.Domain);
    }

    private static bool IsLocalLikeDomain(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        var d = value.Trim().Trim('.').ToLowerInvariant();
        if (d == "localhost" || d.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase)) return true;
        if (d.EndsWith(".local", StringComparison.OrdinalIgnoreCase)) return true;
        if (d.EndsWith(".lan", StringComparison.OrdinalIgnoreCase)) return true;
        if (d.EndsWith(".home.arpa", StringComparison.OrdinalIgnoreCase)) return true;
        if (d.EndsWith(".internal", StringComparison.OrdinalIgnoreCase)) return true;
        if (!d.Contains('.')) return true;
        return false;
    }

    private static bool TryNormalizeRelevantIp(string? value, out string normalized)
    {
        normalized = string.Empty;
        if (!IPAddress.TryParse(value, out var ip)) return false;
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (IPAddress.IsLoopback(ip)) return false;
        if (ip.IsIPv6LinkLocal || ip.IsIPv6Multicast || ip.IsIPv6SiteLocal) return false;

        var b = ip.GetAddressBytes();
        if (b.Length == 4)
        {
            // Preserve this network-specific sinkhole range so it can be surfaced as FILTERED.
            if (b[0] == 10 && b[1] == 10 && b[2] == 34)
            {
                normalized = ip.ToString();
                return true;
            }

            // Other RFC1918 / non-public addresses are intentionally hidden.
            if (b[0] == 10) return false;
            if (b[0] == 172 && b[1] is >= 16 and <= 31) return false;
            if (b[0] == 192 && b[1] == 168) return false;
            if (b[0] == 127) return false;
            if (b[0] == 169 && b[1] == 254) return false;
            if (b[0] == 100 && b[1] is >= 64 and <= 127) return false;
            if (b[0] == 0 || b[0] >= 224) return false;
        }
        else if (b.Length == 16)
        {
            if ((b[0] & 0xFE) == 0xFC) return false;
            if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) return false;
            if (b[0] == 0xFF) return false;
        }
        else
        {
            return false;
        }

        normalized = ip.ToString().ToLowerInvariant();
        return true;
    }


    private async void RefreshProcessesButton_OnClick(object sender, RoutedEventArgs e) => await RefreshProcessListAsync(force: true);

    private void ProcessSearchTextBox_OnTextChanged(object sender, TextChangedEventArgs e) => _processesViewSource.View.Refresh();
    private void LiveSearchTextBox_OnTextChanged(object sender, TextChangedEventArgs e) => _eventsViewSource.View.Refresh();
    private void DomainsSearchTextBox_OnTextChanged(object sender, TextChangedEventArgs e) => _domainsViewSource.View.Refresh();
    private void DomainIpSearchTextBox_OnTextChanged(object sender, TextChangedEventArgs e) => _domainIpsViewSource.View.Refresh();
    private void NetworkSearchTextBox_OnTextChanged(object sender, TextChangedEventArgs e) => _networkViewSource.View.Refresh();

    private void NetworkOptions_OnChanged(object sender, RoutedEventArgs e)
    {
        if (!_uiReady) return;

        if (NetworkSourceIpColumn is not null)
            NetworkSourceIpColumn.Visibility = IgnoreSourceIpNetworkCheckBox.IsChecked == true
                ? Visibility.Collapsed
                : Visibility.Visible;

        if (NetworkDestinationPortColumn is not null)
            NetworkDestinationPortColumn.Visibility = IgnoreDestinationPortNetworkCheckBox.IsChecked == true
                ? Visibility.Collapsed
                : Visibility.Visible;

        if (UniqueNetworkCheckBox.IsChecked == true)
            RebuildUniqueNetworkRows();
        ApplyNetworkSource();
    }
    private void LogSearchTextBox_OnTextChanged(object sender, TextChangedEventArgs e) => _logsViewSource.View.Refresh();

    private void TargetTextBox_OnTextChanged(object sender, TextChangedEventArgs e)
    {
        if (_uiReady) UpdateTargetCaptureDisplay();
    }

    private void TargetSelection_OnChanged(object sender, RoutedEventArgs e)
    {
        if (_uiReady) UpdateTargetCaptureDisplay();
    }

    private void UpdateTargetCaptureDisplay()
    {
        var label = _service?.IsRunning == true && !string.IsNullOrWhiteSpace(_activeCaptureTargetName)
            ? _activeCaptureTargetName
            : GetCurrentTargetName();

        TargetCaptureTextBlock.Text = string.IsNullOrWhiteSpace(label) ? "Not selected" : label;
    }

    private string GetCurrentTargetName()
    {
        if (TrackByPidRadio.IsChecked == true && int.TryParse(PidTextBox.Text.Trim(), out var pid) && pid > 0)
        {
            var matching = _allProcesses.FirstOrDefault(x => x.Pid == pid);
            return matching?.Name ?? $"PID-{pid}";
        }

        var raw = ProcessNameTextBox.Text.Trim();
        if (!string.IsNullOrWhiteSpace(raw))
            return Path.GetFileNameWithoutExtension(raw);

        if (ProcessesGrid.SelectedItem is ProcessDescriptor selected)
            return selected.Name;

        return string.Empty;
    }

    private void UseSelectedPidButton_OnClick(object sender, RoutedEventArgs e)
    {
        if (ProcessesGrid.SelectedItem is ProcessDescriptor proc)
        {
            FillTargetFields(proc);
            TrackByPidRadio.IsChecked = true;
        }
    }

    private void UseSelectedNameButton_OnClick(object sender, RoutedEventArgs e)
    {
        if (ProcessesGrid.SelectedItem is ProcessDescriptor proc)
        {
            FillTargetFields(proc);
            TrackByProcessNameRadio.IsChecked = true;
        }
    }

    private void ProcessesGrid_OnMouseDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (ProcessesGrid.SelectedItem is ProcessDescriptor proc)
        {
            FillTargetFields(proc);
            TrackByProcessNameRadio.IsChecked = true;
        }
    }

    private void BrowseExeButton_OnClick(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Filter = "Executable files (*.exe)|*.exe|All files (*.*)|*.*",
            Title = "Select target executable"
        };

        if (dialog.ShowDialog(this) == true)
        {
            ProcessNameTextBox.Text = Path.GetFileName(dialog.FileName);
            TrackByProcessNameRadio.IsChecked = true;
            TargetCaptureTextBlock.Text = Path.GetFileNameWithoutExtension(dialog.FileName);
        }
    }

    private async void BrowseTsharkButton_OnClick(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Filter = "tshark.exe|tshark.exe|Executable files (*.exe)|*.exe",
            Title = "Select tshark.exe"
        };
        if (dialog.ShowDialog(this) == true)
        {
            TsharkPathTextBox.Text = dialog.FileName;
            UpdateTsharkStatus();
            await LoadInterfacesAsync();
        }
    }

    private void BrowseOutputDirectoryButton_OnClick(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog
        {
            Title = "Select output folder",
            InitialDirectory = Directory.Exists(OutputDirectoryTextBox.Text.Trim())
                ? OutputDirectoryTextBox.Text.Trim()
                : Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory)
        };

        if (dialog.ShowDialog(this) == true)
        {
            OutputDirectoryTextBox.Text = dialog.FolderName;
            OutputFolderStatusTextBlock.Text = dialog.FolderName;
        }
    }

    private void OpenOutputFolderButton_OnClick(object sender, RoutedEventArgs e)
    {
        var path = OutputDirectoryTextBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(path)) return;
        Directory.CreateDirectory(path);
        Process.Start(new ProcessStartInfo
        {
            FileName = path,
            UseShellExecute = true
        });
    }

    private void FilterOptions_OnChanged(object sender, RoutedEventArgs e)
    {
        if (!_uiReady) return;
        SyncFilterCheckBoxes();
        RefreshFilteredViews();
    }

    private void LiveShowLocalhostCheckBoxMirror_OnChanged(object sender, RoutedEventArgs e)
    {
        if (!_uiReady) return;
        ShowLocalhostInLiveCheckBox.IsChecked = LiveShowLocalhostCheckBoxMirror.IsChecked;
        RefreshFilteredViews();
    }

    private void DomainsHideLocalhostCheckBoxMirror_OnChanged(object sender, RoutedEventArgs e)
    {
        if (!_uiReady) return;
        HideLocalhostInSummaryCheckBox.IsChecked = DomainsHideLocalhostCheckBoxMirror.IsChecked;
        RefreshFilteredViews();
    }

    private void SyncFilterCheckBoxes()
    {
        LiveShowLocalhostCheckBoxMirror.IsChecked = ShowLocalhostInLiveCheckBox.IsChecked;
        DomainsHideLocalhostCheckBoxMirror.IsChecked = HideLocalhostInSummaryCheckBox.IsChecked;
    }

    private void OpenTargetTabButton_OnClick(object sender, RoutedEventArgs e) => WorkspaceTabs.SelectedIndex = 0;
    private void OpenCaptureSettingsTabButton_OnClick(object sender, RoutedEventArgs e) => WorkspaceTabs.SelectedIndex = 1;
    private void OpenLiveEventsTabButton_OnClick(object sender, RoutedEventArgs e) => WorkspaceTabs.SelectedIndex = 3;
    private void OpenDomainsTabButton_OnClick(object sender, RoutedEventArgs e) => WorkspaceTabs.SelectedIndex = 4;
    private void OpenDomainIpTabButton_OnClick(object sender, RoutedEventArgs e) => WorkspaceTabs.SelectedIndex = 5;
    private void OpenNetworkTabButton_OnClick(object sender, RoutedEventArgs e) => WorkspaceTabs.SelectedIndex = 6;

    // Copy = selected rows only. Copy All = the entire visible tab. Export = the entire visible tab.
    private void CopyLiveEventsButton_OnClick(object sender, RoutedEventArgs e) =>
        CopySelected(BuildLiveEventsText, EventsGrid.SelectedItems.Cast<ObservationRow>().ToList(), "live event");

    private void CopyAllLiveEventsButton_OnClick(object sender, RoutedEventArgs e)
    {
        var rows = GetVisibleLiveRows().ToList();
        CopyAll(BuildLiveEventsText(rows), rows.Count, "live events");
    }

    private void CopyDomainsButton_OnClick(object sender, RoutedEventArgs e) =>
        CopySelected(BuildDomainsText, DomainsGrid.SelectedItems.Cast<DomainCountRow>().ToList(), "domain");

    private void CopyAllDomainsButton_OnClick(object sender, RoutedEventArgs e)
    {
        var rows = GetVisibleDomainRows().ToList();
        CopyAll(BuildDomainsText(rows), rows.Count, "domains");
    }

    private void CopyDomainIpsButton_OnClick(object sender, RoutedEventArgs e) =>
        CopySelected(BuildDomainIpsText, DomainIpsGrid.SelectedItems.Cast<DomainIpRow>().ToList(), "domain + IP row");

    private void CopyAllDomainIpsButton_OnClick(object sender, RoutedEventArgs e)
    {
        var rows = _domainIpRows.ToList();
        CopyAll(BuildDomainIpsText(rows), rows.Count, "domain + IP rows");
    }

    private void CopyNetworkButton_OnClick(object sender, RoutedEventArgs e) =>
        CopySelected(BuildNetworkText, NetworkGrid.SelectedItems.Cast<NetworkPacketRow>().ToList(), "network row");

    private void CopyAllNetworkButton_OnClick(object sender, RoutedEventArgs e)
    {
        var rows = GetVisibleNetworkRows().ToList();
        CopyAll(BuildNetworkText(rows), rows.Count, "network rows");
    }

    private void CopyLogsButton_OnClick(object sender, RoutedEventArgs e) =>
        CopySelected(BuildLogsText, LogGrid.SelectedItems.Cast<LogRow>().ToList(), "log entry");

    private void CopyAllLogsButton_OnClick(object sender, RoutedEventArgs e)
    {
        var rows = _logRows.ToList();
        CopyAll(BuildLogsText(rows), rows.Count, "log entries");
    }

    private void ExportLiveEventsButton_OnClick(object sender, RoutedEventArgs e)
    {
        var rows = GetVisibleLiveRows().ToList();
        ExportRows(rows, "Export all live events", (list, ext) => ext switch
        {
            ".json" => JsonSerializer.Serialize(list, JsonOptions()),
            ".txt" => BuildLiveEventsText(list),
            _ => BuildLiveEventsCsv(list)
        });
    }

    private void ExportDomainsButton_OnClick(object sender, RoutedEventArgs e)
    {
        var rows = GetVisibleDomainRows().ToList();
        ExportRows(rows, "Export all captured domains", (list, ext) => ext switch
        {
            ".json" => JsonSerializer.Serialize(list, JsonOptions()),
            ".txt" => BuildDomainsText(list),
            _ => BuildDomainsCsv(list)
        });
    }

    private void ExportDomainIpsButton_OnClick(object sender, RoutedEventArgs e)
    {
        var rows = _domainIpRows.ToList();
        ExportRows(rows, "Export all domains and public IPs", (list, ext) => ext switch
        {
            ".json" => JsonSerializer.Serialize(list, JsonOptions()),
            ".txt" => BuildDomainIpsText(list),
            _ => BuildDomainIpsCsv(list)
        });
    }

    private void ExportNetworkButton_OnClick(object sender, RoutedEventArgs e)
    {
        var rows = GetVisibleNetworkRows().ToList();
        ExportRows(rows, "Export complete network log", (list, ext) => ext switch
        {
            ".json" => JsonSerializer.Serialize(list, JsonOptions()),
            ".txt" => BuildNetworkText(list),
            _ => BuildNetworkCsv(list)
        });
    }

    private void ExportLogsButton_OnClick(object sender, RoutedEventArgs e)
    {
        var rows = _logRows.ToList();
        ExportRows(rows, "Export complete activity log", (list, ext) => ext switch
        {
            ".json" => JsonSerializer.Serialize(list, JsonOptions()),
            ".txt" => BuildLogsText(list),
            _ => BuildLogsCsv(list)
        });
    }

    private void CopySelected<T>(Func<IEnumerable<T>, string> builder, List<T> rows, string label)
    {
        if (rows.Count == 0)
        {
            MessageBox.Show(this, $"Select a {label} first, or use Copy All.", "Nothing selected", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        Clipboard.SetText(builder(rows));
        AddLog("INFO", $"Copied {rows.Count} selected {label}(s) to clipboard.");
        ShowToast($"Copied {rows.Count} {label}(s)");
    }

    private void CopyAll(string text, int itemCount, string label)
    {
        if (itemCount == 0)
        {
            MessageBox.Show(this, $"No {label} available to copy.", "Nothing to copy", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        Clipboard.SetText(text);
        AddLog("INFO", $"Copied all {itemCount} {label} to clipboard.");
        ShowToast($"Copied all {itemCount} {label}");
    }

    private void ExportRows<T>(List<T> rows, string title, Func<List<T>, string, string> contentFactory)
    {
        if (rows.Count == 0)
        {
            MessageBox.Show(this, "There is nothing to export.", "Nothing to export", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var dialog = new SaveFileDialog
        {
            Title = title,
            Filter = "CSV file (*.csv)|*.csv|JSON file (*.json)|*.json|Text file (*.txt)|*.txt",
            FileName = GetExportBaseFileName(),
            DefaultExt = ".csv",
            AddExtension = true,
            OverwritePrompt = true,
            InitialDirectory = Directory.Exists(OutputDirectoryTextBox.Text.Trim())
                ? OutputDirectoryTextBox.Text.Trim()
                : Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory)
        };

        if (dialog.ShowDialog(this) != true)
            return;

        var ext = Path.GetExtension(dialog.FileName).ToLowerInvariant();
        var content = contentFactory(rows, ext);
        File.WriteAllText(dialog.FileName, content, new UTF8Encoding(false));
        AddLog("INFO", $"Exported all {rows.Count} rows to {dialog.FileName}");
    }

    private string GetExportBaseFileName()
    {
        var target = !string.IsNullOrWhiteSpace(_activeCaptureTargetName)
            ? _activeCaptureTargetName!
            : GetCurrentTargetName();

        if (string.IsNullOrWhiteSpace(target))
            target = "ProcDomainSniffer";

        foreach (var invalid in Path.GetInvalidFileNameChars())
            target = target.Replace(invalid, '_');

        target = target.Trim().Trim('.');
        if (string.IsNullOrWhiteSpace(target)) target = "ProcDomainSniffer";

        return $"{target}-{DateTime.Now:yyyyMMdd-HHmmss}";
    }

    private static JsonSerializerOptions JsonOptions() => new() { WriteIndented = true };

    private static string BuildLiveEventsText(IEnumerable<ObservationRow> rows)
    {
        var sb = new StringBuilder();
        foreach (var row in rows)
            sb.AppendLine($"{row.Time}\t{row.Source}\t{row.Pid}\t{row.Domain}\t{row.Protocol}\t{row.Local}\t{row.Remote}");
        return sb.ToString();
    }

    private static string BuildDomainsText(IEnumerable<DomainCountRow> rows)
    {
        var sb = new StringBuilder();
        foreach (var row in rows)
            sb.AppendLine($"{row.Domain}\t{row.Count}\t{row.Sources}");
        return sb.ToString();
    }

    private static string BuildDomainIpsText(IEnumerable<DomainIpRow> rows)
    {
        var sb = new StringBuilder();
        foreach (var row in rows)
            sb.AppendLine($"{row.Domain}\t{row.ResolvedIps}\t{row.IpCount}\t{row.Status}\t{row.Sources}");
        return sb.ToString();
    }

    private static string BuildNetworkText(IEnumerable<NetworkPacketRow> rows)
    {
        var sb = new StringBuilder();
        foreach (var row in rows)
            sb.AppendLine($"{row.Time}	{row.SourceIp}	{row.DestinationIp}	{row.DestinationPort}	{row.Protocol}	{row.Domain}	{row.Requests}");
        return sb.ToString();
    }

    private static string BuildLogsText(IEnumerable<LogRow> rows)
    {
        var sb = new StringBuilder();
        foreach (var row in rows)
            sb.AppendLine($"{row.Time}\t{row.Level}\t{row.Message}");
        return sb.ToString();
    }

    private static string BuildLiveEventsCsv(IEnumerable<ObservationRow> rows)
    {
        var sb = new StringBuilder();
        sb.AppendLine("Time,Source,Pid,Domain,Protocol,Local,Remote");
        foreach (var row in rows)
            sb.AppendLine(string.Join(',', Csv(row.Time), Csv(row.Source), Csv(row.Pid), Csv(row.Domain), Csv(row.Protocol), Csv(row.Local), Csv(row.Remote)));
        return sb.ToString();
    }

    private static string BuildDomainsCsv(IEnumerable<DomainCountRow> rows)
    {
        var sb = new StringBuilder();
        sb.AppendLine("Domain,Count,Sources");
        foreach (var row in rows)
            sb.AppendLine(string.Join(',', Csv(row.Domain), Csv(row.Count), Csv(row.Sources)));
        return sb.ToString();
    }

    private static string BuildDomainIpsCsv(IEnumerable<DomainIpRow> rows)
    {
        var sb = new StringBuilder();
        sb.AppendLine("Domain,ResolvedIps,IpCount,Status,Sources");
        foreach (var row in rows)
            sb.AppendLine(string.Join(',', Csv(row.Domain), Csv(row.ResolvedIps), Csv(row.IpCount), Csv(row.Status), Csv(row.Sources)));
        return sb.ToString();
    }

    private static string BuildNetworkCsv(IEnumerable<NetworkPacketRow> rows)
    {
        var sb = new StringBuilder();
        sb.AppendLine("Time,SourceIp,DestinationIp,DestinationPort,Protocol,Domain,Requests");
        foreach (var row in rows)
            sb.AppendLine(string.Join(',', Csv(row.Time), Csv(row.SourceIp), Csv(row.DestinationIp), Csv(row.DestinationPort), Csv(row.Protocol), Csv(row.Domain), Csv(row.Requests)));
        return sb.ToString();
    }

    private static string BuildLogsCsv(IEnumerable<LogRow> rows)
    {
        var sb = new StringBuilder();
        sb.AppendLine("Time,Level,Message");
        foreach (var row in rows)
            sb.AppendLine(string.Join(',', Csv(row.Time), Csv(row.Level), Csv(row.Message)));
        return sb.ToString();
    }

    private static string Csv(object? value)
    {
        var s = value?.ToString() ?? string.Empty;
        return '"' + s.Replace("\"", "\"\"") + '"';
    }

    private void DataGrid_OnPreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key != Key.C || Keyboard.Modifiers != ModifierKeys.Control) return;
        if (sender is not DataGrid grid) return;

        switch (grid.Name)
        {
            case nameof(EventsGrid):
                CopySelected(BuildLiveEventsText, EventsGrid.SelectedItems.Cast<ObservationRow>().ToList(), "live event");
                break;
            case nameof(DomainsGrid):
                CopySelected(BuildDomainsText, DomainsGrid.SelectedItems.Cast<DomainCountRow>().ToList(), "domain");
                break;
            case nameof(DomainIpsGrid):
                CopySelected(BuildDomainIpsText, DomainIpsGrid.SelectedItems.Cast<DomainIpRow>().ToList(), "domain + IP row");
                break;
            case nameof(NetworkGrid):
                CopySelected(BuildNetworkText, NetworkGrid.SelectedItems.Cast<NetworkPacketRow>().ToList(), "network row");
                break;
            case nameof(LogGrid):
                CopySelected(BuildLogsText, LogGrid.SelectedItems.Cast<LogRow>().ToList(), "log entry");
                break;
            default:
                return;
        }

        e.Handled = true;
    }

    private void DataGrid_OnMouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (sender is not DataGrid grid) return;
        var cell = FindVisualParent<DataGridCell>(e.OriginalSource as DependencyObject);
        if (cell is null) return;

        var text = ExtractCellText(cell);
        if (string.IsNullOrWhiteSpace(text)) return;

        Clipboard.SetText(text);
        ShowToast($"Copied: {TruncateForToast(text)}");
        e.Handled = true;
    }

    private static T? FindVisualParent<T>(DependencyObject? child) where T : DependencyObject
    {
        var current = child;
        while (current is not null)
        {
            if (current is T wanted) return wanted;
            current = VisualTreeHelper.GetParent(current);
        }
        return null;
    }

    private static string ExtractCellText(DataGridCell cell)
    {
        if (cell.Content is TextBlock textBlock) return textBlock.Text?.Trim() ?? string.Empty;
        if (cell.Content is TextBox textBox) return textBox.Text?.Trim() ?? string.Empty;

        var nestedText = FindVisualChild<TextBlock>(cell);
        if (nestedText is not null) return nestedText.Text?.Trim() ?? string.Empty;

        return cell.Content?.ToString()?.Trim() ?? string.Empty;
    }

    private static T? FindVisualChild<T>(DependencyObject parent) where T : DependencyObject
    {
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
        {
            var child = VisualTreeHelper.GetChild(parent, i);
            if (child is T wanted) return wanted;
            var nested = FindVisualChild<T>(child);
            if (nested is not null) return nested;
        }
        return null;
    }

    private async void ShowToast(string message)
    {
        _toastCts?.Cancel();
        _toastCts?.Dispose();
        _toastCts = new CancellationTokenSource();
        var token = _toastCts.Token;

        ToastTextBlock.Text = message;
        ToastBorder.Visibility = Visibility.Visible;
        ToastBorder.Opacity = 1;

        try
        {
            await Task.Delay(1700, token);
            if (token.IsCancellationRequested) return;
            ToastBorder.Visibility = Visibility.Collapsed;
        }
        catch (OperationCanceledException)
        {
        }
    }

    private static string TruncateForToast(string value)
    {
        var cleaned = value.Replace("\r", " ").Replace("\n", " ").Trim();
        return cleaned.Length <= 72 ? cleaned : cleaned[..69] + "...";
    }

    private void MinimizeButton_OnClick(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    private void MaximizeButton_OnClick(object sender, RoutedEventArgs e)
    {
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
    }

    private void CloseButton_OnClick(object sender, RoutedEventArgs e) => Close();

    private void TitleBar_OnMouseLeftButtonDown(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (e.ChangedButton != System.Windows.Input.MouseButton.Left)
            return;

        if (e.ClickCount == 2)
        {
            WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
            return;
        }

        try { DragMove(); } catch { }
    }
}
