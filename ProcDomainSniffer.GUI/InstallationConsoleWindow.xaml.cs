using System.ComponentModel;
using System.Diagnostics;
using System.Text;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;

namespace ProcDomainSniffer.GUI;

/// <summary>
/// Independent, non-modal WPF terminal window for streaming the actual winget
/// stdout/stderr and the app's dependency verification steps.
/// </summary>
public partial class InstallationConsoleWindow : Window
{
    private const int MaxVisibleChars = 180_000;
    private readonly Stopwatch _clock = Stopwatch.StartNew();
    private readonly DispatcherTimer _elapsedTimer;
    private readonly StringBuilder _fullLog = new();
    private bool _completed;

    public InstallationConsoleWindow()
    {
        InitializeComponent();
        _elapsedTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _elapsedTimer.Tick += (_, _) =>
        {
            ElapsedTextBlock.Text = $"Elapsed: {_clock.Elapsed:hh\\:mm\\:ss}";
        };
        _elapsedTimer.Start();
        Closing += InstallationConsoleWindow_OnClosing;

        AppendSystem("Dependency installation console started.");
        AppendSystem("All output below comes from winget or explicit application checks.");
        AppendSystem("Command: " + WiresharkInstaller.CommandDescription);
        AppendSystem("The Wireshark setup wizard may open separately; its internal UI is not piped into this log.");
    }

    public void SetStage(string description)
    {
        if (Dispatcher.CheckAccess()) StageTextBlock.Text = description;
        else Dispatcher.BeginInvoke(new Action(() => SetStage(description)));
    }

    public void AppendSystem(string message) => Append("[STEP]", message);

    public void AppendOutput(string line, bool isError) =>
        Append(isError ? "[STDERR]" : "[STDOUT]", line);

    public void Complete(bool successful, string summary)
    {
        if (!Dispatcher.CheckAccess())
        {
            Dispatcher.BeginInvoke(new Action(() => Complete(successful, summary)));
            return;
        }

        if (_completed) return;
        Append(successful ? "[SUCCESS]" : "[FAILED]", summary);
        StageTextBlock.Text = summary;
        InstallStateBadge.Text = successful ? "SUCCESS" : "ACTION REQUIRED";
        InstallStateBadge.Foreground = new SolidColorBrush(
            successful ? Color.FromRgb(0x8D, 0xE8, 0xAC) : Color.FromRgb(0xFF, 0xB2, 0x9B));
        InstallProgressBar.IsIndeterminate = false;
        InstallProgressBar.Visibility = Visibility.Collapsed;
        _completed = true;
        CloseInstallerButton.IsEnabled = true;
        _clock.Stop();
        _elapsedTimer.Stop();
        Activate();
    }

    private void Append(string prefix, string message)
    {
        if (!Dispatcher.CheckAccess())
        {
            Dispatcher.BeginInvoke(new Action(() => Append(prefix, message)));
            return;
        }

        if (_completed) return;
        if (string.IsNullOrWhiteSpace(message)) return;

        // Winget can write VT terminal control sequences when piped.
        // Strip only rendering controls; preserve message text and order.
        var clean = System.Text.RegularExpressions.Regex.Replace(
            message, @"\x1B(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1B\\))", "");
        if (string.IsNullOrWhiteSpace(clean)) return;

        var entry = $"[{DateTime.Now:HH:mm:ss}] {prefix} {clean.TrimEnd()}{Environment.NewLine}";
        _fullLog.Append(entry);
        ConsoleTextBox.AppendText(entry);

        if (ConsoleTextBox.Text.Length > MaxVisibleChars)
        {
            ConsoleTextBox.Text = "[Earlier lines trimmed from view; Copy log retains all output.]" +
                                  Environment.NewLine +
                                  ConsoleTextBox.Text[^MaxVisibleChars..];
        }

        ConsoleTextBox.ScrollToEnd();
    }

    private void CopyLogButton_OnClick(object sender, RoutedEventArgs e)
    {
        try { Clipboard.SetText(_fullLog.ToString()); }
        catch (Exception ex) { AppendSystem("Clipboard unavailable: " + ex.Message); }
    }

    private void CloseInstallerButton_OnClick(object sender, RoutedEventArgs e) => Close();

    private void InstallationConsoleWindow_OnClosing(object? sender, CancelEventArgs e)
    {
        if (_completed) return;
        e.Cancel = true;
        SetStage("Installation is still in progress. Keep this window open until winget finishes.");
    }
}
