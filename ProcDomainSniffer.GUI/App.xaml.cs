using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Threading;

namespace ProcDomainSniffer.GUI;

public partial class App : System.Windows.Application
{
    private static readonly object CrashLogGate = new();

    public App()
    {
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;
        TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        var path = WriteCrashLog("DispatcherUnhandledException", e.Exception);

        try
        {
            MessageBox.Show(
                $"ProcDomainSniffer hit an unexpected error.\n\n{e.Exception.Message}\n\nCrash log:\n{path}",
                "ProcDomainSniffer - Unexpected error",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        catch
        {
        }

        e.Handled = true;
        Shutdown(-1);
    }

    private void OnUnhandledException(object? sender, UnhandledExceptionEventArgs e)
    {
        if (e.ExceptionObject is Exception ex)
            WriteCrashLog("AppDomain.UnhandledException", ex);
        else
            WriteCrashLog("AppDomain.UnhandledException", new Exception(e.ExceptionObject?.ToString() ?? "Unknown unhandled exception"));
    }

    private void OnUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
    {
        WriteCrashLog("TaskScheduler.UnobservedTaskException", e.Exception);
        e.SetObserved();
    }

    private static string WriteCrashLog(string source, Exception exception)
    {
        var baseDir = AppContext.BaseDirectory;
        var path = Path.Combine(baseDir, "ProcDomainSniffer-crash.log");

        try
        {
            lock (CrashLogGate)
            {
                var sb = new StringBuilder();
                sb.AppendLine(new string('=', 88));
                sb.AppendLine($"Time: {DateTimeOffset.Now:O}");
                sb.AppendLine($"Source: {source}");
                sb.AppendLine($"Process: {Environment.ProcessPath}");
                sb.AppendLine($"OS: {Environment.OSVersion}");
                sb.AppendLine($".NET: {Environment.Version}");
                sb.AppendLine();
                sb.AppendLine(exception.ToString());
                sb.AppendLine();
                File.AppendAllText(path, sb.ToString(), new UTF8Encoding(false));
            }
        }
        catch
        {
        }

        return path;
    }
}
