# ProcDomainSniffer Requirements

## Runtime

- Windows 10/11 x64
- Wireshark/TShark
- Npcap capture driver
- Administrator privileges where required by Npcap/capture policy

## Build

- .NET 8 SDK
- PowerShell 5.1+ or PowerShell 7+
- NuGet network access for `Microsoft.Diagnostics.Tracing.TraceEvent` 3.2.6

## Output

`build-gui.ps1` creates a self-contained single-file executable at:

`output/ProcDomainSniffer.GUI.exe`

A separately installed .NET runtime is not required for the published executable.
