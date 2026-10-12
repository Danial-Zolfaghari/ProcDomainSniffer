# ProcDomainSniffer

<p align="center">
  <img src="ProcDomainSniffer.GUI/Assets/ProcDomainSnifferIcon.png" width="120" alt="ProcDomainSniffer icon" />
</p>

<h3 align="center">Process-aware domain & network telemetry for Windows</h3>

<p align="center">
  Observe the domains and network endpoints associated with a selected Windows process through a native .NET 8 / WPF interface.
</p>

<p align="center">
  <img alt=".NET" src="https://img.shields.io/badge/.NET-8.0-512BD4?logo=dotnet&logoColor=white">
  <img alt="Windows" src="https://img.shields.io/badge/Platform-Windows%20x64-0078D4?logo=windows11&logoColor=white">
  <img alt="UI" src="https://img.shields.io/badge/UI-WPF-2D7D9A">
  <img alt="Capture" src="https://img.shields.io/badge/Capture-TShark%20%2F%20Npcap-1679A7">
</p>
<p align="center">
  <a href="https://github.com/Danial-Zolfaghari/ProcDomainSniffer/actions/workflows/build.yml"><img alt="CI" src="https://github.com/Danial-Zolfaghari/ProcDomainSniffer/actions/workflows/build.yml/badge.svg"></a>
  <a href="https://github.com/Danial-Zolfaghari/ProcDomainSniffer/releases"><img alt="Release" src="https://img.shields.io/github/v/release/Danial-Zolfaghari/ProcDomainSniffer?display_name=tag&sort=semver"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/github/license/Danial-Zolfaghari/ProcDomainSniffer"></a>
</p>


---

## Overview

**ProcDomainSniffer** is a native Windows desktop application for correlating a selected process with observed DNS/domain activity and network endpoints.

It combines process selection, capture telemetry, DNS observations, resolved IP tracking, network-flow summaries, filtering, activity logs, and export/copy workflows in one desktop workspace.

## Download

The current Windows build is available from [GitHub Releases](https://github.com/Danial-Zolfaghari/ProcDomainSniffer/releases/latest).

Release assets include:

- `ProcDomainSniffer.GUI.exe` — self-contained Windows x64 executable
- `SHA256SUMS.txt` — SHA-256 checksum for verification

Verify the executable in PowerShell:

```powershell
Get-FileHash .\ProcDomainSniffer.GUI.exe -Algorithm SHA256
```

## Architecture

```mermaid
flowchart LR
    GUI[WPF GUI] --> CORE[ProcDomainSniffer.Core]
    GUI --> PROC[Selected Process / PID]
    CORE --> ETW[Windows ETW / TraceEvent]
    CORE --> TSHARK[TShark]
    TSHARK --> NPCAP[Npcap capture driver]
    ETW --> CORR[Process-aware correlation]
    NPCAP --> CORR
    CORR --> DNS[Domain events]
    CORR --> NET[Network endpoints]
    DNS --> GUI
    NET --> GUI
```

## Main workspace

The GUI is split into focused tabs:

- **Target Application** — process selection and PID/path details
- **Capture Settings** — capture behavior and interface controls
- **Overview** — active capture state and high-level counters
- **Live Events** — timestamped domain events
- **Domain Summary** — aggregated domain observations
- **Domain + IP** — resolved public IP addresses per observed domain
- **Network Log** — source/destination endpoint telemetry
- **Activity Log** — operational messages and capture status

## Features

- Process-aware capture workflow
- Windows process enumeration
- PID-targeted telemetry correlation
- DNS/domain observation
- Domain aggregation and occurrence counters
- Domain-to-public-IP resolution view
- Network endpoint log
- Protocol and destination-port visibility
- Capture-interface selection
- Loopback/internal-traffic filtering controls
- Search/filter controls across views
- Copy/export-oriented workflows
- Native dark WPF interface
- Single-file self-contained Windows build
- No environment-specific private IP ranges hard-coded in the public build

## Capture pipeline

```mermaid
sequenceDiagram
    participant User
    participant GUI
    participant Core
    participant TShark
    participant ETW

    User->>GUI: Select target process
    User->>GUI: Start capture
    GUI->>Core: PID + capture settings
    Core->>TShark: Start packet/DNS capture
    Core->>ETW: Observe process/network telemetry
    TShark-->>Core: DNS + endpoint events
    ETW-->>Core: Process-aware network context
    Core-->>GUI: Correlated events
    GUI-->>User: Live Events / Domains / Network Log
```

## Platform support

| Platform | Support | Notes |
|---|---|---|
| Windows 10/11 x64 | ✅ Full | WPF + ETW + Npcap/TShark |
| Linux | ❌ Not supported | Current GUI/correlation layer uses Windows WPF/ETW |
| macOS | ❌ Not supported | Current GUI/correlation layer uses Windows WPF/ETW |

## Runtime requirements

### Required on the target Windows machine

- Windows 10 or Windows 11 x64
- **Wireshark / TShark** installed
- **Npcap** installed, driver service running, and at least one Npcap interface visible to TShark
- Administrator privileges for ETW and capture; the GUI must be run as administrator

### Build requirements

- .NET **8 SDK**
- PowerShell 5.1+ or PowerShell 7+
- Internet access during restore for NuGet packages

The core project restores:

```text
Microsoft.Diagnostics.Tracing.TraceEvent 3.2.6
```

## Build

From the repository root:

```powershell
.\build-gui.ps1
```

The script:

1. Restores the .NET projects for `win-x64`
2. Publishes a self-contained Release build
3. Produces a single executable
4. Removes extra publish artifacts from the final output folder

Final output:

```text
output/ProcDomainSniffer.GUI.exe
```

The published executable is self-contained, so the target machine does not need a separate .NET runtime installation. **TShark + Npcap are still runtime dependencies.**

### Troubleshooting: PowerShell script execution is disabled

If running `build-gui.ps1` fails with:

```text
cannot be loaded because running scripts is disabled on this system
```

PowerShell may be configured to block local scripts. From the repository root,
run the following **in the same PowerShell window**:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\build-gui.ps1
```

The `Process` scope applies only to the current PowerShell session and does
**not** change the persistent execution policy. Close the terminal to discard
it. If the PC is managed by an organization, enforced Group Policy may still
block the script. Only run scripts you trust.

### First-run TShark setup

If `tshark.exe` is missing, the GUI detects it at startup and **asks permission**
to install the official Wireshark package via Windows Package Manager (`winget`).
The **Capture Settings** tab also offers an **Install TShark** button.
Installation opens the Wireshark installer interactively so you can select
**Npcap** if needed; Administrator approval and an internet connection may be
required. No third-party executable is downloaded directly by this app.

After installation, the GUI locates `tshark.exe`, checks the Npcap driver
service and refreshes capture interfaces. **Capture is completely disabled**
(including ETW-only collection) unless TShark, the running Npcap driver and
at least one Npcap interface are all available. The backend checks these
requirements again before opening any capture session.

For a manual interactive Wireshark installation you can run:

```powershell
winget install --id WiresharkFoundation.Wireshark --exact --interactive
```

Choose the **Npcap** component in the Wireshark installer. If TShark is already
installed but Npcap is missing or its driver is stopped, click **Get Npcap**
in Capture Settings to open the [official Npcap download](https://npcap.com/),
install/repair it, and click **Recheck**. Nmap is a separate network scanner
and is **not** required. If `winget` is unavailable, download Wireshark
from the official [Wireshark downloads](https://www.wireshark.org/download.html)
page. Administrative privileges and a reboot may be necessary.

## Build manually

```powershell
dotnet restore .\ProcDomainSniffer.GUI\ProcDomainSniffer.GUI.csproj -r win-x64

dotnet publish .\ProcDomainSniffer.GUI\ProcDomainSniffer.GUI.csproj `
  -c Release `
  -r win-x64 `
  --self-contained true `
  -p:PublishSingleFile=true `
  -p:PublishTrimmed=false
```

## Project structure

```text
ProcDomainSniffer/
├─ ProcDomainSniffer.Core/
│  ├─ DomainSnifferService.cs
│  ├─ SnifferContracts.cs
│  └─ ProcDomainSniffer.Core.csproj
├─ ProcDomainSniffer.GUI/
│  ├─ Assets/
│  │  ├─ ProcDomainSniffer.ico
│  │  └─ ProcDomainSnifferIcon.png
│  ├─ Models/
│  │  └─ UiModels.cs
│  ├─ App.xaml
│  ├─ App.xaml.cs
│  ├─ MainWindow.xaml
│  ├─ MainWindow.xaml.cs
│  └─ ProcDomainSniffer.GUI.csproj
├─ build-gui.ps1
├─ REQUIREMENTS.md
└─ README.md
```

## Privacy & scope

ProcDomainSniffer works with local process/network telemetry. Captures can contain sensitive operational information such as hostnames, destination IP addresses and process paths.

Before sharing captures or screenshots:

- redact internal domains
- redact private infrastructure addresses when necessary
- redact usernames embedded in process paths
- avoid committing capture exports or logs containing environment-specific data

## Responsible use

Use packet/process monitoring only on systems and networks you own or are explicitly authorized to inspect.

## Author

**Danial Zolfaghari**  
GitHub: [@Danial-Zolfaghari](https://github.com/Danial-Zolfaghari)

---

## Author

**Danial Zolfaghari** — [@Danial-Zolfaghari](https://github.com/Danial-Zolfaghari)

