# Contributing to ProcDomainSniffer

ProcDomainSniffer depends on Windows ETW, Npcap and TShark.

Run before opening a pull request:

```powershell
dotnet test .\ProcDomainSniffer.Tests\ProcDomainSniffer.Tests.csproj -c Release
dotnet build .\ProcDomainSniffer.GUI\ProcDomainSniffer.GUI.csproj -c Release -r win-x64
.\build-gui.ps1
```

Keep changes focused, document platform impact, use non-sensitive example data, and update tests when core parsing or filtering behavior changes.
