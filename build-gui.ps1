$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$gui = Join-Path $root 'ProcDomainSniffer.GUI\ProcDomainSniffer.GUI.csproj'
$output = Join-Path $root 'output'
$staging = Join-Path $root '.publish-temp'
function Assert-LastExitCode { param([string]$Step) if ($LASTEXITCODE -ne 0) { throw "$Step failed with exit code $LASTEXITCODE" } }
$running = Get-Process -Name 'ProcDomainSniffer.GUI' -ErrorAction SilentlyContinue
if ($running) { throw 'ProcDomainSniffer.GUI is currently running. Close it before rebuilding.' }
foreach ($dir in @($output,$staging)) { if(Test-Path $dir){Remove-Item $dir -Recurse -Force}; New-Item -ItemType Directory -Path $dir|Out-Null }
& dotnet restore $gui -r win-x64; Assert-LastExitCode 'dotnet restore'
& dotnet publish $gui -c Release -r win-x64 --self-contained true --output $staging -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true -p:PublishTrimmed=false -p:DebugType=None -p:DebugSymbols=false
Assert-LastExitCode 'dotnet publish'
$publishedExe=Join-Path $staging 'ProcDomainSniffer.GUI.exe'; if(-not(Test-Path $publishedExe)){throw "EXE not found: $publishedExe"}
Copy-Item $publishedExe (Join-Path $output 'ProcDomainSniffer.GUI.exe') -Force
Remove-Item $staging -Recurse -Force
Write-Host 'Build succeeded.' -ForegroundColor Green
Write-Host 'TShark + Npcap must be installed on the target Windows machine.' -ForegroundColor Yellow
