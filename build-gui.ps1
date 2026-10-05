$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$gui = Join-Path $root 'ProcDomainSniffer.GUI\ProcDomainSniffer.GUI.csproj'
$output = Join-Path $root 'output'
$staging = Join-Path $root '.publish-temp'

function Assert-LastExitCode {
    param([string]$Step)
    if ($LASTEXITCODE -ne 0) {
        throw "$Step failed with exit code $LASTEXITCODE"
    }
}

$running = Get-Process -Name 'ProcDomainSniffer.GUI' -ErrorAction SilentlyContinue
if ($running) {
    throw 'ProcDomainSniffer.GUI is currently running. Close it before rebuilding.'
}

Write-Host 'Preparing single-file output...' -ForegroundColor Cyan
foreach ($dir in @($output, $staging)) {
    if (Test-Path $dir) { Remove-Item $dir -Recurse -Force }
    New-Item -ItemType Directory -Path $dir | Out-Null
}

Write-Host 'Restoring...' -ForegroundColor Cyan
& dotnet restore $gui -r win-x64
Assert-LastExitCode 'dotnet restore'

Write-Host 'Publishing self-contained single EXE...' -ForegroundColor Cyan
& dotnet publish $gui `
    -c Release `
    -r win-x64 `
    --self-contained true `
    --output $staging `
    -p:PublishSingleFile=true `
    -p:IncludeNativeLibrariesForSelfExtract=true `
    -p:EnableCompressionInSingleFile=true `
    -p:PublishTrimmed=false `
    -p:DebugType=None `
    -p:DebugSymbols=false
Assert-LastExitCode 'dotnet publish'

$publishedExe = Join-Path $staging 'ProcDomainSniffer.GUI.exe'
if (-not (Test-Path $publishedExe)) {
    throw "Single-file publish completed but EXE was not found: $publishedExe"
}

$finalExe = Join-Path $output 'ProcDomainSniffer.GUI.exe'
Copy-Item $publishedExe $finalExe -Force
Remove-Item $staging -Recurse -Force

$extraFiles = @(Get-ChildItem $output -File | Where-Object { $_.Name -ne 'ProcDomainSniffer.GUI.exe' })
if ($extraFiles.Count -gt 0) {
    $extraFiles | Remove-Item -Force
}

$sizeMb = [Math]::Round((Get-Item $finalExe).Length / 1MB, 1)

Write-Host ''
Write-Host 'Build succeeded.' -ForegroundColor Green
Write-Host 'Single-file output:' -ForegroundColor Cyan
Write-Host $finalExe
Write-Host "Size: $sizeMb MB"
Write-Host ''
Write-Host 'The output folder contains only ProcDomainSniffer.GUI.exe.' -ForegroundColor Green
Write-Host 'Wireshark/TShark + Npcap must still be installed on the target Windows machine.' -ForegroundColor Yellow
Write-Host 'Run the EXE as Administrator.' -ForegroundColor Yellow
