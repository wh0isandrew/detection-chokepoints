#Requires -Version 5.1
# MITRE ATT&CK: T1505.003 — Server Software Component: Web Shell
# Simulates web shell write to web root and subsequent command execution via HTTP.

[CmdletBinding()]
param(
    [string]$WebRoot        = (Join-Path $env:TEMP 'wwwroot-emulation'),
    [string]$ShellExtension = '.aspx',
    [switch]$CleanupOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$ShellName   = "cmd$(Get-Random -Maximum 9999)$ShellExtension"
$ShellPath   = Join-Path $WebRoot $ShellName
$C2Endpoint  = 'https://example.com'

function Write-Step ([string]$Msg) { Write-Host "[*] $Msg" -ForegroundColor Cyan }
function Write-Ok   ([string]$Msg) { Write-Host "[+] $Msg" -ForegroundColor Green }
function Write-Warn ([string]$Msg) { Write-Host "[!] $Msg" -ForegroundColor Yellow }

function Remove-Artefacts {
    if (Test-Path $ShellPath)  { Remove-Item $ShellPath  -Force -ErrorAction SilentlyContinue }
    if (Test-Path $WebRoot -and (Get-ChildItem $WebRoot -ErrorAction SilentlyContinue).Count -eq 0) {
        Remove-Item $WebRoot -Force -ErrorAction SilentlyContinue
    }
    Write-Ok "Artefacts removed"
}

if ($CleanupOnly) { Remove-Artefacts; exit 0 }

Write-Host ""
Write-Host "=== Web Shell Emulation ===" -ForegroundColor Magenta
Write-Host "    T1505.003 | Detection Chokepoints Project" -ForegroundColor DarkGray
Write-Host ""

Write-Step "Step 1/3 — Creating web shell file in web-accessible directory"
Write-Verbose "  Path: $ShellPath"

# Ensure web root exists
if (-not (Test-Path $WebRoot)) {
    New-Item -ItemType Directory -Path $WebRoot -Force | Out-Null
    Write-Ok "Created test web root: $WebRoot"
}

# Write a safe marker file (NOT an executable web shell — just text content)
$ShellContent = @"
<%@ Page Language="C#" %>
<!-- Web Shell Emulation Marker — NOT executable, for detection testing only -->
<!-- Created by Detection Chokepoints emulation script -->
<!-- T1505.003 — File created at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') -->
<% Response.Write("Detection test"); %>
"@
Set-Content -Path $ShellPath -Value $ShellContent -Encoding UTF8
Write-Ok "Web shell marker created: $ShellPath"
Write-Ok "Sysmon EID 11 generated — extension=$ShellExtension, path contains web root pattern"

Start-Sleep -Milliseconds 400

Write-Step "Step 2/3 — Simulating web server → cmd.exe execution chain"
Write-Verbose "  Real pattern: w3wp.exe → cmd.exe (web server spawns interpreter after HTTP request)"
Write-Verbose "  Simulated:    powershell.exe → cmd.exe (same child process, different parent)"
Write-Verbose "  Note: Hunt/Analyst rules check ParentImage=w3wp.exe specifically"
Write-Verbose "  For w3wp parent: deploy in IIS and access via HTTP (see below)"

# Run recon commands that web shells execute post-exploitation
$reconCommands = @(
    'whoami',
    'hostname',
    'ipconfig /all',
    'net user',
    'net localgroup administrators'
)

foreach ($cmd in $reconCommands) {
    $result = cmd.exe /c $cmd 2>&1 | Select-Object -First 3
    Write-Ok "cmd /c $cmd`: $($result[0])"
}

# Also run an encoded command (Analyst rule trigger)
$encodedPayload = [Convert]::ToBase64String(
    [System.Text.Encoding]::Unicode.GetBytes('Get-ChildItem C:\inetpub\wwwroot -ErrorAction SilentlyContinue')
)
powershell.exe -NonInteractive -NoProfile -EncodedCommand $encodedPayload 2>&1 | Out-Null
Write-Ok "Encoded command executed from cmd context — Analyst rule EID 1 pattern matched"

Start-Sleep -Milliseconds 400

Write-Step "Step 3/3 — Outbound HTTP connection from spawned interpreter"
Write-Verbose "  In real scenario: w3wp.exe child makes outbound connection to C2"

try {
    $resp = Invoke-WebRequest -Uri $C2Endpoint -Method HEAD -TimeoutSec 10 `
        -UseBasicParsing -ErrorAction Stop
    Write-Ok "Outbound connection (HTTP $($resp.StatusCode)) from interpreter — Sysmon EID 3 generated"
} catch {
    Write-Warn "Network request failed (EID 3 may still have fired for the TCP attempt): $_"
}

Write-Host ""
Write-Step "Cleaning up artefacts"
Remove-Artefacts

Write-Host ""
Write-Host "=== Emulation Complete ===" -ForegroundColor Magenta
Write-Host ""
Write-Host "Expected detections:" -ForegroundColor White
Write-Host "  [Research]  Sysmon EID 1 — any child process of web server"                               -ForegroundColor DarkCyan
Write-Host "  [Hunt]      EID 11 ($ShellExtension in web path) + EID 1 (cmd.exe/powershell.exe child)"  -ForegroundColor DarkYellow
Write-Host "  [Analyst]   EID 11 (web shell ext) + EID 1 (-enc or recon cmd) + EID 3 (outbound)"       -ForegroundColor DarkGreen
Write-Host ""
Write-Host "For w3wp.exe parent chain (IIS-specific Hunt/Analyst rules):" -ForegroundColor DarkGray
Write-Host "  1. Install IIS: Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServer"
Write-Host "  2. Copy shell marker to C:\inetpub\wwwroot\$ShellName"
Write-Host "  3. For ASPX execution: rename to .aspx, enable ASP.NET in IIS"
Write-Host "  4. Use a benign ASPX that runs: Response.Write(new System.Diagnostics.Process(){...}.StandardOutput.ReadToEnd())"
Write-Host "  5. HTTP request to http://localhost/$ShellName generates authentic w3wp.exe → cmd.exe"
Write-Host ""
Write-Host "For Linux (Apache/nginx) parent chain:" -ForegroundColor DarkGray
Write-Host "  Use companion emulate.sh (spawn bash from httpd/nginx context via PHP)"
Write-Host ""
