#Requires -Version 5.1
# MITRE ATT&CK: T1204.004 — Malicious Copy-Paste
# Simulates ClickFix UI deception chain that spawns a script interpreter to execute a payload.

[CmdletBinding()]
param(
    [switch]$UseVbsShim,
    [switch]$CleanupOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$VbsShimPath  = Join-Path $env:TEMP "cf_shim_$(Get-Random).vbs"
$C2Endpoint   = 'https://example.com'

function Write-Step ([string]$Msg) { Write-Host "[*] $Msg" -ForegroundColor Cyan }
function Write-Ok   ([string]$Msg) { Write-Host "[+] $Msg" -ForegroundColor Green }
function Write-Warn ([string]$Msg) { Write-Host "[!] $Msg" -ForegroundColor Yellow }

function Remove-Artefacts {
    if (Test-Path $VbsShimPath) {
        Remove-Item $VbsShimPath -Force -ErrorAction SilentlyContinue
        Write-Ok "Removed VBS shim: $VbsShimPath"
    }
}

if ($CleanupOnly) { Remove-Artefacts; exit 0 }

Write-Host ""
Write-Host "=== ClickFix Technique Emulation ===" -ForegroundColor Magenta
Write-Host "    T1204.004 | Detection Chokepoints Project" -ForegroundColor DarkGray
Write-Host ""

Write-Step "Step 1/3 — Executing PowerShell with -EncodedCommand flag"

# Benign payload: Get-Date | Out-String (base64 encoded)
$BenignCmd   = 'Get-Date | Out-String'
$EncodedCmd  = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($BenignCmd))

Write-Verbose "  Encoded payload (benign): $EncodedCmd"
$result = powershell.exe -NonInteractive -NoProfile -EncodedCommand $EncodedCmd
Write-Ok "Encoded command executed. Output: $($result.Trim())"

Start-Sleep -Milliseconds 300

Write-Step "Step 2/3 — DNS resolution + outbound HTTP connection from interpreter"

try {
    $null = [System.Net.Dns]::GetHostAddresses('example.com')
    Write-Ok "DNS resolved example.com (Sysmon EID 22 generated)"
} catch {
    Write-Warn "DNS resolution failed: $_"
}

try {
    $resp = Invoke-WebRequest -Uri $C2Endpoint -Method HEAD -TimeoutSec 10 `
        -UseBasicParsing -ErrorAction Stop
    Write-Ok "Outbound connection made (HTTP $($resp.StatusCode)) — Sysmon EID 3 generated"
} catch {
    Write-Warn "Network request failed (telemetry may still fire): $_"
}

Start-Sleep -Milliseconds 300

# This is what makes Hunt/Analyst rules fire — browser/scripting parent spawning PowerShell
if ($UseVbsShim) {
    Write-Step "Step 3/3 — Spawning PowerShell via VBScript shim (browser parent simulation)"
    Write-Verbose "  Note: For full browser parent (chrome.exe → powershell.exe), manually:"
    Write-Verbose "        1. Open Chrome, press F12 → Console"
    Write-Verbose "        2. This script cannot automate that chain safely"

    # VBScript spawns PowerShell with encoded command — simulates wscript.exe parent chain
    $InnerEncoded = [Convert]::ToBase64String(
        [System.Text.Encoding]::Unicode.GetBytes('Write-Host "ClickFix emulation - child of wscript"')
    )
    $VbsContent = @"
Dim oShell
Set oShell = CreateObject("WScript.Shell")
oShell.Run "powershell.exe -NonInteractive -NoProfile -EncodedCommand $InnerEncoded", 0, True
"@
    Set-Content -Path $VbsShimPath -Value $VbsContent -Encoding ASCII
    Write-Ok "VBS shim written to $VbsShimPath"

    try {
        $proc = Start-Process -FilePath 'wscript.exe' -ArgumentList "`"$VbsShimPath`"" `
            -Wait -PassThru -ErrorAction Stop
        Write-Ok "VBScript → PowerShell chain executed (wscript.exe PID $($proc.Id))"
        Write-Ok "Expected parent chain in telemetry: wscript.exe → powershell.exe"
    } catch {
        Write-Warn "VBS shim execution failed: $_"
    }
} else {
    Write-Warn "Step 3 skipped (run with -UseVbsShim for Hunt/Analyst parent chain simulation)"
    Write-Warn "For full Analyst rule validation, Hunt parent chain requires browser context."
    Write-Host ""
    Write-Host "  Manual Hunt/Analyst test:" -ForegroundColor DarkGray
    Write-Host "    1. Open Chrome/Edge DevTools console" -ForegroundColor DarkGray
    Write-Host "    2. Paste: powershell.exe -enc $EncodedCmd" -ForegroundColor DarkGray
    Write-Host "    3. Check Sysmon EID 1 for ParentImage=chrome.exe" -ForegroundColor DarkGray
}

Write-Host ""
Write-Step "Cleaning up artefacts"
Remove-Artefacts

Write-Host ""
Write-Host "=== Emulation Complete ===" -ForegroundColor Magenta
Write-Host ""
Write-Host "Expected detections:" -ForegroundColor White
Write-Host "  [Research]  Sysmon EID 1 (powershell w/ -enc) + EID 3 (outbound network)"    -ForegroundColor DarkCyan
Write-Host "  [Hunt]      EID 1 parent=wscript/browser + EID 3 within 60s"                 -ForegroundColor DarkYellow
Write-Host "  [Analyst]   EID 1 (-enc, browser parent) + EID 3 (external) + EID 22 (DNS)"  -ForegroundColor DarkGreen
Write-Host ""
Write-Host "If no alerts fired, verify:" -ForegroundColor DarkGray
Write-Host "  - Sysmon config captures EID 1 (all process creation) and EID 3 (network)"
Write-Host "  - Process creation command-line logging enabled in Sysmon config"
Write-Host "  - DNS logging enabled (EID 22) in Sysmon config"
Write-Host ""
