#Requires -Version 5.1
# MITRE ATT&CK: T1059.006, T1059.007 — BYOSI (Bring Your Own Scripting Interpreter)
# Simulates the three BYOSI chokepoint stages: interpreter delivery, execution, and script action.
# Does NOT download real interpreters or establish real C2 — uses safe stand-in artifacts only.

[CmdletBinding()]
param(
    [switch]$CleanupOnly,
    [string]$StagingDir = "$env:TEMP\byosi_emulation"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

function Write-Step ([string]$Msg) { Write-Host "[*] $Msg" -ForegroundColor Cyan }
function Write-Ok   ([string]$Msg) { Write-Host "[+] $Msg" -ForegroundColor Green }
function Write-Warn ([string]$Msg) { Write-Host "[!] $Msg" -ForegroundColor Yellow }

function Remove-Artefacts {
    if (Test-Path $StagingDir) {
        Remove-Item -Recurse -Force $StagingDir -ErrorAction SilentlyContinue
        Write-Ok "Cleaned up staging directory: $StagingDir"
    } else {
        Write-Warn "No artefacts found at $StagingDir"
    }
}

if ($CleanupOnly) { Remove-Artefacts; exit 0 }

Write-Host ""
Write-Host "=== BYOSI Emulation ===" -ForegroundColor Magenta
Write-Host "    T1059.006 / T1059.007 | Detection Chokepoints Project" -ForegroundColor DarkGray
Write-Host ""
Write-Warn "This script creates SAFE stand-in files to generate detection telemetry."
Write-Warn "No real interpreters are downloaded. No network connections are made."
Write-Host ""

# ─── Stage 1: Interpreter Delivery (Sysmon EID 11 — File Create) ─────────────

Write-Step "Stage 1/3 — Simulating interpreter delivery to temp directory"
Write-Verbose "  Creates stand-in files mimicking interpreter binary drop"
Write-Verbose "  Targets: Sysmon EID 11 (FileCreate) for interpreter binaries in temp paths"

New-Item -ItemType Directory -Path $StagingDir -Force | Out-Null

# Create zero-byte stand-in files named like common BYOSI interpreter binaries
$interpreters = @(
    "python.exe",
    "php.exe",
    "node.exe",
    "ruby.exe",
    "AutoHotkey64.exe"
)

foreach ($interp in $interpreters) {
    $path = Join-Path $StagingDir $interp
    [System.IO.File]::WriteAllText($path, "BYOSI_EMULATION_STANDIN")
    Write-Ok "Created stand-in: $path"
}

Write-Ok "Sysmon EID 11 (FileCreate) generated for $($interpreters.Count) interpreter stand-ins"
Write-Ok "Research rule trigger: interpreter binaries written to temp directory"

Start-Sleep -Milliseconds 500

# ─── Stage 2: Interpreter Execution (Sysmon EID 1 — Process Creation) ────────

Write-Step "Stage 2/3 — Simulating interpreter execution with script arguments"
Write-Verbose "  Launches cmd.exe with command lines that mimic BYOSI interpreter invocations"
Write-Verbose "  Targets: Sysmon EID 1 (ProcessCreate) with interpreter-like command lines"

# Create a benign script file to reference in command lines
$scriptFile = Join-Path $StagingDir "payload.py"
[System.IO.File]::WriteAllText($scriptFile, "# BYOSI emulation - benign placeholder")

$jsScript = Join-Path $StagingDir "implant.js"
[System.IO.File]::WriteAllText($jsScript, "// BYOSI emulation - benign placeholder")

$phpScript = Join-Path $StagingDir "shell.php"
[System.IO.File]::WriteAllText($phpScript, "<?php // BYOSI emulation - benign placeholder ?>")

Write-Ok "Created stand-in script files: payload.py, implant.js, shell.php"

# Simulate the command patterns that BYOSI attacks use
# These generate Sysmon EID 1 with the command lines our Sigma rules match on

# Pattern 1: Python-style execution from temp
$pythonCmd = "`"$StagingDir\python.exe`" `"$scriptFile`""
Write-Ok "Simulated command: $pythonCmd"
Write-Warn "  (Stand-in file — not a real interpreter, will fail to execute)"
cmd.exe /c "echo BYOSI_EMULATION: $pythonCmd" 2>&1 | Out-Null

# Pattern 2: Node.js inline execution
$nodeCmd = "`"$StagingDir\node.exe`" -e `"console.log('test')`""
Write-Ok "Simulated command: $nodeCmd"
cmd.exe /c "echo BYOSI_EMULATION: $nodeCmd" 2>&1 | Out-Null

# Pattern 3: PHP script execution
$phpCmd = "`"$StagingDir\php.exe`" `"$phpScript`""
Write-Ok "Simulated command: $phpCmd"
cmd.exe /c "echo BYOSI_EMULATION: $phpCmd" 2>&1 | Out-Null

Write-Ok "Hunt rule trigger: interpreter paths + script arguments in command lines"

Start-Sleep -Milliseconds 500

# ─── Stage 3: Script Action Indicators ───────────────────────────────────────

Write-Step "Stage 3/3 — Simulating post-execution indicators"
Write-Verbose "  Creates file-system artifacts that would accompany real BYOSI script execution"
Write-Verbose "  Targets: Sysmon EID 11 (FileCreate) for script output files"

# Simulate script output (e.g., a C2 beacon config or exfil staging file)
$outputFile = Join-Path $StagingDir "output.dat"
[System.IO.File]::WriteAllText($outputFile, "BYOSI_EMULATION_OUTPUT_STANDIN")
Write-Ok "Created simulated script output: $outputFile"

# Simulate a dropped persistence artifact
$persistFile = Join-Path $StagingDir "update_service.vbs"
[System.IO.File]::WriteAllText($persistFile, "' BYOSI emulation - benign persistence stand-in")
Write-Ok "Created simulated persistence script: $persistFile"

Write-Ok "Analyst rule context: interpreter drop + execution + file-system artifacts in temp path"

# ─── Summary ──────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "=== Emulation Complete ===" -ForegroundColor Magenta
Write-Host ""
Write-Host "Expected detections:" -ForegroundColor White
Write-Host "  [Research]  Sysmon EID 11: interpreter binaries created in $StagingDir" -ForegroundColor DarkCyan
Write-Host "  [Hunt]      Sysmon EID 1:  interpreter execution with script file arguments" -ForegroundColor DarkYellow
Write-Host "  [Analyst]   Correlated:    interpreter drop + suspicious parent + script args" -ForegroundColor DarkGreen
Write-Host ""
Write-Host "Cleanup:" -ForegroundColor DarkGray
Write-Host "  .\emulate.ps1 -CleanupOnly"
Write-Host "  (or manually delete $StagingDir)"
Write-Host ""
Write-Host "For higher-fidelity testing:" -ForegroundColor DarkGray
Write-Host "  1. Download a real portable Python/Node.js ZIP to $StagingDir"
Write-Host "  2. Extract and execute: $StagingDir\python.exe -c ""import socket; print('test')"""
Write-Host "  3. This generates authentic Sysmon EID 1 + EID 3 (network) telemetry"
Write-Host "  4. Run in an isolated lab VM only"
Write-Host ""
