#Requires -Version 5.1
#Requires -RunAsAdministrator
# MITRE ATT&CK: T1003.001, OS Credential Dumping: LSASS Memory
# Simulates LSASS credential dumping chokepoint stages: handle acquisition, memory read, and dump artifact.
# Does NOT extract credentials; uses safe API calls to generate detection telemetry only.

[CmdletBinding()]
param(
    [switch]$SkipDumpFile,
    [switch]$CleanupOnly,
    [string]$DumpPath = (Join-Path $env:TEMP "lsass_emu_$(Get-Random).dmp")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

function Write-Step ([string]$Msg) { Write-Host "[*] $Msg" -ForegroundColor Cyan }
function Write-Ok   ([string]$Msg) { Write-Host "[+] $Msg" -ForegroundColor Green }
function Write-Warn ([string]$Msg) { Write-Host "[!] $Msg" -ForegroundColor Yellow }

function Remove-Artefacts {
    if (Test-Path $DumpPath) {
        Remove-Item -Path $DumpPath -Force -ErrorAction SilentlyContinue
        Write-Ok "Removed dump artefact: $DumpPath"
    } else {
        Write-Warn "No artefacts found at $DumpPath"
    }
}

if ($CleanupOnly) { Remove-Artefacts; exit 0 }

Write-Host ""
Write-Host "=== LSASS Credential Dumping Emulation ===" -ForegroundColor Magenta
Write-Host "    T1003.001 | Detection Chokepoints Project" -ForegroundColor DarkGray
Write-Host ""
Write-Warn "This script generates detection telemetry ONLY."
Write-Warn "No credentials are extracted. No memory is parsed."
Write-Warn "Requires Administrator privileges for SeDebugPrivilege."
Write-Host ""

# ─── Enable SeDebugPrivilege ────────────────────────────────────────────────

Write-Step "Enabling SeDebugPrivilege (required for LSASS handle access)"

Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class LsassChokepointEmulation {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(
        uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool OpenProcessToken(
        IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool LookupPrivilegeValue(
        string lpSystemName, string lpName, out long lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool AdjustTokenPrivileges(
        IntPtr TokenHandle, bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState, int BufferLength,
        IntPtr PreviousState, IntPtr ReturnLength);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES {
        public int PrivilegeCount;
        public long Luid;
        public int Attributes;
    }

    public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    public const uint TOKEN_QUERY = 0x0008;
    public const int SE_PRIVILEGE_ENABLED = 0x00000002;
    public const uint PROCESS_VM_READ_QUERY = 0x1010;

    public static bool EnableDebugPrivilege() {
        IntPtr tokenHandle;
        if (!OpenProcessToken(GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out tokenHandle))
            return false;

        long luid;
        if (!LookupPrivilegeValue(null, "SeDebugPrivilege", out luid)) {
            CloseHandle(tokenHandle);
            return false;
        }

        TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
        tp.PrivilegeCount = 1;
        tp.Luid = luid;
        tp.Attributes = SE_PRIVILEGE_ENABLED;

        bool result = AdjustTokenPrivileges(tokenHandle, false, ref tp, 0,
            IntPtr.Zero, IntPtr.Zero);
        CloseHandle(tokenHandle);
        return result && Marshal.GetLastWin32Error() == 0;
    }

    public static int OpenLsass() {
        Process[] procs = Process.GetProcessesByName("lsass");
        if (procs.Length == 0) return -1;

        int pid = procs[0].Id;
        IntPtr handle = OpenProcess(PROCESS_VM_READ_QUERY, false, pid);

        if (handle == IntPtr.Zero) return -2;

        // Handle acquired. Sysmon EID 10 has fired.
        // Close immediately; we do not read memory.
        CloseHandle(handle);
        return pid;
    }
}
'@

$privEnabled = [LsassChokepointEmulation]::EnableDebugPrivilege()
if ($privEnabled) {
    Write-Ok "SeDebugPrivilege enabled"
} else {
    Write-Warn "Failed to enable SeDebugPrivilege. Handle acquisition may fail."
    Write-Warn "This is expected if LSASS is running as PPL (Protected Process Light)."
}

Start-Sleep -Milliseconds 300

# ─── Stage 1: Handle Acquisition (Sysmon EID 10, ProcessAccess) ─────────────

Write-Step "Stage 1/3: Opening handle to lsass.exe (ProcessAccess telemetry)"
Write-Verbose "  Targets: Sysmon EID 10 with TargetImage=lsass.exe"
Write-Verbose "  This is the chokepoint invariant; every dump tool must do this"

try {
    $result = [LsassChokepointEmulation]::OpenLsass()
    if ($result -gt 0) {
        Write-Ok "Handle opened to lsass.exe (PID $result) with GrantedAccess 0x1010"
        Write-Ok "Handle closed immediately, no memory read performed"
        Write-Ok "Sysmon EID 10 generated: TargetImage=lsass.exe, GrantedAccess=0x1010"
    } elseif ($result -eq -1) {
        Write-Warn "lsass.exe process not found (are you running on Windows?)"
    } else {
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($err -eq 5) {
            Write-Warn "OpenProcess returned ACCESS_DENIED (error 5)"
            Write-Warn "LSASS is likely running as Protected Process Light (PPL)."
            Write-Warn "PPL blocks handle acquisition even with SeDebugPrivilege."
            Write-Warn "To test Stage 1, either:"
            Write-Warn "  1. Disable PPL: reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f (reboot required)"
            Write-Warn "  2. Use a VM without PPL enabled"
            Write-Warn "  3. Accept that PPL is working as intended (this IS the defense)"
            Write-Warn ""
            Write-Warn "Sysmon may still log the failed access attempt as EID 10."
            Write-Warn "Check for GrantedAccess=0x0 or a reduced mask in your logs."
        } else {
            Write-Warn "OpenProcess failed (error $err)"
        }
    }
} catch {
    Write-Warn "Handle acquisition failed: $_"
}

Start-Sleep -Milliseconds 500

# ─── Stage 2: comsvcs.dll MiniDump LOLBin (Sysmon EID 1, Process Creation) ──

Write-Step "Stage 2/3: Simulating comsvcs.dll MiniDump command line (LOLBin telemetry)"
Write-Verbose "  Generates Sysmon EID 1 with CommandLine containing 'comsvcs' and 'MiniDump'"
Write-Verbose "  This is the most common LOLBin technique for LSASS dumping"

# Echo the command line pattern without actually calling MiniDump
# This generates a process creation event with the suspicious command line
$lsassPid = (Get-Process lsass -ErrorAction SilentlyContinue).Id
if ($lsassPid) {
    $cmdLine = "rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $lsassPid $DumpPath full"
    Write-Ok "LOLBin command pattern: $cmdLine"
    # Run cmd /c echo with the suspicious command line to trigger EID 1 matching
    cmd.exe /c "echo EMULATION_ONLY: $cmdLine" 2>&1 | Out-Null
    Write-Ok "Sysmon EID 1 generated with comsvcs.dll MiniDump in CommandLine"
} else {
    Write-Warn "lsass.exe PID not found, skipping LOLBin simulation"
}

Start-Sleep -Milliseconds 500

# ─── Stage 3: Dump File Artifact (Sysmon EID 11, File Create) ───────────────

if (-not $SkipDumpFile) {
    Write-Step "Stage 3/3: Creating dump file artefact in temp directory"
    Write-Verbose "  Creates a marker .dmp file to trigger file creation detection"
    Write-Verbose "  Targets: Sysmon EID 11 with TargetFilename=*.dmp in temp path"

    # Write a safe marker file (NOT a real memory dump)
    $marker = "LSASS_EMULATION_MARKER | Detection Chokepoints Project | NOT A REAL DUMP"
    [System.IO.File]::WriteAllText($DumpPath, $marker)
    Write-Ok "Dump artefact created: $DumpPath"
    Write-Ok "Sysmon EID 11 generated: .dmp file in temp directory"
} else {
    Write-Warn "Stage 3 skipped (-SkipDumpFile flag set)"
}

# ─── Summary ─────────────────────────────────────────────────────────────────

Write-Host ""
Write-Step "Cleaning up artefacts"
Remove-Artefacts

Write-Host ""
Write-Host "=== Emulation Complete ===" -ForegroundColor Magenta
Write-Host ""
Write-Host "Expected detections:" -ForegroundColor White
Write-Host "  [Research]  Sysmon EID 10: non-system process opened handle to lsass.exe"        -ForegroundColor DarkCyan
Write-Host "  [Hunt]      EID 10: GrantedAccess 0x1010 + CallTrace from non-AV/EDR process"   -ForegroundColor DarkYellow
Write-Host "  [Analyst]   EID 10: 0x1010 + CallTrace + non-standard source path"              -ForegroundColor DarkGreen
Write-Host ""
Write-Host "Supplementary signals (deploy as companion SIEM rules):" -ForegroundColor DarkGray
Write-Host "  EID 1:  comsvcs.dll MiniDump command line pattern"
Write-Host "  EID 11: .dmp file created in temp directory"
Write-Host ""
Write-Host "Cleanup:" -ForegroundColor DarkGray
Write-Host "  .\emulate.ps1 -CleanupOnly"
Write-Host ""
Write-Host "For higher-fidelity testing (isolated lab VM only):" -ForegroundColor DarkGray
Write-Host "  1. rundll32.exe comsvcs.dll MiniDump <lsass_pid> C:\Temp\test.dmp full"
Write-Host "  2. procdump.exe -accepteula -ma lsass.exe C:\Temp\lsass.dmp"
Write-Host "  3. These generate authentic EID 10 with dbgcore.dll in CallTrace"
Write-Host ""
