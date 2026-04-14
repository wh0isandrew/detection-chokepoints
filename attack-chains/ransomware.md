---
layout: attack-chain
title: Ransomware Attack Chain
subtitle: "How ransomware operators all follow the same five-stage chokepoint sequence, regardless of group, brand, or tooling."
last_updated: 2026-04-12
permalink: /attack-chains/ransomware/
show_ttp_overlap: true
ttp_data_key: ransomware_ttp_overlap

stages:
  - id: initial_access
    label: Initial Access
    detection_status: detected
    attacker_action: "Phishing / exposed VPN / RMM abuse"
    systems: "Endpoint · Email GW · VPN"
    detection_signals:
      - "Browser download of renamed/masqueraded binary (missing or mismatched signature)"
      - "RDP/VPN login from new geo-location or ASN"
      - "Email attachment execution from user Downloads folder"
      - "Legitimate RMM tool (AnyDesk, ConnectWise, TeamViewer) installed outside of IT workflow"
    chokepoint_links:
      - label: "Renamed RMM Tools"
        slug: "renamed-rmm-tools"
      - label: "ClickFix Techniques"
        slug: "clickfix-techniques"
  - id: credential_access
    label: Credential Access
    detection_status: detected
    attacker_action: "LSASS dump / credential harvest"
    systems: "DC · Endpoint"
    detection_signals:
      - "LSASS process access by non-system process (Sysmon EID 10)"
      - "SAM/SECURITY registry hive read outside of system tools"
      - "rundll32.exe loading comsvcs.dll with MiniDump export"
      - "esentutl.exe copying browser credential databases"
  - id: lateral_movement
    label: Lateral Movement
    detection_status: exploited
    attacker_action: "PsExec / RDP / WMI"
    systems: "Domain · Servers"
    detection_signals:
      - "Network logon Type 3 + service creation across multiple hosts in short window"
      - "IPC$ share access followed by ADMIN$ write"
      - "Unusual admin account authenticating to 5+ hosts within 30 minutes"
      - "PsExec service installation (PSEXESVC) on remote host"
    chokepoint_links:
      - label: "Remote Execution Tools"
        slug: "remote-execution-tools"
  - id: defense_evasion
    label: Defense Evasion
    detection_status: detected
    attacker_action: "Kill AV/EDR · Safe-mode boot · Stop backups"
    systems: "All hosts"
    detection_signals:
      - "Multiple security/backup services stopped in rapid succession"
      - "EDR kill tool execution (Backstab, PowerTool, GMER, Terminator)"
      - "bcdedit.exe with safeboot argument"
      - "PowerShell Set-MpPreference DisableRealtimeMonitoring / DisableAntiSpyware"
      - "Veeam, VSS, or SQL service termination"
    chokepoint_links:
      - label: "Ransomware Service Manipulation"
        slug: "ransomware-service-manipulation"
  - id: impact
    label: Impact
    mitre_tactic: "TA0040"
    mitre_techniques:
      - id: "T1486"
        name: "Data Encrypted for Impact"
      - id: "T1490"
        name: "Inhibit System Recovery"
      - id: "T1567.002"
        name: "Exfiltration to Cloud Storage"
    detection_status: exploited
    attacker_action: "Exfil data · VSS delete · File encrypt"
    systems: "All file servers · Cloud storage"
    detection_signals:
      - "vssadmin delete shadows / wmic shadowcopy delete / PowerShell Get-WmiObject Win32_Shadowcopy | Remove-WmiObject"
      - "Mass file modifications with high-entropy output (bulk file rename)"
      - "Ransom note .txt/.html creation across multiple directories"
      - "WinSCP / RClone / FileZilla outbound to cloud storage (Mega, attacker infrastructure)"

actors:
  - name: BlackBasta
    status: Inactive
    initial_access: "QakBot phishing / Teams social engineering / exploit acquisition (zero-days purchased within days of disclosure)"
    credential_access: "Mimikatz LSASS dump + ZeroLogon / NoPac / PrintNightmare CVE exploitation"
    lateral_movement: "PsExec + Cobalt Strike beacon (custom 'Coba PROXY' C2 infrastructure)"
    defense_evasion: "Backstab EDR kill + PowerShell Defender disable (DisableAntiSpyware) + bcdedit safeboot"
    impact: "vssadmin delete shadows + ChaCha20/RSA-4096 file encrypt (.basta extension)"
  - name: LockBit 3.0
    status: Disrupted
    initial_access: "Stolen RDP creds / exposed RMM / valid accounts"
    credential_access: "LSASS dump + SAM hive export"
    lateral_movement: "PsExec + Cobalt Strike + GPO mass-deploy"
    defense_evasion: "Comprehensive service kill list (50+ services) + registry modification"
    impact: "WMI shadow copy delete + fastest-in-class encrypt (LockBit 3.0 / Black)"
  - name: Akira
    status: Active
    initial_access: "VPN compromise (no MFA) / SonicWall exploitation / Veeam CVE-2024-40711"
    credential_access: "Mimikatz + LaZagne + esentutl browser credential theft + comsvcs.dll LSASS MiniDump"
    lateral_movement: "RDP + SSH + AnyDesk / RustDesk / MobaXterm"
    defense_evasion: "PowerTool + Terminator BYOVD + Zemana AntiMalware driver EDR kill"
    impact: "PowerShell WMI shadow delete + Akira / Akira_v2 (Rust) / Megazord encrypt"
  - name: Alphv/BlackCat
    status: Defunct
    initial_access: "Stolen creds / Eamfo infostealer (Veeam credential theft) / exposed web services"
    credential_access: "Eamfo Veeam credential theft + LSASS dump"
    lateral_movement: "PsExec + RDP + WMI"
    defense_evasion: "Multi-vendor EDR termination + reg.exe registry modification + bcdedit safeboot"
    impact: "vssadmin delete shadows + vim-cmd snapshot.removeall (ESXi) + cross-platform Rust encrypt"
  - name: Play
    status: Active
    initial_access: "N-day exploits (FortiOS, Exchange ProxyNotShell/OWASSRF)"
    credential_access: "Mimikatz LSASS dump"
    lateral_movement: "PsExec + WMI + Grixba custom infostealer"
    defense_evasion: "GMER + IOBit + Process Hacker + PowerTool"
    impact: "Custom .NET VSS Copying Tool + PlayCrypt selective file encrypt"

chokepoints:
  initial_access: "User executes payload OR exposed service is network-reachable"
  credential_access: "Elevated process reads memory/registry containing credential material"
  lateral_movement: "Valid admin credentials + network path open (445 / 3389 / 135)"
  defense_evasion: "SYSTEM-level process with service stop/delete permission"
  impact: "File system write access + encryption library loaded"

---

## Research Methodology

Procedure-level data in this attack chain was extracted and corroborated using
[Kitsune](https://github.com/christina23/kitsune), an AI-driven threat intelligence pipeline.
260 procedures were extracted across 36 reports from 5 ransomware actors, with cross-report
corroboration used to validate convergence patterns. Reports were sourced from
[ORKL](https://orkl.eu/) (Open Repository of Knowledge on Libraries) and direct vendor publications.

## Related Attack Chains

- [Infostealers]({{ '/attack-chains/infostealers/' | relative_url }}) - Often precedes ransomware via IABs
- [AiTM / Phishing Kits]({{ '/attack-chains/aitm/' | relative_url }}) - AiTM-compromised accounts sold to ransomware IABs
