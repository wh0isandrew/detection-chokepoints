---
layout: attack-chain
title: Ransomware Attack Chain
subtitle: "How ransomware operators all follow the same five-stage chokepoint sequence — regardless of group, brand, or tooling."
last_updated: 2026-04-12
permalink: /attack-chains/ransomware/
show_ttp_overlap: true
ttp_data_key: ransomware_ttp_overlap

stages:
  - id: initial_access
    label: Initial Access
    mitre_tactic: "TA0001"
    mitre_techniques:
      - id: "T1566.001"
        name: "Spearphishing Attachment"
      - id: "T1133"
        name: "External Remote Services"
      - id: "T1190"
        name: "Exploit Public-Facing App"
      - id: "T1078"
        name: "Valid Accounts"
      - id: "T1219"
        name: "Remote Access Software"
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
    mitre_tactic: "TA0006"
    mitre_techniques:
      - id: "T1003.001"
        name: "LSASS Memory"
      - id: "T1003.002"
        name: "SAM Hive"
      - id: "T1555"
        name: "Credentials from Password Stores"
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
    mitre_tactic: "TA0008"
    mitre_techniques:
      - id: "T1021.002"
        name: "SMB/Admin Shares"
      - id: "T1021.001"
        name: "Remote Desktop Protocol"
      - id: "T1569.002"
        name: "Service Execution (PsExec)"
      - id: "T1047"
        name: "WMI"
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
    mitre_tactic: "TA0005"
    mitre_techniques:
      - id: "T1562.001"
        name: "Disable Security Tools"
      - id: "T1562.009"
        name: "Safe Mode Boot"
      - id: "T1490"
        name: "Inhibit System Recovery"
      - id: "T1027"
        name: "Obfuscated Files or Information"
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

## VSS Deletion: Same Chokepoint, Five Different Procedures

Every actor must delete shadow copies before encryption (T1490) — the chokepoint is invariant.
But **the procedure varies by actor**, demonstrating why detection must cover multiple methods:

| Actor | VSS Deletion Method | Detection Signal |
|-------|-------------------|-----------------|
| **BlackBasta** | `vssadmin.exe delete shadows` | Sysmon EID 1: vssadmin.exe with "delete shadows" |
| **LockBit 3.0** | WMI: `select * from Win32_ShadowCopy` | WMI query for Win32_ShadowCopy class |
| **Akira** | PowerShell: `Get-WmiObject Win32_Shadowcopy \| Remove-WmiObject` | Sysmon EID 1: powershell.exe with Win32_Shadowcopy |
| **Alphv/BlackCat** | `vssadmin.exe` + ESXi: `vim-cmd vmsvc/snapshot.removeall` | vssadmin on Windows + vim-cmd on ESXi hypervisors |
| **Play** | Custom .NET VSS Copying Tool | .NET executable accessing VSS APIs (non-standard binary) |

This table illustrates the core chokepoint principle: **detect the invariant condition** (shadow copy deletion),
not the specific tool. A single `vssadmin.exe` detection misses 3 out of 5 actors.

## Research Methodology

Procedure-level data in this attack chain was extracted and corroborated using
[Kitsune](https://github.com/christina23/kitsune), an AI-driven threat intelligence pipeline.
260 procedures were extracted across 36 reports from 5 ransomware actors, with cross-report
corroboration used to validate convergence patterns. Reports were sourced from
[ORKL](https://orkl.eu/) (Open Repository of Knowledge on Libraries) and direct vendor publications.

### Reports Analyzed

**BlackBasta** (7 reports, 55 procedures, 44 techniques):
- [CISA Advisory AA24-131A: #StopRansomware: Black Basta](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a)
- [Unit42: Threat Assessment — Black Basta Ransomware](https://unit42.paloaltonetworks.com/threat-assessment-black-basta-ransomware/)
- [Qualys: Black Basta Ransomware — What You Need to Know](https://blog.qualys.com/vulnerabilities-threat-research/2024/09/19/black-basta-ransomware-what-you-need-to-know)
- [Kroll: Black Basta Technical Analysis](https://www.kroll.com/en/publications/cyber/black-basta-technical-analysis)
- Trustwave SpiderLabs: A Deep Dive into the Leaked Black Basta Chat Logs (PDF)
- Trend Micro: Black Basta Infiltrates Networks via QAKBOT, Brute Ratel, and Cobalt Strike (PDF, ORKL)
- SentinelOne: Black Basta Ransomware — Attacks Deploy Custom EDR Evasion Tools Tied to FIN7 (ORKL)

**LockBit 3.0** (7 reports, 54 procedures, 44 techniques):
- [CISA Advisory: #StopRansomware: LockBit 3.0](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-165a) (ORKL)
- Trend Micro: Ransomware: LockBit 3.0 Starts Using in Cyberattacks (ORKL)
- Northwave: Back in Black — Unlocking a LockBit 3.0 Ransomware Attack (ORKL)
- Cybereason: Lockbit 3.0 — Another Upgrade to World's Most Active Ransomware (ORKL)
- AhnLab: Quick Overview of Leaked LockBit 3.0 (Black) Builder (ORKL)
- Kroll: LockBit 3.0 Update — Unpicking the Ransomware's Latest Tricks (ORKL)
- Cluster25: Lockbit 3.0 — Ransomware Group Launches New Version (ORKL)

**Akira** (7 reports, 57 procedures, 38 techniques):
- [CISA Advisory: #StopRansomware: Akira Ransomware](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a) (ORKL)
- SentinelOne: Akira Ransomware is "bringin' 1988 back" (ORKL)
- Trend Micro: Akira Ransomware: The Evolution of a Major Threat (ORKL)
- Logpoint: Are Akira Ransomware's Crypto-Locking Malware Days Numbered? (ORKL)
- SophosLabs: Akira Ransomware Continues to Evolve (ORKL)
- S-RM: Weaponising VMs to Bypass EDR — Akira Ransomware (ORKL)
- Trend Micro: Akira's Play with Linux (ORKL)

**Alphv/BlackCat** (8 reports, 50 procedures, 32 techniques):
- Varonis: ALPHV/BlackCat Ransomware Family Becoming More Dangerous (ORKL)
- Krebs on Security: Who Wrote the ALPHV/BlackCat Ransomware Strain? (ORKL)
- Varonis: A Deep Dive Into ALPHV/BlackCat Ransomware (ORKL)
- Bitdefender: BlackCat/ALPHV Ransomware (ORKL)
- Symantec: ALPHV (BlackCat) Ransomware (ORKL)
- FortiGuard Labs: ALPHV Ransomware Gang Analysis (ORKL)
- Heise: BlackCat/ALPHV Ransomware Asks $5 Million (ORKL)
- Microsoft: ALPHV/BlackCat Ransomware Family Becoming More Dangerous (ORKL)

**Play** (7 reports, 44 procedures, 35 techniques):
- Symantec: Play Ransomware Group Using New Custom Data-Gathering Tools (ORKL)
- Rackspace / CrowdStrike: Play Ransomware Behind Rackspace Incident (ORKL)
- Trend Micro: An In-Depth Look at PLAY Ransomware (ORKL)
- Fortinet: Ransomware Roundup — Play Ransomware (ORKL)
- Trend Micro: Play Ransomware's Attack Playbook Similar to Hive, Nokoyawa (ORKL)
- Advintel: PLAY Ransomware (ORKL)
- Symantec: Play Ransomware Group Using New Custom Data-Gathering Tools (ORKL)

## References

- [Kaspersky: Common TTPs of Modern Ransomware (2022)](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2022/06/23093553/Common-TTPs-of-the-modern-ransomware_low-res.pdf)
- [CISA Advisory: BlackBasta ransomware](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a)
- [CISA Advisory: Akira ransomware](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a)
- [CISA Advisory: Play ransomware](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a)
- [DOJ: LockBit disruption operation (Feb 2024)](https://www.justice.gov/opa/pr/us-and-uk-disrupt-lockbit-ransomware-variant)
- [ORKL: Open Repository of Knowledge on Libraries](https://orkl.eu/)

## Related Attack Chains

- [Infostealers]({{ '/attack-chains/infostealers/' | relative_url }}) - Often precedes ransomware via IABs
- [AiTM / Phishing Kits]({{ '/attack-chains/aitm/' | relative_url }}) - AiTM-compromised accounts sold to ransomware IABs
