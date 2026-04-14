"""
Build hypervisor_ttp_overlap.yml from Kitsune pipeline extraction data.
Reads scripts/_hypervisor_ttps.txt (actor TTP pairs) and outputs YAML.
"""
import sys
from collections import defaultdict

# MITRE tactic mapping for hypervisor/vSphere-relevant techniques
TACTIC_MAP = {
    # Initial Access & Recon
    "T1190": "Initial Access & Recon", "T1133": "Initial Access & Recon",
    "T1078": "Initial Access & Recon", "T1078.002": "Initial Access & Recon",
    "T1078.003": "Initial Access & Recon", "T1078.004": "Initial Access & Recon",
    "T1199": "Initial Access & Recon",
    "T1583": "Initial Access & Recon", "T1583.001": "Initial Access & Recon",
    "T1566": "Initial Access & Recon", "T1566.001": "Initial Access & Recon",
    "T1566.004": "Initial Access & Recon",
    "T1589": "Initial Access & Recon", "T1589.002": "Initial Access & Recon",
    "T1591": "Initial Access & Recon", "T1591.002": "Initial Access & Recon",
    "T1588": "Initial Access & Recon", "T1588.002": "Initial Access & Recon",
    # Management Plane Takeover / Execution
    "T1059": "Mgmt Plane Takeover", "T1059.001": "Mgmt Plane Takeover",
    "T1059.003": "Mgmt Plane Takeover", "T1059.004": "Mgmt Plane Takeover",
    "T1059.006": "Mgmt Plane Takeover", "T1059.007": "Mgmt Plane Takeover",
    "T1203": "Mgmt Plane Takeover",
    "T1106": "Mgmt Plane Takeover",
    "T1569": "Mgmt Plane Takeover", "T1569.001": "Mgmt Plane Takeover",
    "T1569.002": "Mgmt Plane Takeover",
    "T1651": "Mgmt Plane Takeover",  # Cloud Admin Command
    # Credential Theft
    "T1003": "Credential Theft", "T1003.001": "Credential Theft",
    "T1003.002": "Credential Theft", "T1003.003": "Credential Theft",
    "T1003.008": "Credential Theft",
    "T1555": "Credential Theft", "T1555.001": "Credential Theft",
    "T1555.003": "Credential Theft", "T1555.005": "Credential Theft",
    "T1539": "Credential Theft",
    "T1552": "Credential Theft", "T1552.001": "Credential Theft",
    "T1552.004": "Credential Theft", "T1552.006": "Credential Theft",
    "T1528": "Credential Theft",
    "T1621": "Credential Theft",
    "T1040": "Credential Theft",
    # Persistence
    "T1037": "Persistence", "T1037.001": "Persistence",
    "T1037.004": "Persistence",
    "T1098": "Persistence", "T1098.001": "Persistence",
    "T1098.004": "Persistence", "T1098.005": "Persistence",
    "T1136": "Persistence", "T1136.001": "Persistence",
    "T1136.003": "Persistence",
    "T1543": "Persistence", "T1543.002": "Persistence",
    "T1543.003": "Persistence",
    "T1547": "Persistence", "T1547.006": "Persistence",
    "T1547.013": "Persistence",
    "T1554": "Persistence",  # Compromise host software binary
    "T1505": "Persistence", "T1505.003": "Persistence",
    # Lateral Movement
    "T1210": "Lateral Movement",
    "T1021": "Lateral Movement", "T1021.001": "Lateral Movement",
    "T1021.002": "Lateral Movement", "T1021.004": "Lateral Movement",
    "T1021.006": "Lateral Movement",
    "T1550": "Lateral Movement", "T1550.001": "Lateral Movement",
    "T1550.002": "Lateral Movement", "T1550.003": "Lateral Movement",
    "T1550.004": "Lateral Movement",
    # Defense Evasion
    "T1070": "Defense Evasion", "T1070.002": "Defense Evasion",
    "T1070.003": "Defense Evasion", "T1070.004": "Defense Evasion",
    "T1070.006": "Defense Evasion",
    "T1036": "Defense Evasion", "T1036.004": "Defense Evasion",
    "T1036.005": "Defense Evasion", "T1036.008": "Defense Evasion",
    "T1027": "Defense Evasion", "T1027.002": "Defense Evasion",
    "T1027.004": "Defense Evasion", "T1027.013": "Defense Evasion",
    "T1562": "Defense Evasion", "T1562.001": "Defense Evasion",
    "T1562.002": "Defense Evasion", "T1562.004": "Defense Evasion",
    "T1562.007": "Defense Evasion",
    "T1564": "Defense Evasion", "T1564.001": "Defense Evasion",
    "T1564.003": "Defense Evasion", "T1564.008": "Defense Evasion",
    "T1140": "Defense Evasion",
    "T1218": "Defense Evasion", "T1218.011": "Defense Evasion",
    "T1620": "Defense Evasion",  # Reflective Code Loading
    "T1553": "Defense Evasion", "T1553.002": "Defense Evasion",
    "T1497": "Defense Evasion", "T1497.001": "Defense Evasion",
    # Discovery
    "T1018": "Discovery",  # Remote System Discovery
    "T1049": "Discovery",  # System Network Connections Discovery
    "T1057": "Discovery", "T1082": "Discovery",
    "T1083": "Discovery", "T1087": "Discovery",
    "T1087.001": "Discovery", "T1087.002": "Discovery",
    "T1087.003": "Discovery",
    "T1016": "Discovery", "T1033": "Discovery",
    "T1069": "Discovery", "T1069.001": "Discovery",
    "T1069.002": "Discovery",
    "T1482": "Discovery", "T1526": "Discovery",
    "T1518": "Discovery", "T1518.001": "Discovery",
    # Collection
    "T1005": "Collection", "T1039": "Collection",
    "T1074": "Collection", "T1074.001": "Collection",
    "T1114": "Collection", "T1114.002": "Collection",
    "T1560": "Collection", "T1560.001": "Collection",
    "T1602": "Collection",  # Data from Configuration Repository
    "T1213": "Collection",
    "T1119": "Collection",
    # Command and Control / Exfiltration
    "T1071": "C2 & Exfiltration", "T1071.001": "C2 & Exfiltration",
    "T1071.004": "C2 & Exfiltration",
    "T1090": "C2 & Exfiltration", "T1090.001": "C2 & Exfiltration",
    "T1090.003": "C2 & Exfiltration",
    "T1095": "C2 & Exfiltration", "T1105": "C2 & Exfiltration",
    "T1573": "C2 & Exfiltration", "T1573.001": "C2 & Exfiltration",
    "T1573.002": "C2 & Exfiltration",
    "T1568": "C2 & Exfiltration", "T1568.002": "C2 & Exfiltration",
    "T1041": "C2 & Exfiltration",
    "T1048": "C2 & Exfiltration", "T1048.003": "C2 & Exfiltration",
    "T1567": "C2 & Exfiltration", "T1567.002": "C2 & Exfiltration",
    # Impact
    "T1486": "Impact", "T1490": "Impact",
    "T1489": "Impact", "T1485": "Impact",
    "T1529": "Impact",  # System Shutdown/Reboot
    "T1561": "Impact", "T1561.001": "Impact",
    "T1561.002": "Impact",
    # Privilege Escalation (tag often maps to its sub-techniques under Mgmt Plane Takeover,
    # but core escalation techniques stay in their own phase)
    "T1068": "Mgmt Plane Takeover",
    "T1134": "Mgmt Plane Takeover", "T1134.001": "Mgmt Plane Takeover",
    "T1484": "Mgmt Plane Takeover", "T1484.002": "Mgmt Plane Takeover",
}

TECH_NAMES = {
    "T1190": "Exploit Public-Facing Application",
    "T1133": "External Remote Services",
    "T1078": "Valid Accounts", "T1078.002": "Domain Accounts",
    "T1078.003": "Local Accounts", "T1078.004": "Cloud Accounts",
    "T1199": "Trusted Relationship",
    "T1583": "Acquire Infrastructure", "T1583.001": "Domains",
    "T1566": "Phishing", "T1566.001": "Spearphishing Attachment",
    "T1566.004": "Spearphishing Voice",
    "T1589": "Gather Victim Identity Information",
    "T1589.002": "Email Addresses",
    "T1591": "Gather Victim Org Information",
    "T1591.002": "Business Relationships",
    "T1588": "Obtain Capabilities", "T1588.002": "Tool",
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "PowerShell", "T1059.003": "Windows Command Shell",
    "T1059.004": "Unix Shell", "T1059.006": "Python",
    "T1059.007": "JavaScript",
    "T1203": "Exploitation for Client Execution",
    "T1106": "Native API",
    "T1569": "System Services", "T1569.001": "Launchctl",
    "T1569.002": "Service Execution",
    "T1651": "Cloud Administration Command",
    "T1003": "OS Credential Dumping", "T1003.001": "LSASS Memory",
    "T1003.002": "Security Account Manager", "T1003.003": "NTDS",
    "T1003.008": "/etc/passwd and /etc/shadow",
    "T1555": "Credentials from Password Stores",
    "T1555.001": "Keychain", "T1555.003": "Credentials from Web Browsers",
    "T1555.005": "Password Managers",
    "T1539": "Steal Web Session Cookie",
    "T1552": "Unsecured Credentials",
    "T1552.001": "Credentials In Files",
    "T1552.004": "Private Keys",
    "T1552.006": "Group Policy Preferences",
    "T1528": "Steal Application Access Token",
    "T1621": "MFA Request Generation",
    "T1040": "Network Sniffing",
    "T1037": "Boot or Logon Init Scripts",
    "T1037.001": "Logon Script (Windows)",
    "T1037.004": "RC Scripts",
    "T1098": "Account Manipulation",
    "T1098.001": "Additional Cloud Credentials",
    "T1098.004": "SSH Authorized Keys",
    "T1098.005": "Device Registration",
    "T1136": "Create Account", "T1136.001": "Local Account",
    "T1136.003": "Cloud Account",
    "T1543": "Create or Modify System Process",
    "T1543.002": "Systemd Service",
    "T1543.003": "Windows Service",
    "T1547": "Boot or Logon Autostart Execution",
    "T1547.006": "Kernel Modules and Extensions",
    "T1547.013": "XDG Autostart Entries",
    "T1554": "Compromise Host Software Binary",
    "T1505": "Server Software Component", "T1505.003": "Web Shell",
    "T1210": "Exploitation of Remote Services",
    "T1021": "Remote Services", "T1021.001": "Remote Desktop Protocol",
    "T1021.002": "SMB/Windows Admin Shares",
    "T1021.004": "SSH", "T1021.006": "Windows Remote Management",
    "T1550": "Use Alternate Authentication Material",
    "T1550.001": "Application Access Token",
    "T1550.002": "Pass the Hash",
    "T1550.003": "Pass the Ticket",
    "T1550.004": "Web Session Cookie",
    "T1070": "Indicator Removal", "T1070.002": "Clear Linux or Mac System Logs",
    "T1070.003": "Clear Command History",
    "T1070.004": "File Deletion",
    "T1070.006": "Timestomp",
    "T1036": "Masquerading", "T1036.004": "Masquerade Task or Service",
    "T1036.005": "Match Legitimate Name or Location",
    "T1036.008": "Masquerade File Type",
    "T1027": "Obfuscated Files or Information",
    "T1027.002": "Software Packing",
    "T1027.004": "Compile After Delivery",
    "T1027.013": "Encrypted/Encoded File",
    "T1562": "Impair Defenses",
    "T1562.001": "Disable or Modify Tools",
    "T1562.002": "Disable Windows Event Logging",
    "T1562.004": "Disable or Modify System Firewall",
    "T1562.007": "Disable or Modify Cloud Firewall",
    "T1564": "Hide Artifacts", "T1564.001": "Hidden Files and Directories",
    "T1564.003": "Hidden Window",
    "T1564.008": "Email Hiding Rules",
    "T1140": "Deobfuscate/Decode Files",
    "T1218": "System Binary Proxy Execution",
    "T1218.011": "Rundll32",
    "T1620": "Reflective Code Loading",
    "T1553": "Subvert Trust Controls", "T1553.002": "Code Signing",
    "T1497": "Virtualization/Sandbox Evasion",
    "T1497.001": "System Checks",
    "T1018": "Remote System Discovery",
    "T1049": "System Network Connections Discovery",
    "T1057": "Process Discovery", "T1082": "System Information Discovery",
    "T1083": "File and Directory Discovery",
    "T1087": "Account Discovery", "T1087.001": "Local Account",
    "T1087.002": "Domain Account", "T1087.003": "Email Account",
    "T1016": "System Network Config Discovery",
    "T1033": "System Owner/User Discovery",
    "T1069": "Permission Groups Discovery",
    "T1069.001": "Local Groups", "T1069.002": "Domain Groups",
    "T1482": "Domain Trust Discovery",
    "T1526": "Cloud Service Discovery",
    "T1518": "Software Discovery",
    "T1518.001": "Security Software Discovery",
    "T1005": "Data from Local System",
    "T1039": "Data from Network Shared Drive",
    "T1074": "Data Staged", "T1074.001": "Local Data Staging",
    "T1114": "Email Collection", "T1114.002": "Remote Email Collection",
    "T1560": "Archive Collected Data",
    "T1560.001": "Archive via Utility",
    "T1602": "Data from Configuration Repository",
    "T1213": "Data from Information Repositories",
    "T1119": "Automated Collection",
    "T1071": "Application Layer Protocol",
    "T1071.001": "Web Protocols", "T1071.004": "DNS",
    "T1090": "Proxy", "T1090.001": "Internal Proxy",
    "T1090.003": "Multi-hop Proxy",
    "T1095": "Non-Application Layer Protocol",
    "T1105": "Ingress Tool Transfer",
    "T1573": "Encrypted Channel",
    "T1573.001": "Symmetric Cryptography",
    "T1573.002": "Asymmetric Cryptography",
    "T1568": "Dynamic Resolution",
    "T1568.002": "Domain Generation Algorithms",
    "T1041": "Exfiltration Over C2 Channel",
    "T1048": "Exfil Over Alternative Protocol",
    "T1048.003": "Exfil Over Unencrypted Non-C2 Protocol",
    "T1567": "Exfiltration Over Web Service",
    "T1567.002": "Exfiltration to Cloud Storage",
    "T1486": "Data Encrypted for Impact",
    "T1490": "Inhibit System Recovery",
    "T1489": "Service Stop", "T1485": "Data Destruction",
    "T1529": "System Shutdown/Reboot",
    "T1561": "Disk Wipe", "T1561.001": "Disk Content Wipe",
    "T1561.002": "Disk Structure Wipe",
    "T1068": "Exploitation for Privilege Escalation",
    "T1134": "Access Token Manipulation",
    "T1134.001": "Token Impersonation/Theft",
    "T1484": "Domain or Tenant Policy Modification",
    "T1484.002": "Trust Modification",
}

ALL_ACTORS = ["brick", "unc3886", "unc3944", "play", "alphv"]
ACTOR_NAMES = {
    "brick": "BRICKSTORM / UNC5221",
    "unc3886": "UNC3886",
    "unc3944": "UNC3944 / Scattered Spider",
    "play": "Play Ransomware",
    "alphv": "Alphv / BlackCat",
}
ACTOR_COLORS = {
    "brick": "#ef4444",
    "unc3886": "#8b5cf6",
    "unc3944": "#ec4899",
    "play": "#f59e0b",
    "alphv": "#3b82f6",
}
PHASE_ORDER = [
    "Initial Access & Recon", "Mgmt Plane Takeover", "Credential Theft",
    "Persistence", "Lateral Movement", "Defense Evasion",
    "Discovery", "Collection", "C2 & Exfiltration", "Impact",
]


def main():
    actor_ttps = defaultdict(set)
    with open("scripts/_hypervisor_ttps.txt") as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) == 2:
                actor_ttps[parts[0]].add(parts[1])

    phases = defaultdict(list)
    seen = set()
    for ttp in sorted(set(t for ts in actor_ttps.values() for t in ts)):
        phase = TACTIC_MAP.get(ttp)
        if not phase:
            continue
        groups = [a for a in ALL_ACTORS if ttp in actor_ttps[a]]
        if len(groups) >= 2 and ttp not in seen:
            name = TECH_NAMES.get(ttp, ttp)
            phases[phase].append({"id": ttp, "name": name, "groups": groups})
            seen.add(ttp)

    total = 0
    for p in PHASE_ORDER:
        techs = phases.get(p, [])
        total += len(techs)
        print(f"{p}: {len(techs)} shared techniques", file=sys.stderr)
        for t in techs:
            print(f"  {t['id']} {t['name']} -> {t['groups']}", file=sys.stderr)

    print(f"\nTotal shared techniques (2+ actors): {total}", file=sys.stderr)
    for a in ALL_ACTORS:
        print(f"{a}: {len(actor_ttps[a])} total techniques", file=sys.stderr)

    print("# Hypervisor Compromise TTP Overlap Data")
    print("# Generated from Kitsune pipeline analysis of 12 threat reports via ORKL.")
    print("# 5 actors targeting VMware vSphere / ESXi, cross-report corroboration for convergence.")
    print(f"# Shared techniques (2+ actors): {total}")
    print(f"# Generated: 2026-04-14")
    print("")
    print("groups:")
    for a in ALL_ACTORS:
        print(f'  - id: {a}')
        print(f'    name: "{ACTOR_NAMES[a]}"')
        print(f'    color: "{ACTOR_COLORS[a]}"')
    print("")
    print("phases:")
    for p in PHASE_ORDER:
        techs = phases.get(p, [])
        if not techs:
            continue
        print(f'  - label: "{p}"')
        print(f"    techniques:")
        for t in techs:
            print(f'      - id: "{t["id"]}"')
            print(f'        name: "{t["name"]}"')
            grp_str = ", ".join(t["groups"])
            print(f"        groups: [{grp_str}]")
        print("")


if __name__ == "__main__":
    main()
