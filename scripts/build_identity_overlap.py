"""
Build identity_domination_ttp_overlap.yml from Kitsune pipeline extraction data.
Reads scripts/_identity_ttps.txt (actor TTP pairs) and outputs YAML.
"""
import sys
from collections import defaultdict

# MITRE tactic mapping for AD / identity-domination techniques.
# Phases match the page stage structure: Initial Access, Credential Access,
# Privilege Escalation, Lateral Movement, Persistence, Impact + ancillary
# discovery/evasion buckets.
TACTIC_MAP = {
    # Initial Access
    "T1078": "Initial Access", "T1078.001": "Initial Access",
    "T1078.002": "Initial Access", "T1078.003": "Initial Access",
    "T1078.004": "Initial Access",
    "T1566": "Initial Access", "T1566.001": "Initial Access",
    "T1566.002": "Initial Access", "T1566.003": "Initial Access",
    "T1566.004": "Initial Access",
    "T1190": "Initial Access", "T1133": "Initial Access",
    "T1199": "Initial Access",
    "T1189": "Initial Access",
    "T1598": "Initial Access", "T1598.002": "Initial Access",
    "T1598.003": "Initial Access", "T1598.004": "Initial Access",
    "T1583": "Initial Access", "T1583.001": "Initial Access",
    "T1588": "Initial Access", "T1588.002": "Initial Access",
    # Credential Access
    "T1003": "Credential Access", "T1003.001": "Credential Access",
    "T1003.002": "Credential Access", "T1003.003": "Credential Access",
    "T1003.006": "Credential Access",
    "T1110": "Credential Access", "T1110.001": "Credential Access",
    "T1110.003": "Credential Access", "T1110.004": "Credential Access",
    "T1555": "Credential Access", "T1555.001": "Credential Access",
    "T1555.003": "Credential Access",
    "T1552": "Credential Access", "T1552.001": "Credential Access",
    "T1552.004": "Credential Access", "T1552.006": "Credential Access",
    "T1528": "Credential Access", "T1539": "Credential Access",
    "T1040": "Credential Access", "T1557": "Credential Access",
    "T1557.002": "Credential Access", "T1557.003": "Credential Access",
    "T1056": "Credential Access", "T1056.003": "Credential Access",
    "T1187": "Credential Access",  # Forced Authentication
    "T1558": "Credential Access",  # Kerberos
    "T1558.001": "Credential Access",  # Golden Ticket
    "T1558.002": "Credential Access",  # Silver Ticket
    "T1558.003": "Credential Access",  # Kerberoasting
    "T1558.004": "Credential Access",  # AS-REP Roasting
    "T1621": "Credential Access",  # MFA Request Generation (fatigue)
    # Privilege Escalation
    "T1068": "Privilege Escalation",
    "T1134": "Privilege Escalation", "T1134.001": "Privilege Escalation",
    "T1548": "Privilege Escalation", "T1548.002": "Privilege Escalation",
    "T1484": "Privilege Escalation", "T1484.001": "Privilege Escalation",
    "T1484.002": "Privilege Escalation",
    "T1098.001": "Privilege Escalation",
    # Lateral Movement
    "T1021": "Lateral Movement", "T1021.001": "Lateral Movement",
    "T1021.002": "Lateral Movement", "T1021.004": "Lateral Movement",
    "T1021.006": "Lateral Movement", "T1021.007": "Lateral Movement",
    "T1550": "Lateral Movement", "T1550.001": "Lateral Movement",
    "T1550.002": "Lateral Movement", "T1550.003": "Lateral Movement",
    "T1550.004": "Lateral Movement",
    "T1210": "Lateral Movement",
    "T1570": "Lateral Movement",
    # Persistence
    "T1098": "Persistence",
    "T1098.002": "Persistence", "T1098.003": "Persistence",
    "T1098.004": "Persistence", "T1098.005": "Persistence",
    "T1136": "Persistence", "T1136.001": "Persistence",
    "T1136.002": "Persistence", "T1136.003": "Persistence",
    "T1556": "Persistence", "T1556.004": "Persistence",
    "T1556.006": "Persistence", "T1556.007": "Persistence",
    "T1547": "Persistence", "T1547.001": "Persistence",
    "T1543": "Persistence", "T1543.003": "Persistence",
    "T1505": "Persistence", "T1505.003": "Persistence",
    # Impact
    "T1486": "Impact", "T1490": "Impact",
    "T1489": "Impact", "T1485": "Impact",
    "T1531": "Impact",  # Account Access Removal
    "T1657": "Impact",  # Financial Theft
    # Discovery
    "T1087": "Discovery", "T1087.001": "Discovery",
    "T1087.002": "Discovery", "T1087.003": "Discovery",
    "T1069": "Discovery", "T1069.001": "Discovery",
    "T1069.002": "Discovery", "T1069.003": "Discovery",
    "T1482": "Discovery", "T1018": "Discovery",
    "T1083": "Discovery", "T1033": "Discovery",
    "T1082": "Discovery", "T1016": "Discovery",
    "T1049": "Discovery", "T1057": "Discovery",
    "T1518": "Discovery", "T1518.001": "Discovery",
    "T1526": "Discovery", "T1538": "Discovery",
    # Defense Evasion
    "T1027": "Defense Evasion", "T1027.002": "Defense Evasion",
    "T1027.013": "Defense Evasion",
    "T1036": "Defense Evasion", "T1036.005": "Defense Evasion",
    "T1036.008": "Defense Evasion",
    "T1070": "Defense Evasion", "T1070.001": "Defense Evasion",
    "T1070.002": "Defense Evasion", "T1070.003": "Defense Evasion",
    "T1070.004": "Defense Evasion", "T1070.006": "Defense Evasion",
    "T1562": "Defense Evasion", "T1562.001": "Defense Evasion",
    "T1562.002": "Defense Evasion", "T1562.004": "Defense Evasion",
    "T1562.007": "Defense Evasion", "T1562.008": "Defense Evasion",
    "T1140": "Defense Evasion",
    "T1564": "Defense Evasion", "T1564.008": "Defense Evasion",
    # Collection / C2 / Exfil
    "T1114": "Collection", "T1114.002": "Collection",
    "T1114.003": "Collection", "T1213": "Collection",
    "T1005": "Collection", "T1119": "Collection",
    "T1071": "Command and Control", "T1071.001": "Command and Control",
    "T1071.004": "Command and Control", "T1090": "Command and Control",
    "T1090.001": "Command and Control", "T1090.003": "Command and Control",
    "T1105": "Command and Control", "T1573": "Command and Control",
    "T1573.001": "Command and Control", "T1573.002": "Command and Control",
    "T1568": "Command and Control", "T1568.002": "Command and Control",
    "T1041": "Exfiltration", "T1048": "Exfiltration",
    "T1048.003": "Exfiltration",
    "T1567": "Exfiltration", "T1567.002": "Exfiltration",
    # Execution
    "T1059": "Execution", "T1059.001": "Execution",
    "T1059.003": "Execution", "T1059.005": "Execution",
    "T1059.006": "Execution", "T1059.007": "Execution",
    "T1106": "Execution", "T1203": "Execution",
    "T1204": "Execution", "T1204.001": "Execution",
    "T1204.002": "Execution", "T1569": "Execution",
    "T1569.002": "Execution", "T1651": "Execution",
}

TECH_NAMES = {
    "T1078": "Valid Accounts", "T1078.001": "Default Accounts",
    "T1078.002": "Domain Accounts", "T1078.003": "Local Accounts",
    "T1078.004": "Cloud Accounts",
    "T1566": "Phishing", "T1566.001": "Spearphishing Attachment",
    "T1566.002": "Spearphishing Link",
    "T1566.003": "Spearphishing via Service",
    "T1566.004": "Spearphishing Voice",
    "T1190": "Exploit Public-Facing Application",
    "T1133": "External Remote Services",
    "T1199": "Trusted Relationship",
    "T1189": "Drive-by Compromise",
    "T1598": "Phishing for Information",
    "T1598.002": "Spearphishing Attachment",
    "T1598.003": "Spearphishing Link",
    "T1598.004": "Spearphishing Voice",
    "T1583": "Acquire Infrastructure",
    "T1583.001": "Domains",
    "T1588": "Obtain Capabilities", "T1588.002": "Tool",
    "T1003": "OS Credential Dumping",
    "T1003.001": "LSASS Memory",
    "T1003.002": "Security Account Manager",
    "T1003.003": "NTDS",
    "T1003.006": "DCSync",
    "T1110": "Brute Force", "T1110.001": "Password Guessing",
    "T1110.003": "Password Spraying",
    "T1110.004": "Credential Stuffing",
    "T1555": "Credentials from Password Stores",
    "T1555.001": "Keychain",
    "T1555.003": "Credentials from Web Browsers",
    "T1552": "Unsecured Credentials",
    "T1552.001": "Credentials In Files",
    "T1552.004": "Private Keys",
    "T1552.006": "Group Policy Preferences",
    "T1528": "Steal Application Access Token",
    "T1539": "Steal Web Session Cookie",
    "T1040": "Network Sniffing",
    "T1557": "Adversary-in-the-Middle",
    "T1557.002": "ARP Cache Poisoning",
    "T1557.003": "DHCP Spoofing",
    "T1056": "Input Capture",
    "T1056.003": "Web Portal Capture",
    "T1187": "Forced Authentication",
    "T1558": "Steal or Forge Kerberos Tickets",
    "T1558.001": "Golden Ticket",
    "T1558.002": "Silver Ticket",
    "T1558.003": "Kerberoasting",
    "T1558.004": "AS-REP Roasting",
    "T1621": "MFA Request Generation",
    "T1068": "Exploitation for Privilege Escalation",
    "T1134": "Access Token Manipulation",
    "T1134.001": "Token Impersonation/Theft",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1548.002": "Bypass User Account Control",
    "T1484": "Domain or Tenant Policy Modification",
    "T1484.001": "Group Policy Modification",
    "T1484.002": "Trust Modification",
    "T1098": "Account Manipulation",
    "T1098.001": "Additional Cloud Credentials",
    "T1098.002": "Additional Email Delegate Permissions",
    "T1098.003": "Additional Cloud Roles",
    "T1098.004": "SSH Authorized Keys",
    "T1098.005": "Device Registration",
    "T1021": "Remote Services",
    "T1021.001": "Remote Desktop Protocol",
    "T1021.002": "SMB/Windows Admin Shares",
    "T1021.004": "SSH",
    "T1021.006": "Windows Remote Management",
    "T1021.007": "Cloud Services",
    "T1550": "Use Alternate Authentication Material",
    "T1550.001": "Application Access Token",
    "T1550.002": "Pass the Hash",
    "T1550.003": "Pass the Ticket",
    "T1550.004": "Web Session Cookie",
    "T1210": "Exploitation of Remote Services",
    "T1570": "Lateral Tool Transfer",
    "T1136": "Create Account",
    "T1136.001": "Local Account",
    "T1136.002": "Domain Account",
    "T1136.003": "Cloud Account",
    "T1556": "Modify Authentication Process",
    "T1556.004": "Network Device Authentication",
    "T1556.006": "Multi-Factor Authentication",
    "T1556.007": "Hybrid Identity",
    "T1547": "Boot or Logon Autostart Execution",
    "T1547.001": "Registry Run Keys",
    "T1543": "Create or Modify System Process",
    "T1543.003": "Windows Service",
    "T1505": "Server Software Component",
    "T1505.003": "Web Shell",
    "T1486": "Data Encrypted for Impact",
    "T1490": "Inhibit System Recovery",
    "T1489": "Service Stop",
    "T1485": "Data Destruction",
    "T1531": "Account Access Removal",
    "T1657": "Financial Theft",
    "T1087": "Account Discovery",
    "T1087.001": "Local Account",
    "T1087.002": "Domain Account",
    "T1087.003": "Email Account",
    "T1069": "Permission Groups Discovery",
    "T1069.001": "Local Groups",
    "T1069.002": "Domain Groups",
    "T1069.003": "Cloud Groups",
    "T1482": "Domain Trust Discovery",
    "T1018": "Remote System Discovery",
    "T1083": "File and Directory Discovery",
    "T1033": "System Owner/User Discovery",
    "T1082": "System Information Discovery",
    "T1016": "System Network Config Discovery",
    "T1049": "System Network Connections Discovery",
    "T1057": "Process Discovery",
    "T1518": "Software Discovery",
    "T1518.001": "Security Software Discovery",
    "T1526": "Cloud Service Discovery",
    "T1538": "Cloud Service Dashboard",
    "T1027": "Obfuscated Files or Information",
    "T1027.002": "Software Packing",
    "T1027.013": "Encrypted/Encoded File",
    "T1036": "Masquerading",
    "T1036.005": "Match Legitimate Name or Location",
    "T1036.008": "Masquerade File Type",
    "T1070": "Indicator Removal",
    "T1070.001": "Clear Windows Event Logs",
    "T1070.002": "Clear Linux or Mac System Logs",
    "T1070.003": "Clear Command History",
    "T1070.004": "File Deletion",
    "T1070.006": "Timestomp",
    "T1562": "Impair Defenses",
    "T1562.001": "Disable or Modify Tools",
    "T1562.002": "Disable Windows Event Logging",
    "T1562.004": "Disable or Modify System Firewall",
    "T1562.007": "Disable or Modify Cloud Firewall",
    "T1562.008": "Disable or Modify Cloud Logs",
    "T1140": "Deobfuscate/Decode Files",
    "T1564": "Hide Artifacts",
    "T1564.008": "Email Hiding Rules",
    "T1114": "Email Collection",
    "T1114.002": "Remote Email Collection",
    "T1114.003": "Email Forwarding Rule",
    "T1213": "Data from Information Repositories",
    "T1005": "Data from Local System",
    "T1119": "Automated Collection",
    "T1071": "Application Layer Protocol",
    "T1071.001": "Web Protocols",
    "T1071.004": "DNS",
    "T1090": "Proxy",
    "T1090.001": "Internal Proxy",
    "T1090.003": "Multi-hop Proxy",
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
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "PowerShell",
    "T1059.003": "Windows Command Shell",
    "T1059.005": "Visual Basic",
    "T1059.006": "Python",
    "T1059.007": "JavaScript",
    "T1106": "Native API",
    "T1203": "Exploitation for Client Execution",
    "T1204": "User Execution",
    "T1204.001": "Malicious Link",
    "T1204.002": "Malicious File",
    "T1569": "System Services",
    "T1569.002": "Service Execution",
    "T1651": "Cloud Administration Command",
}

ALL_ACTORS = ["apt29", "storm0501", "storm2372", "scattered", "ransomware"]
ACTOR_NAMES = {
    "apt29": "APT29 / Midnight Blizzard",
    "storm0501": "Storm-0501",
    "storm2372": "Storm-2372",
    "scattered": "Scattered Spider",
    "ransomware": "Ransomware Operators",
}
ACTOR_COLORS = {
    "apt29": "#ef4444",
    "storm0501": "#f59e0b",
    "storm2372": "#8b5cf6",
    "scattered": "#ec4899",
    "ransomware": "#06b6d4",
}
PHASE_ORDER = [
    "Initial Access", "Execution", "Credential Access",
    "Privilege Escalation", "Persistence", "Lateral Movement",
    "Defense Evasion", "Discovery", "Collection",
    "Command and Control", "Exfiltration", "Impact",
]


def main():
    actor_ttps = defaultdict(set)
    with open("scripts/_identity_ttps.txt") as f:
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

    print("# Active Directory & Entra ID Identity Domination TTP Overlap Data")
    print("# Generated from Kitsune pipeline analysis of 12 threat reports via ORKL.")
    print("# 5 actors covering on-prem AD, hybrid identity, and cloud Entra ID.")
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
