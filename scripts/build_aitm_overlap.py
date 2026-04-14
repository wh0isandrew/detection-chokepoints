"""
Build aitm_ttp_overlap.yml from Kitsune pipeline extraction data.
Reads scripts/_aitm_ttps.txt (actor TTP pairs) and outputs YAML.
"""
import sys
from collections import defaultdict

# MITRE tactic mapping for AiTM-relevant techniques
TACTIC_MAP = {
    # Resource Development / Infra Setup
    "T1583": "Infrastructure Setup", "T1583.001": "Infrastructure Setup",
    "T1583.003": "Infrastructure Setup", "T1583.004": "Infrastructure Setup",
    "T1583.008": "Infrastructure Setup", "T1588": "Infrastructure Setup",
    "T1588.002": "Infrastructure Setup", "T1584": "Infrastructure Setup",
    "T1608": "Infrastructure Setup", "T1608.001": "Infrastructure Setup",
    "T1608.004": "Infrastructure Setup", "T1608.005": "Infrastructure Setup",
    # Lure Delivery (Initial Access)
    "T1566": "Lure Delivery", "T1566.001": "Lure Delivery",
    "T1566.002": "Lure Delivery", "T1566.003": "Lure Delivery",
    "T1566.004": "Lure Delivery", "T1189": "Lure Delivery",
    "T1204": "Lure Delivery", "T1204.001": "Lure Delivery",
    "T1204.002": "Lure Delivery", "T1204.003": "Lure Delivery",
    # Proxy Interception / Credential Access
    "T1557": "Proxy Interception", "T1557.002": "Proxy Interception",
    "T1557.003": "Proxy Interception", "T1185": "Proxy Interception",
    "T1110": "Proxy Interception", "T1110.003": "Proxy Interception",
    "T1110.004": "Proxy Interception",
    "T1056": "Proxy Interception", "T1056.003": "Proxy Interception",
    # Token Harvest / Collection
    "T1539": "Token Harvest", "T1528": "Token Harvest",
    "T1552": "Token Harvest", "T1552.004": "Token Harvest",
    "T1550": "Token Harvest", "T1550.001": "Token Harvest",
    "T1550.004": "Token Harvest",
    # Account Takeover (Defense Evasion + Credential Access + Persistence)
    "T1078": "Account Takeover", "T1078.004": "Account Takeover",
    "T1621": "Account Takeover",  # MFA request generation
    "T1556": "Account Takeover", "T1556.006": "Account Takeover",
    "T1098": "Persistence", "T1098.001": "Persistence",
    "T1098.005": "Persistence", "T1136": "Persistence",
    "T1136.003": "Persistence", "T1547": "Persistence",
    # Discovery / Impact
    "T1087": "Discovery", "T1087.003": "Discovery",
    "T1526": "Discovery",  # Cloud service discovery
    "T1538": "Discovery",  # Cloud service dashboard
    "T1114": "Collection", "T1114.002": "Collection",
    "T1114.003": "Collection",
    # C2 / Exfil
    "T1071": "Command and Control", "T1071.001": "Command and Control",
    "T1105": "Command and Control",
    "T1568": "Command and Control", "T1568.002": "Command and Control",
    "T1027": "Defense Evasion", "T1027.013": "Defense Evasion",
    "T1036": "Defense Evasion", "T1036.005": "Defense Evasion",
    "T1036.008": "Defense Evasion",
    "T1598": "Lure Delivery", "T1598.002": "Lure Delivery",
    "T1598.003": "Lure Delivery",
    "T1199": "Lure Delivery",  # Trusted relationship
    # Execution
    "T1059": "Execution", "T1059.001": "Execution",
    "T1059.007": "Execution",
    # Exfiltration
    "T1041": "Exfiltration", "T1567": "Exfiltration",
    "T1567.002": "Exfiltration",
}

TECH_NAMES = {
    "T1566": "Phishing", "T1566.001": "Spearphishing Attachment",
    "T1566.002": "Spearphishing Link", "T1566.003": "Spearphishing via Service",
    "T1566.004": "Spearphishing Voice",
    "T1189": "Drive-by Compromise",
    "T1204": "User Execution", "T1204.001": "Malicious Link",
    "T1204.002": "Malicious File", "T1204.003": "Malicious Image",
    "T1557": "Adversary-in-the-Middle", "T1557.002": "ARP Cache Poisoning",
    "T1557.003": "DHCP Spoofing",
    "T1185": "Browser Session Hijacking",
    "T1110": "Brute Force", "T1110.003": "Password Spraying",
    "T1110.004": "Credential Stuffing",
    "T1056": "Input Capture", "T1056.003": "Web Portal Capture",
    "T1539": "Steal Web Session Cookie",
    "T1528": "Steal Application Access Token",
    "T1552": "Unsecured Credentials", "T1552.004": "Private Keys",
    "T1550": "Use Alternate Authentication Material",
    "T1550.001": "Application Access Token",
    "T1550.004": "Web Session Cookie",
    "T1078": "Valid Accounts", "T1078.004": "Cloud Accounts",
    "T1621": "Multi-Factor Authentication Request Generation",
    "T1556": "Modify Authentication Process",
    "T1556.006": "Multi-Factor Authentication",
    "T1098": "Account Manipulation",
    "T1098.001": "Additional Cloud Credentials",
    "T1098.005": "Device Registration",
    "T1136": "Create Account", "T1136.003": "Cloud Account",
    "T1547": "Boot or Logon Autostart Execution",
    "T1087": "Account Discovery", "T1087.003": "Email Account",
    "T1526": "Cloud Service Discovery",
    "T1538": "Cloud Service Dashboard",
    "T1114": "Email Collection", "T1114.002": "Remote Email Collection",
    "T1114.003": "Email Forwarding Rule",
    "T1071": "Application Layer Protocol", "T1071.001": "Web Protocols",
    "T1105": "Ingress Tool Transfer",
    "T1568": "Dynamic Resolution", "T1568.002": "Domain Generation Algorithms",
    "T1027": "Obfuscated Files or Information",
    "T1027.013": "Encrypted/Encoded File",
    "T1036": "Masquerading", "T1036.005": "Match Legitimate Name or Location",
    "T1036.008": "Masquerade File Type",
    "T1598": "Phishing for Information",
    "T1598.002": "Spearphishing Attachment", "T1598.003": "Spearphishing Link",
    "T1199": "Trusted Relationship",
    "T1583": "Acquire Infrastructure", "T1583.001": "Domains",
    "T1583.003": "Virtual Private Server", "T1583.004": "Server",
    "T1583.008": "Malvertising",
    "T1588": "Obtain Capabilities", "T1588.002": "Tool",
    "T1584": "Compromise Infrastructure",
    "T1608": "Stage Capabilities", "T1608.001": "Upload Malware",
    "T1608.004": "Drive-by Target", "T1608.005": "Link Target",
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "PowerShell", "T1059.007": "JavaScript",
    "T1041": "Exfiltration Over C2 Channel",
    "T1567": "Exfiltration Over Web Service",
    "T1567.002": "Exfiltration to Cloud Storage",
}

ALL_ACTORS = ["tycoon", "evilginx", "evilproxy", "sneaky", "device_code"]
ACTOR_NAMES = {
    "tycoon": "Tycoon 2FA", "evilginx": "Evilginx",
    "evilproxy": "EvilProxy", "sneaky": "Sneaky 2FA",
    "device_code": "Device Code Phishing",
}
ACTOR_COLORS = {
    "tycoon": "#f85149", "evilginx": "#d29922",
    "evilproxy": "#3fb950", "sneaky": "#58a6ff",
    "device_code": "#bc8cff",
}
PHASE_ORDER = [
    "Infrastructure Setup", "Lure Delivery", "Proxy Interception",
    "Token Harvest", "Account Takeover", "Persistence",
    "Discovery", "Collection", "Defense Evasion",
    "Command and Control", "Execution", "Exfiltration",
]


def main():
    actor_ttps = defaultdict(set)
    with open("scripts/_aitm_ttps.txt") as f:
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

    print(f"\nTotal shared techniques (2+ kits): {total}", file=sys.stderr)
    for a in ALL_ACTORS:
        print(f"{a}: {len(actor_ttps[a])} total techniques", file=sys.stderr)

    print("# AiTM / Phishing Kit TTP Overlap Data")
    print("# Generated from Kitsune pipeline analysis of 11 threat reports via ORKL.")
    print("# 5 AiTM kit families, cross-report corroboration for convergence validation.")
    print(f"# Shared techniques (2+ kits): {total}")
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
