"""
Build infostealer_ttp_overlap.yml from Kitsune pipeline extraction data.
Reads /tmp/infostealer_ttps.txt (actor TTP pairs) and outputs YAML.
"""
import sys
from collections import defaultdict

# MITRE ATT&CK phase mapping for infostealer-relevant techniques
TACTIC_MAP = {
    "T1566": "Distribution", "T1566.001": "Distribution", "T1566.002": "Distribution",
    "T1189": "Distribution", "T1204": "Execution", "T1204.002": "Execution",
    "T1059": "Execution", "T1059.001": "Execution", "T1059.003": "Execution",
    "T1059.005": "Execution", "T1106": "Execution", "T1129": "Execution",
    "T1053.005": "Execution",
    "T1027": "Defense Evasion", "T1027.002": "Defense Evasion",
    "T1027.007": "Defense Evasion", "T1027.013": "Defense Evasion",
    "T1036": "Defense Evasion", "T1140": "Defense Evasion",
    "T1055": "Defense Evasion", "T1070": "Defense Evasion",
    "T1070.003": "Defense Evasion", "T1070.004": "Defense Evasion",
    "T1218.010": "Defense Evasion", "T1218.011": "Defense Evasion",
    "T1562.001": "Defense Evasion", "T1574": "Defense Evasion",
    "T1622": "Defense Evasion",
    "T1543.003": "Persistence",
    "T1078": "Credential Access", "T1078.002": "Credential Access",
    "T1078.003": "Credential Access",
    "T1110": "Credential Access", "T1110.001": "Credential Access",
    "T1110.003": "Credential Access",
    "T1539": "Collection", "T1555": "Collection", "T1555.003": "Collection",
    "T1552.001": "Collection", "T1005": "Collection", "T1119": "Collection",
    "T1113": "Collection", "T1056.004": "Collection", "T1560": "Collection",
    "T1012": "Discovery", "T1016": "Discovery", "T1033": "Discovery",
    "T1046": "Discovery", "T1057": "Discovery", "T1069.001": "Discovery",
    "T1069.002": "Discovery", "T1082": "Discovery", "T1083": "Discovery",
    "T1087.001": "Discovery", "T1087.002": "Discovery", "T1482": "Discovery",
    "T1518": "Discovery", "T1614": "Discovery",
    "T1041": "Exfiltration", "T1048": "Exfiltration",
    "T1048.003": "Exfiltration", "T1030": "Exfiltration", "T1020": "Exfiltration",
    "T1071": "Command and Control", "T1071.001": "Command and Control",
    "T1071.004": "Command and Control", "T1095": "Command and Control",
    "T1105": "Command and Control", "T1132.001": "Command and Control",
    "T1571": "Command and Control", "T1573": "Command and Control",
    "T1568": "Command and Control", "T1090.003": "Command and Control",
    "T1102": "Command and Control",
}

TECH_NAMES = {
    "T1005": "Data from Local System", "T1012": "Query Registry",
    "T1016": "System Network Config Discovery", "T1020": "Automated Exfiltration",
    "T1027": "Obfuscated Files or Information", "T1027.002": "Software Packing",
    "T1027.007": "Dynamic API Resolution", "T1027.013": "Encrypted/Encoded File",
    "T1030": "Data Transfer Size Limits", "T1033": "System Owner/User Discovery",
    "T1036": "Masquerading", "T1041": "Exfiltration Over C2 Channel",
    "T1046": "Network Service Discovery", "T1048": "Exfil Over Alternative Protocol",
    "T1048.003": "Exfil Over Unencrypted Non-C2 Protocol",
    "T1055": "Process Injection", "T1057": "Process Discovery",
    "T1059": "Command and Scripting Interpreter", "T1059.001": "PowerShell",
    "T1059.003": "Windows Command Shell", "T1059.005": "Visual Basic",
    "T1071.001": "Web Protocols", "T1078": "Valid Accounts",
    "T1078.002": "Domain Accounts", "T1078.003": "Local Accounts",
    "T1082": "System Information Discovery", "T1083": "File and Directory Discovery",
    "T1095": "Non-Application Layer Protocol", "T1105": "Ingress Tool Transfer",
    "T1106": "Native API", "T1110.001": "Password Guessing",
    "T1110.003": "Password Spraying", "T1113": "Screen Capture",
    "T1119": "Automated Collection", "T1129": "Shared Modules",
    "T1132.001": "Standard Encoding", "T1140": "Deobfuscate/Decode Files",
    "T1189": "Drive-by Compromise", "T1204": "User Execution",
    "T1218.010": "Regsvr32", "T1218.011": "Rundll32",
    "T1482": "Domain Trust Discovery", "T1518": "Software Discovery",
    "T1539": "Steal Web Session Cookie", "T1552.001": "Credentials In Files",
    "T1555": "Credentials from Password Stores",
    "T1555.003": "Credentials from Web Browsers",
    "T1560": "Archive Collected Data", "T1562.001": "Disable or Modify Tools",
    "T1566": "Phishing", "T1566.001": "Spearphishing Attachment",
    "T1566.002": "Spearphishing Link", "T1571": "Non-Standard Port",
    "T1573": "Encrypted Channel", "T1574": "Hijack Execution Flow",
    "T1614": "System Location Discovery", "T1622": "Debugger Evasion",
    "T1056.004": "Credential API Hooking",
    "T1070": "Indicator Removal", "T1070.003": "Clear Command History",
    "T1070.004": "File Deletion",
    "T1543.003": "Windows Service", "T1053.005": "Scheduled Task",
}

ALL_ACTORS = ["redline", "lummac2", "vidar", "stealc", "raccoon"]
PHASE_ORDER = [
    "Distribution", "Execution", "Defense Evasion", "Discovery",
    "Collection", "Credential Access", "Exfiltration", "Command and Control",
]

def main():
    actor_ttps = defaultdict(set)
    with open("scripts/_infostealer_ttps.txt") as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) == 2:
                actor_ttps[parts[0]].add(parts[1])

    # Build phases with convergence (2+ actors)
    phases = defaultdict(list)
    seen = set()
    all_shared = set()
    for ttp in sorted(set(t for ts in actor_ttps.values() for t in ts)):
        phase = TACTIC_MAP.get(ttp)
        if not phase:
            continue
        groups = [a for a in ALL_ACTORS if ttp in actor_ttps[a]]
        if len(groups) >= 2 and ttp not in seen:
            name = TECH_NAMES.get(ttp, ttp)
            phases[phase].append({"id": ttp, "name": name, "groups": groups})
            seen.add(ttp)
            all_shared.add(ttp)

    # Print summary
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

    # Output YAML
    print("# Infostealer TTP Overlap Data")
    print("# Generated from Kitsune pipeline analysis of 13 threat reports via ORKL.")
    print("# 5 infostealer families, cross-report corroboration for convergence validation.")
    print(f"# Shared techniques (2+ actors): {total}")
    print(f"# Generated: 2026-04-13")
    print("")
    print("groups:")
    colors = {
        "redline": "#f85149", "lummac2": "#f0883e",
        "vidar": "#e3b341", "stealc": "#3fb950", "raccoon": "#58a6ff",
    }
    names = {
        "redline": "RedLine", "lummac2": "LummaC2",
        "vidar": "Vidar", "stealc": "StealC", "raccoon": "Raccoon",
    }
    for a in ALL_ACTORS:
        print(f'  - id: {a}')
        print(f'    name: "{names[a]}"')
        print(f'    color: "{colors[a]}"')
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
