#!/usr/bin/env python3
"""Validate chokepoint YAML entries against schema/chokepoint-schema.yml.

Run locally or in CI: `python scripts/validate_schema.py`
Exits non-zero if any entry has errors, so it can gate a pull request.

Why a standalone validator rather than a JSON-Schema file: the chokepoint
schema mixes simple enums with cross-file invariants (Sigma paths must exist on
disk, the parent directory must match a declared tactic). Those checks are
clearer in code than in a declarative schema, and the error messages can point
at the exact file and field a contributor needs to fix.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
CHOKEPOINTS_DIR = REPO / "chokepoints"

# ── enum constraints (mirror schema/chokepoint-schema.yml) ───────────────────
PRIORITY = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
PREVALENCE = {"VERY HIGH", "HIGH", "MEDIUM", "LOW", "EMERGING"}
DIFFICULTY = {"LOW", "MEDIUM", "HIGH"}
TACTICS = {
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact",
}
TIER = {"Research", "Hunt", "Analyst"}
# Variations.Status and Detections.ExpectedFPRate are authored as a leading
# severity/status token optionally followed by detail (a date, a range, or a
# parenthetical caveat). We validate the LEADING token against a controlled
# vocabulary and let the trailing context through, so genuine typos still fail
# but the house style ("Medium (password managers...)", "Disrupted (Oct 2024)")
# passes.
VARIATION_STATUS = {"Active", "Declining", "Emerging", "Legacy",
                    "Disrupted", "Defunct", "Inactive", "Dismantled"}
INTEL_TIER = {"primary", "supporting"}
FP_RATE_RE = re.compile(r"^\s*(very\s+)?(low|medium|high)(\s*[-/]\s*(low|medium|high))?\b", re.I)

REQUIRED = [
    "Name", "Id", "MitreIds", "Tactics", "Techniques", "DetectionPriority",
    "ThreatPrevalence", "DetectionDifficulty", "Description", "LastUpdated", "Author",
]
LIST_FIELDS = ["MitreIds", "Tactics", "Techniques"]

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
MITRE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

# directory name -> the tactic the entry is expected to declare
DIR_TO_TACTIC = {
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}


def check_enum(errors, label, value, allowed):
    if value is not None and value not in allowed:
        errors.append(f"{label}: {value!r} is not one of {sorted(allowed)}")


def leading_token(value: str) -> str:
    """First word of an authored status string, e.g. 'Disrupted (Oct 2024)' -> 'Disrupted'."""
    return re.split(r"[\s(/-]", value.strip(), maxsplit=1)[0] if isinstance(value, str) else value


def validate_entry(path: Path) -> list[str]:
    errors: list[str] = []
    rel = path.relative_to(REPO).as_posix()
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return [f"{rel}: YAML parse error: {exc}"]
    if not isinstance(data, dict):
        return [f"{rel}: top-level YAML is not a mapping"]

    # required fields present + non-empty
    for field in REQUIRED:
        if field not in data or data[field] in (None, "", [], {}):
            errors.append(f"{rel}: missing required field {field!r}")

    # list-typed fields really are lists
    for field in LIST_FIELDS:
        if field in data and not isinstance(data[field], list):
            errors.append(f"{rel}: {field} must be a list")

    # scalar enums
    check_enum(errors, f"{rel}: DetectionPriority", data.get("DetectionPriority"), PRIORITY)
    check_enum(errors, f"{rel}: ThreatPrevalence", data.get("ThreatPrevalence"), PREVALENCE)
    check_enum(errors, f"{rel}: DetectionDifficulty", data.get("DetectionDifficulty"), DIFFICULTY)

    # tactics
    for t in data.get("Tactics", []) or []:
        check_enum(errors, f"{rel}: Tactics entry", t, TACTICS)

    # id / date / mitre formats
    if isinstance(data.get("Id"), str) and not UUID_RE.match(data["Id"]):
        errors.append(f"{rel}: Id {data['Id']!r} is not a UUIDv4")
    if isinstance(data.get("LastUpdated"), str) and not DATE_RE.match(str(data["LastUpdated"])):
        errors.append(f"{rel}: LastUpdated {data['LastUpdated']!r} is not ISO YYYY-MM-DD")
    for mid in data.get("MitreIds", []) or []:
        if not (isinstance(mid, str) and MITRE_RE.match(mid)):
            errors.append(f"{rel}: MitreIds entry {mid!r} is not a Txxxx[.xxx] id")

    # nested enums + Sigma path existence
    for st in data.get("Chokepoints", []) or []:
        if isinstance(st, dict):
            check_enum(errors, f"{rel}: Chokepoints.DetectionTier", st.get("DetectionTier"), TIER)
            ref = st.get("SigmaRef")
            if ref and not (REPO / ref).exists():
                errors.append(f"{rel}: Chokepoints.SigmaRef path does not exist: {ref}")
    for v in data.get("Variations", []) or []:
        if isinstance(v, dict):
            check_enum(errors, f"{rel}: Variations.Status (leading token)",
                       leading_token(v.get("Status")) if v.get("Status") else None,
                       VARIATION_STATUS)
    for d in data.get("Detections", []) or []:
        if isinstance(d, dict):
            check_enum(errors, f"{rel}: Detections.Level", d.get("Level"), TIER)
            fp = d.get("ExpectedFPRate")
            if fp is not None and not FP_RATE_RE.match(str(fp)):
                errors.append(f"{rel}: Detections.ExpectedFPRate {fp!r} must start with "
                              f"Low/Medium/High (optionally 'Very ' or a range)")
            rule = d.get("SigmaRule")
            if rule and not (REPO / rule).exists():
                errors.append(f"{rel}: Detections.SigmaRule path does not exist: {rule}")
    for i in data.get("Intel", []) or []:
        if isinstance(i, dict):
            check_enum(errors, f"{rel}: Intel.Tier", i.get("Tier"), INTEL_TIER)

    # directory <-> tactic consistency (the file's folder must be a declared tactic)
    tactic_dir = path.parent.name
    expected = DIR_TO_TACTIC.get(tactic_dir)
    if expected is None:
        errors.append(f"{rel}: parent dir {tactic_dir!r} is not a known tactic directory")
    elif data.get("Tactics") and expected not in data["Tactics"]:
        errors.append(f"{rel}: folder implies tactic {expected!r} but Tactics={data.get('Tactics')}")

    return errors


def main() -> int:
    files = sorted(CHOKEPOINTS_DIR.glob("*/*.yml"))
    if not files:
        print("No chokepoint files found — nothing to validate.")
        return 0

    all_errors: list[str] = []
    for path in files:
        all_errors.extend(validate_entry(path))

    if all_errors:
        print(f"\n  {len(all_errors)} error(s) across {len(files)} chokepoint file(s):\n")
        for e in all_errors:
            print(f"  [FAIL] {e}")
        print()
        return 1

    print(f"[OK] All {len(files)} chokepoint entries valid.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
