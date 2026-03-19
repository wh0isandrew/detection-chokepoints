#!/usr/bin/env python3
"""
append_history.py
Extracts a compact weekly snapshot from _data/masq_infra.json and
appends it to _data/masq_infra_history.json, keyed by ISO week (YYYY-WW).
Idempotent: re-running within the same week overwrites the existing entry.
"""
import json
import sys
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
DATA_DIR  = REPO_ROOT / "_data"
SOURCE    = DATA_DIR / "masq_infra.json"
HISTORY   = DATA_DIR / "masq_infra_history.json"


def _load_json(path: Path, default=None):
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"[WARN] Could not load {path}: {exc}", file=sys.stderr)
    return default if default is not None else {}


def _extract_row(data: dict) -> tuple:
    """Return (week_key, row_dict) from a masq_infra snapshot."""
    generated_at = data.get("generated_at", "")
    try:
        dt = datetime.strptime(generated_at, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        dt = datetime.utcnow()
    week_key = dt.strftime("%G-%V")

    summary = data.get("summary", {})
    stats   = data.get("stats", {})

    lure_types = {
        e["tag"]: e["count"]
        for e in data.get("lure_types", [])
        if "tag" in e and "count" in e
    }
    traffic_sources = {
        e["source"]: e["count"]
        for e in data.get("traffic_sources", [])
        if "source" in e and "count" in e
    }
    top_asns = [
        {
            "asn":   e.get("asn", ""),
            "org":   e.get("org", ""),
            "count": e.get("count", 0),
            "pct":   e.get("pct", 0.0),
        }
        for e in data.get("asn_distribution", [])[:3]
    ]
    payload_families = [
        {"family": e.get("family", ""), "count": e.get("count", 0)}
        for e in data.get("payload_families", [])
    ]

    row = {
        "week":                 week_key,
        "generated_at":         generated_at,
        "total_domains":        summary.get("total_domains", 0),
        "campaigns_identified": summary.get("campaigns_identified", 0),
        "lets_encrypt_pct":     stats.get("tls_lets_encrypt_pct", 0.0),
        "lure_types":           lure_types,
        "traffic_sources":      traffic_sources,
        "top_asns":             top_asns,
        "payload_families":     payload_families,
    }
    return week_key, row


def main() -> None:
    data = _load_json(SOURCE)
    if not data:
        print(f"[ERROR] {SOURCE} is empty or missing — aborting", file=sys.stderr)
        sys.exit(1)

    week_key, row = _extract_row(data)
    history = _load_json(HISTORY, default={})
    existed = week_key in history
    history[week_key] = row
    HISTORY.write_text(json.dumps(history, indent=2, ensure_ascii=False), encoding="utf-8")

    action = "updated" if existed else "appended"
    print(f"  [{action}] week {week_key}: {row['total_domains']} domains, "
          f"{row['campaigns_identified']} campaigns, "
          f"LE={row['lets_encrypt_pct']}%")


if __name__ == "__main__":
    main()
