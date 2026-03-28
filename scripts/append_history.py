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
    generated_at = data.get("meta", {}).get("last_updated", "")
    try:
        dt = datetime.strptime(generated_at, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        dt = datetime.utcnow()
    week_key = dt.strftime("%G-%V")

    lure_types = {
        e["lure_type"]: e["count"]
        for e in (data.get("payload_summary", {}).get("lure_payload_matrix") or [])
        if "lure_type" in e and "count" in e
    }
    top_asns = [
        {
            "asn":   e.get("asn", ""),
            "org":   "",
            "count": e.get("count", 0),
            "pct":   0.0,
        }
        for e in (data.get("infrastructure_summary", {}).get("top_asns") or [])[:3]
    ]
    payload_families = [
        {"family": e.get("family", ""), "count": e.get("count", 0)}
        for e in (data.get("payload_summary", {}).get("top_families") or [])
    ]

    row = {
        "week":                 week_key,
        "generated_at":         generated_at,
        "total_domains":        data.get("meta", {}).get("record_count") or data.get("meta", {}).get("sample_size", 0),
        "campaigns_identified": len(data.get("campaigns", [])),
        "lets_encrypt_pct":     data.get("stats", {}).get("tls_lets_encrypt_pct", 0.0),
        "lure_types":           lure_types,
        "traffic_sources":      {e["source"]: e["count"] for e in (data.get("traffic_sources") or []) if "source" in e and "count" in e},
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
