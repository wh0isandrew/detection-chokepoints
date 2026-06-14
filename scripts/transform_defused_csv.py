#!/usr/bin/env python3
"""Transform Defused honeypot export CSV(s) into _data/edge_exploits.yml.

Why this exists: the edge-exploits trends page used to be hand-typed. This reads
the Defused export(s) (default: all export_shared_*.csv in ~/Downloads),
aggregates per day, and writes combined = frozen baseline + live so history
ACCUMULATES instead of being overwritten (decision #002). Aggregates only -- no
IP address ever reaches the repo (decision #001); only counts.

Data shape facts this relies on (verified against the May 2026 export and the
page it reproduces):
  * Exports are pre-filtered by the analyst to high+critical severity, so the
    Severity column is uniformly "major" -- a dead dimension, intentionally skipped.
  * Each export covers a time WINDOW, not a cumulative dump. Windows are merged
    at DAY granularity (newer export's day replaces older's -- newest is most
    complete). NOT row-deduped: Defused gives no per-alert id, and identical
    rows in the same second are distinct rapid-fire events the page counts.

The first export (Mar 14-Apr 13) was taken from a mobile session and not
retained; it survives only as scripts/edge_exploits_baseline.yml (frozen, never
recomputed). baseline = (page combined) - (CSV live), validated once.

Usage:
    py scripts/transform_defused_csv.py                 # all CSVs in ~/Downloads
    py scripts/transform_defused_csv.py --input X.csv   # one specific export
    py scripts/transform_defused_csv.py --check-seed    # assert it reproduces the page
"""
from __future__ import annotations

import argparse
import csv
import glob
import os
import re
from collections import Counter
from datetime import date
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
BASELINE_FILE = REPO / "scripts" / "edge_exploits_baseline.yml"
OUT = REPO / "_data" / "edge_exploits.yml"
DEFAULT_GLOB = os.path.expanduser("~/Downloads/export_shared_*.csv")

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
MONTHS = {1: "Jan", 2: "Feb", 3: "Mar", 4: "Apr", 5: "May", 6: "Jun",
          7: "Jul", 8: "Aug", 9: "Sep", 10: "Oct", 11: "Nov", 12: "Dec"}

# CSV "Decoy Type" -> page display name. Only entries that differ from the raw
# string need listing; everything else passes through. Mapping lives here (logic
# the page contract depends on), not in the data file.
DECOY_DISPLAY = {
    "cPanel": "cPanel WHM",
    "Cisco Catalyst SD-WAN (vManage)": "Cisco SD-WAN",
}

# Page headline stat cells, keyed by CVE. baseline contributes the first-window
# count (frozen); live adds the rest.
HEADLINE = [
    ("citrixbleed2", "CitrixBleed 2",     "CVE-2025-5777"),
    ("nextjs_rce",   "Next.js RCE (new)", "CVE-2025-55182"),
    ("cpanel_whm",   "cPanel WHM chain",  "CVE-2026-41940"),
]

# The 6-day hole between the two export windows; rendered as a visible gap.
GAP_DAYS = ["2026-04-14", "2026-04-15", "2026-04-16", "2026-04-17", "2026-04-18"]


class _QuoteCommaDumper(yaml.SafeDumper):
    """SafeDumper that single-quotes strings containing a comma, so display
    values like "25,420" survive the YAML round-trip into Jekyll -- which
    otherwise reads an unquoted 25,420 and drops the comma."""


def _repr_str(dumper, data):
    return dumper.represent_scalar("tag:yaml.org,2002:str", data,
                                   style="'" if "," in data else None)


_QuoteCommaDumper.add_representer(str, _repr_str)


def label_for(iso: str) -> str:
    y, m, d = (int(x) for x in iso.split("-"))
    return f"{MONTHS[m]} {d}"


def human(n: int) -> str:
    return f"{n / 1000:.1f}k" if n >= 1000 else str(n)


def aggregate_file(path):
    """One export CSV -> {iso_date: {total, ips:set, cve:Counter, decoy:Counter}}.

    Counts every row -- see module docstring on why there is no row-level dedup.
    Cross-export overlap is resolved at the day level in build() (newest wins).
    """
    days = {}
    with open(path, encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            iso = (r.get("Datetime") or "")[:10]
            if not iso:
                continue
            rec = days.setdefault(iso, {"total": 0, "ips": set(),
                                        "cve": Counter(), "decoy": Counter()})
            rec["total"] += 1
            ip = (r.get("Attacker IP") or "").strip()
            if ip:
                rec["ips"].add(ip)
            decoy = (r.get("Decoy Type") or "").strip()
            rec["decoy"][DECOY_DISPLAY.get(decoy, decoy)] += 1
            m = CVE_RE.search(r.get("Alert") or "")
            if m:
                rec["cve"][m.group(0)] += 1
    return days


def build(paths):
    baseline = yaml.safe_load(BASELINE_FILE.read_text(encoding="utf-8"))
    # Merge exports at day granularity: process oldest->newest (export_shared_
    # YYYYMMDD_* sorts chronologically) so a newer export's day replaces an older
    # one (newest is most complete). Disjoint windows simply union.
    live_days = {}
    seen_days = set()
    for p in sorted(paths):
        fdays = aggregate_file(p)
        overlap = seen_days & set(fdays)
        if overlap:
            print(f"  WARN {p.name}: {len(overlap)} day(s) overlap an earlier "
                  "export; replaced with this (newer) export's counts.")
        live_days.update(fdays)
        seen_days |= set(fdays)
    if not live_days:
        raise SystemExit("No dated rows parsed from the export(s).")

    live_total = sum(d["total"] for d in live_days.values())
    live_cve, live_decoy, live_ips = Counter(), Counter(), set()
    for d in live_days.values():
        live_cve.update(d["cve"])
        live_decoy.update(d["decoy"])
        live_ips |= d["ips"]

    targets = Counter()
    for name, n in baseline["targets"].items():
        targets[name] += n
    for name, n in live_decoy.items():
        targets[name] += n

    headline = []
    for key, label, cve in HEADLINE:
        count = baseline["headline_cves"].get(cve, 0) + live_cve.get(cve, 0)
        headline.append({"key": key, "label": label, "cve": cve,
                         "count": count, "display": f"{count:,}"})

    artifact_day = max(live_days)
    daily = []
    for row in baseline["daily"]:
        daily.append({"date": row["date"], "label": label_for(row["date"]),
                      "total": row["total"]})
    for iso in GAP_DAYS:
        daily.append({"date": iso, "label": "", "total": None})
    for iso in sorted(live_days):
        d = live_days[iso]
        entry = {"date": iso,
                 "label": label_for(iso) + ("*" if iso == artifact_day else ""),
                 "total": d["total"], "unique_ips": len(d["ips"])}
        if iso == artifact_day:
            entry["artifact"] = True
        daily.append(entry)

    total_events = baseline["total_events"] + live_total
    live_min, live_max = min(live_days), max(live_days)
    base_min = baseline["daily"][0]["date"]

    out = {
        "meta": {
            "source": "Defused Cyber honeypot telemetry",
            "source_url": "https://defusedcyber.com/",
            "severity_scope": "high and critical severity alerts only",
            "baseline_window": baseline["window"],
            "live_window": f"{label_for(live_min)} - {label_for(live_max)}, {live_max[:4]}",
            "date_range": f"{label_for(base_min)} - {label_for(live_max)}, {live_max[:4]}",
            "date_range_note": "two export windows, 6-day gap Apr 14-18",
            "total_events": total_events,
            "total_display": human(total_events),
            "total_events_display": f"{total_events:,}",
            "decoy_count_display": baseline["decoy_count_display"],
            "cve_count_display": baseline["cve_count_display"],
            "live_decoy_count": len(live_decoy),
            "live_cve_count": len(live_cve),
            "live_unique_ips": len(live_ips),
            "generated": date.today().isoformat(),
        },
        "headline": headline,
        "targets": [{"name": n, "count": c, "display": f"{c:,}"}
                    for n, c in sorted(targets.items(), key=lambda kv: (-kv[1], kv[0]))],
        "daily": daily,
        "cb2_daily": baseline["cb2_daily"],
        "cves": [{"id": c, "count": n}
                 for c, n in sorted(live_cve.items(), key=lambda kv: (-kv[1], kv[0]))],
    }
    return out, live_total, live_cve, live_ips


def check_seed(out, live_total, live_cve, live_ips) -> None:
    """Assert the seed reproduces the page exactly. Seed-time only -- the refresher
    runs without this, since new exports legitimately change these numbers."""
    checks = [
        ("live_total", live_total, 10419),
        ("combined_total", out["meta"]["total_events"], 25420),
        ("live CVE-2025-5777", live_cve.get("CVE-2025-5777"), 3033),
        ("live CVE-2025-55182", live_cve.get("CVE-2025-55182"), 2683),
        ("live CVE-2026-41940", live_cve.get("CVE-2026-41940"), 1515),
        ("live_unique_ips", len(live_ips), 1034),
    ]
    tg = {t["name"]: t["count"] for t in out["targets"]}
    for name, want in [("Citrix NetScaler", 11995), ("React Server", 2683),
                       ("FortiWeb", 2037), ("cPanel WHM", 1515),
                       ("Cisco SD-WAN", 1383), ("SAP Netweaver", 1341),
                       ("Ivanti Connect Secure", 1035), ("SonicWall SMA", 834)]:
        checks.append(("target " + name, tg.get(name), want))
    hd = {h["key"]: h["count"] for h in out["headline"]}
    checks += [("headline citrixbleed2", hd["citrixbleed2"], 11145),
               ("headline nextjs_rce", hd["nextjs_rce"], 2683),
               ("headline cpanel_whm", hd["cpanel_whm"], 1515)]

    failed = 0
    for name, got, want in checks:
        ok = got == want
        failed += not ok
        print(("  ok   " if ok else "  FAIL ") + f"{name}: got {got} want {want}")
    if failed:
        raise SystemExit(f"SEED VALIDATION FAILED: {failed} check(s)")
    print("  seed reproduces the page: all %d checks pass" % len(checks))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", help="one export CSV (default: all export_shared_*.csv in ~/Downloads)")
    ap.add_argument("--glob", default=DEFAULT_GLOB)
    ap.add_argument("--check-seed", action="store_true",
                    help="assert output reproduces the page (seed-time validation)")
    args = ap.parse_args()

    paths = [Path(args.input)] if args.input else [Path(p) for p in sorted(glob.glob(args.glob))]
    if not paths:
        raise SystemExit(f"No export CSV found (looked for {args.glob})")

    out, live_total, live_cve, live_ips = build(paths)
    if args.check_seed:
        check_seed(out, live_total, live_cve, live_ips)

    header = (
        "# Generated by scripts/transform_defused_csv.py -- do not hand-edit.\n"
        "# Combined = frozen baseline (scripts/edge_exploits_baseline.yml, Mar 14-Apr 13)\n"
        "# + live window recomputed from Defused export CSV(s). Aggregates only; no IPs.\n\n"
    )
    OUT.write_text(
        header + yaml.dump(out, Dumper=_QuoteCommaDumper, sort_keys=False,
                           allow_unicode=True, width=200, default_flow_style=False),
        encoding="utf-8", newline="\n")
    print("OK wrote", OUT.relative_to(REPO),
          f"({len(paths)} CSV, total {out['meta']['total_events']}, "
          f"live {live_total}, unique_ips {len(live_ips)}, "
          f"decoys {out['meta']['live_decoy_count']}, cves {out['meta']['live_cve_count']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
