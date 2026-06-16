#!/usr/bin/env python3
"""
ingest_clickgrab.py
Fetch MHaggis ClickGrab nightly reports as plain git blobs and cache them
per-day for the trends generator (analyze_clickgrab.py).

WHY raw blobs instead of Git LFS (see docs/DECISIONS.md #010):
  MHaggis exhausted the repo's Git-LFS storage/bandwidth quota and migrated
  new files to regular git blobs (confirmed in upstream .gitattributes). The
  old LFS flow (pointer -> LFS batch API -> presigned URL) now returns no
  href once the budget is gone, so the previous ingest silently wrote zero
  records. Regular blobs are one plain GET from raw.githubusercontent.com:
  no token, no batch API, no bandwidth gate.

WHY synchronous requests instead of async httpx:
  We fetch one small file per calendar day (<=~90 sequential GETs for a full
  backfill, one per normal daily run). The async/concurrency machinery only
  added complexity around the LFS hop that no longer exists. A straight loop
  is easier to read and reason about, and the run is I/O-trivial.

Source files (raw.githubusercontent.com/MHaggis/ClickGrab/main/):
  nightly_reports/clickgrab_report_YYYY-MM-DD.json   (per-day, ~100 sites)
  latest_consolidated_report.json                    (alias for the latest day)

Output (gitignored cache — raw payloads never get committed; see memory-hygiene
rule and DECISIONS #001/#011):
  cache/clickgrab/days/<YYYY-MM-DD>.json   one file per day, list of site dicts
  cache/clickgrab/ingest_log.json          run summary

Usage:
  python scripts/ingest_clickgrab.py                       # last LOOKBACK_DAYS
  python scripts/ingest_clickgrab.py 2026-05-20 2026-06-15 # explicit backfill range
  python scripts/ingest_clickgrab.py --since 2026-05-20    # since date -> today

Env:
  CLICKGRAB_LOOKBACK_DAYS   default 21 (overlap is fine; merge is by-date idempotent)
  CLICKGRAB_REQUEST_TIMEOUT default 60
"""

import json
import os
import re
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import requests

ISO_RE = re.compile(r"\d{4}-\d{2}-\d{2}")

# ---------------------------------------------------------------------------
# Paths / config
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).parent.parent
CACHE_DIR = REPO_ROOT / "cache" / "clickgrab"
DAYS_DIR  = CACHE_DIR / "days"
LOG_PATH  = CACHE_DIR / "ingest_log.json"

RAW_BASE = "https://raw.githubusercontent.com/MHaggis/ClickGrab/main"
NIGHTLY_URL_TMPL  = RAW_BASE + "/nightly_reports/clickgrab_report_{date}.json"
CONSOLIDATED_URL  = RAW_BASE + "/latest_consolidated_report.json"

LOOKBACK_DAYS   = int(os.getenv("CLICKGRAB_LOOKBACK_DAYS", "21"))
REQUEST_TIMEOUT = float(os.getenv("CLICKGRAB_REQUEST_TIMEOUT", "60"))

HEADERS = {"User-Agent": "detection-chokepoints/clickgrab-ingest"}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _looks_like_lfs_pointer(text: str) -> bool:
    """Old (pre-migration) reports resolve to a ~130-byte LFS pointer stub on raw,
    not JSON. A real pointer's FIRST line is exactly the git-lfs spec URL and the
    whole blob is tiny. Gate on BOTH so a real report whose payload merely contains
    'oid sha256:' (attacker-controlled ClickFix text can) isn't misclassified and
    silently dropped as 'budget-locked'."""
    return text.lstrip().startswith("version https://git-lfs") and len(text) < 400


def _report_date(data) -> str:
    """The report's own date (YYYY-MM-DD) from report_date/timestamp, or ''. Used to
    confirm the consolidated alias has actually rolled to the requested day."""
    if not isinstance(data, dict):
        return ""
    for f in ("report_date", "ReportDate", "date"):
        v = data.get(f)
        if isinstance(v, str) and ISO_RE.match(v):
            return v[:10]
    ts = data.get("timestamp") or data.get("Timestamp") or ""
    return ts[:10] if isinstance(ts, str) and ISO_RE.match(ts) else ""


def _extract_sites(data) -> list:
    """A nightly/consolidated report is a dict with a 'sites' list. Be tolerant
    of the older capitalised 'Sites' and of a bare top-level list."""
    if isinstance(data, dict):
        return data.get("sites") or data.get("Sites") or []
    if isinstance(data, list):
        return data
    return []


def _normalise_day_records(sites: list, day: str) -> list:
    """Stamp each site with the report date under 'Timestamp' so the generator
    has a reliable per-record date regardless of the upstream field name.
    Records are stored verbatim otherwise (the generator reads PowerShellCommands,
    PowerShellDownloads, ThreatScore, Verdict, etc. directly)."""
    out = []
    for s in sites:
        if not isinstance(s, dict):
            continue
        s = dict(s)
        s.setdefault("Timestamp", day)
        out.append(s)
    return out


def _fetch_json(url: str) -> tuple:
    """GET a raw blob. Returns (status, data_or_None, note).
    note distinguishes the skip reasons so the run log is diagnosable."""
    try:
        resp = requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        return ("error", None, f"request failed: {exc}")

    if resp.status_code == 404:
        return ("missing", None, "404 (no report this day)")
    if resp.status_code != 200:
        return ("error", None, f"HTTP {resp.status_code}")

    text = resp.text
    if _looks_like_lfs_pointer(text):
        return ("lfs_locked", None, "LFS pointer (pre-migration, budget-locked)")

    try:
        return ("ok", json.loads(text), "")
    except ValueError as exc:
        return ("error", None, f"JSON parse error: {exc}")


# ---------------------------------------------------------------------------
# Date range resolution
# ---------------------------------------------------------------------------

def _parse_date(s: str) -> date:
    return datetime.strptime(s, "%Y-%m-%d").date()


def _resolve_range(argv: list) -> tuple:
    """Resolve the [start, end] inclusive date range to fetch.
      (no args)                 -> last LOOKBACK_DAYS ending today
      --since YYYY-MM-DD        -> that date through today
      YYYY-MM-DD YYYY-MM-DD     -> explicit inclusive range
    """
    today = datetime.now(timezone.utc).date()
    if not argv:
        return today - timedelta(days=LOOKBACK_DAYS - 1), today
    if argv[0] == "--since" and len(argv) >= 2:
        return _parse_date(argv[1]), today
    if len(argv) >= 2:
        return _parse_date(argv[0]), _parse_date(argv[1])
    # single date -> just that day
    d = _parse_date(argv[0])
    return d, d


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    DAYS_DIR.mkdir(parents=True, exist_ok=True)

    start, end = _resolve_range(sys.argv[1:])
    today = datetime.now(timezone.utc).date()
    print(f"Fetching ClickGrab nightly blobs {start} -> {end}")

    stats = {"days_requested": 0, "days_written": 0, "sites_total": 0,
             "missing": 0, "lfs_locked": 0, "empty": 0, "errors": 0}
    day_status = {}   # per-day outcome, so a broken 'today' isn't masked by good cached days

    d = start
    while d <= end:
        stats["days_requested"] += 1
        day = d.isoformat()
        url = NIGHTLY_URL_TMPL.format(date=day)
        status, data, note = _fetch_json(url)

        # The latest day's nightly file is occasionally published a few minutes
        # after the consolidated alias; fall back to the consolidated report for
        # "today" — but ONLY if the alias has actually rolled to today. During the
        # publish window it may still hold YESTERDAY's content; writing that under
        # today's filename would mislabel and double-count it (its real day was
        # already ingested). Verify the report's own date before accepting.
        if status != "ok" and d == today:
            status2, data2, _ = _fetch_json(CONSOLIDATED_URL)
            if status2 == "ok" and _report_date(data2) == day:
                status, data, note = "ok", data2, "via consolidated alias"
            elif status2 == "ok":
                note = f"consolidated alias is {_report_date(data2) or 'undated'}, not today — skipped"

        if status != "ok":
            bucket = status if status in ("missing", "lfs_locked") else "errors"
            stats[bucket] += 1
            day_status[day] = note or bucket
            print(f"  {day}: skip — {note}")
            d += timedelta(days=1)
            continue

        # A 200 that parses but is the wrong shape (dict lacking sites/Sites) is an
        # upstream schema break, not a quiet day — flag it as an error, not empty.
        if isinstance(data, dict) and not (data.get("sites") or data.get("Sites")):
            stats["errors"] += 1
            day_status[day] = "200 but no sites/Sites key (schema break?)"
            print(f"  {day}: skip — 200 but no sites/Sites key (schema break?)", file=sys.stderr)
            d += timedelta(days=1)
            continue

        records = _normalise_day_records(_extract_sites(data), day)
        if not records:
            # A real nightly report is ~100 sites; 0 sites on a NON-today day is
            # almost certainly an upstream break, so surface it on stderr.
            stats["empty"] += 1
            day_status[day] = "0 sites"
            historical = d != today
            print(f"  {day}: 0 sites — not written"
                  + ("  [WARN: unexpected for a historical day]" if historical else ""),
                  file=sys.stderr if historical else sys.stdout)
            d += timedelta(days=1)
            continue

        (DAYS_DIR / f"{day}.json").write_text(
            json.dumps(records, ensure_ascii=False), encoding="utf-8"
        )
        stats["days_written"] += 1
        stats["sites_total"] += len(records)
        day_status[day] = f"ok ({len(records)} sites)" + (f" {note}" if note else "")
        print(f"  {day}: {len(records)} sites{(' (' + note + ')') if note else ''}")
        d += timedelta(days=1)

    LOG_PATH.write_text(json.dumps({
        "run_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "range": {"start": start.isoformat(), "end": end.isoformat()},
        **stats,
        "per_day": day_status,
    }, indent=2), encoding="utf-8")

    print(f"\nDays written: {stats['days_written']}  "
          f"sites: {stats['sites_total']}  "
          f"missing: {stats['missing']}  lfs_locked: {stats['lfs_locked']}  "
          f"errors: {stats['errors']}")
    print(f"Cache: {DAYS_DIR}")

    if stats["days_written"] == 0:
        print("\nWARNING: no days written. If this persists, verify the upstream "
              "filename format and that recent reports are non-LFS blobs.",
              file=sys.stderr)


if __name__ == "__main__":
    main()
