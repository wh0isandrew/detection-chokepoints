#!/usr/bin/env python3
"""
ingest_clickgrab.py
Fetch the last 7 nightly ClickGrab reports from the public GitHub repo and
write a deduplicated list of per-URL records to cache/clickgrab_raw.json.

Actual filename format in MHaggis/ClickGrab:
  nightly_reports/clickgrab_report_YYYYMMDD_HHMMSS.json

Files are stored in Git LFS. Download flow:
  1. List nightly_reports/ via GitHub Contents API to find files in the
     last LOOKBACK_DAYS by parsing the YYYYMMDD prefix from each filename.
  2. Read the LFS pointer (oid, size) from the file's raw content.
  3. Resolve the real download URL via the GitHub LFS Batch API.
  4. Download and parse the JSON report.

All files within the lookback window are processed concurrently.

Requires: GITHUB_TOKEN env var (optional but avoids rate limits and gives
LFS access priority). Without it the script uses unauthenticated GitHub API
calls (60 req/hr limit) and may hit the repo's LFS bandwidth budget limit.

Output: cache/clickgrab_raw.json
"""

import asyncio
import base64
import json
import os
import re
import sys
import time
from datetime import date, timedelta
from pathlib import Path
from urllib.parse import urlparse

import httpx
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

REPO_ROOT   = Path(__file__).parent.parent
CACHE_DIR   = REPO_ROOT / "cache"
OUTPUT_PATH = CACHE_DIR / "clickgrab_raw.json"

CLICKGRAB_OWNER  = "MHaggis"
CLICKGRAB_REPO   = "ClickGrab"
CLICKGRAB_BRANCH = "main"
REPORTS_DIR      = "nightly_reports"

LOOKBACK_DAYS   = int(os.getenv("CLICKGRAB_LOOKBACK_DAYS", "7"))
REQUEST_TIMEOUT = float(os.getenv("CLICKGRAB_REQUEST_TIMEOUT", "30"))

GITHUB_API  = "https://api.github.com"
LFS_BATCH_URL = (
    f"https://github.com/{CLICKGRAB_OWNER}/{CLICKGRAB_REPO}.git/info/lfs/objects/batch"
)

# ---------------------------------------------------------------------------
# GitHub API helpers
# ---------------------------------------------------------------------------

def _github_headers(token: str | None = None) -> dict:
    headers = {
        "User-Agent": "detection-chokepoints/enrichment-pipeline",
        "Accept": "application/vnd.github+json",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


async def _list_report_files(client: httpx.AsyncClient, token: str | None) -> list:
    """Return list of {name, sha, size} dicts for files in nightly_reports/."""
    url = (
        f"{GITHUB_API}/repos/{CLICKGRAB_OWNER}/{CLICKGRAB_REPO}"
        f"/contents/{REPORTS_DIR}?ref={CLICKGRAB_BRANCH}"
    )
    try:
        resp = await client.get(url, headers=_github_headers(token), timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        print(f"ERROR listing {REPORTS_DIR}: {exc}", file=sys.stderr)
        return []

    entries = resp.json()
    if not isinstance(entries, list):
        print(f"ERROR: unexpected response listing {REPORTS_DIR}", file=sys.stderr)
        return []

    return [
        {"name": e.get("name", ""), "sha": e.get("sha", ""), "size": e.get("size", 0)}
        for e in entries
        if e.get("name", "").endswith(".json")
        and e.get("name") != "latest_consolidated_report.json"
    ]


def _parse_date_from_filename(filename: str):
    m = re.search(r"_(\d{8})_", filename)
    if m:
        raw = m.group(1)
        try:
            return date(int(raw[:4]), int(raw[4:6]), int(raw[6:8]))
        except ValueError:
            pass
    return None


async def _fetch_lfs_pointer(
    client: httpx.AsyncClient, filename: str, token: str | None
) -> tuple:
    """Fetch LFS pointer file and return (oid, size) or (None, None)."""
    url = (
        f"https://raw.githubusercontent.com/{CLICKGRAB_OWNER}"
        f"/{CLICKGRAB_REPO}/{CLICKGRAB_BRANCH}/{REPORTS_DIR}/{filename}"
    )
    try:
        resp = await client.get(url, headers=_github_headers(token), timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        content = resp.text
    except httpx.HTTPError as exc:
        print(f"    Could not fetch LFS pointer for {filename}: {exc}", file=sys.stderr)
        return None, None

    oid_m  = re.search(r"oid sha256:([0-9a-f]{64})", content)
    size_m = re.search(r"size (\d+)", content)
    if oid_m and size_m:
        return oid_m.group(1), int(size_m.group(1))
    print(f"    {filename}: not a valid LFS pointer", file=sys.stderr)
    return None, None


async def _resolve_lfs_download_url(
    oid: str, size: int, client: httpx.AsyncClient, token: str | None
) -> str | None:
    """Use LFS Batch API to get the real download URL for an LFS object."""
    headers = {
        "Content-Type": "application/vnd.git-lfs+json",
        "Accept":       "application/vnd.git-lfs+json",
    }
    if token:
        cred = base64.b64encode(f"token:{token}".encode()).decode()
        headers["Authorization"] = f"Basic {cred}"

    payload = {
        "operation": "download",
        "transfers": ["basic"],
        "objects":   [{"oid": oid, "size": size}],
    }
    try:
        resp = await client.post(
            LFS_BATCH_URL, json=payload, headers=headers, timeout=REQUEST_TIMEOUT
        )
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        print(f"    LFS batch API error: {exc}", file=sys.stderr)
        return None

    data    = resp.json()
    objects = data.get("objects", [])
    if not objects:
        print(f"    LFS batch API returned no objects: {data.get('message', 'unknown')}", file=sys.stderr)
        return None

    obj   = objects[0]
    error = obj.get("error")
    if error:
        print(f"    LFS object error: {error.get('message', error)}", file=sys.stderr)
        return None

    return obj.get("actions", {}).get("download", {}).get("href")


async def _download_lfs_file(download_url: str, client: httpx.AsyncClient):
    """Download the actual JSON content from an LFS download URL."""
    try:
        # LFS download URLs are pre-signed — send without custom auth headers
        resp = await client.get(download_url, headers={}, timeout=60)
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPError as exc:
        print(f"    LFS download failed: {exc}", file=sys.stderr)
        return None
    except ValueError as exc:
        print(f"    LFS content JSON parse error: {exc}", file=sys.stderr)
        return None


# ---------------------------------------------------------------------------
# Report parsing
# ---------------------------------------------------------------------------

def _extract_url(record: dict) -> str:
    return (
        record.get("Url") or record.get("URL") or record.get("url")
        or record.get("SourceUrl") or record.get("source_url") or ""
    )


def _extract_tags(record: dict) -> list:
    tags = record.get("Tags") or record.get("tags") or []
    if isinstance(tags, str):
        tags = [tags]
    for field in ("Verdict", "verdict", "DetectionType", "detection_type"):
        val = record.get(field)
        if isinstance(val, str) and val:
            tags = list(tags) + [val]
    return [str(t).strip() for t in tags if t]


def _extract_redirect_chain(record: dict) -> list:
    chain = (
        record.get("RedirectChain") or record.get("redirect_chain")
        or record.get("Redirects") or []
    )
    if isinstance(chain, str):
        chain = [chain]
    return [str(u).strip() for u in chain if u]


def _extract_downloaded_files(record: dict) -> list:
    files = []
    for dl in (record.get("PowerShellDownloads") or []):
        if not isinstance(dl, dict):
            continue
        fname = dl.get("FileName") or dl.get("file_name") or dl.get("SavedAs") or ""
        if not fname:
            url = dl.get("URL") or dl.get("url") or ""
            try:
                fname = Path(urlparse(url).path).name
            except Exception:
                pass
        if fname:
            files.append(str(fname).strip())
    direct = record.get("DownloadedFiles") or record.get("downloaded_files") or []
    if isinstance(direct, str):
        direct = [direct]
    files.extend(str(f).strip() for f in direct if f)
    return list(dict.fromkeys(files))


def _extract_script_snippets(record: dict, max_len: int = 350) -> list:
    parts = []
    for field in ("PowerShellCommands", "HighRiskCommands", "ClipboardCommands"):
        val = record.get(field)
        if isinstance(val, str) and val:
            parts.append(val[:max_len])
        elif isinstance(val, list):
            for item in val:
                if item:
                    parts.append(str(item)[:max_len])
    return parts[:5]


def _extract_risk_score(record: dict) -> int:
    score = (
        record.get("ThreatScore") or record.get("threat_score")
        or record.get("RiskScore") or 0
    )
    try:
        return int(float(score))
    except (TypeError, ValueError):
        return 0


def _parse_site_record(record: dict, report_date: str):
    url = _extract_url(record)
    if not url:
        return None
    return {
        "url":              url,
        "date":             report_date,
        "tags":             _extract_tags(record),
        "redirect_chain":   _extract_redirect_chain(record),
        "downloaded_files": _extract_downloaded_files(record),
        "script_snippets":  _extract_script_snippets(record),
        "risk_score":       _extract_risk_score(record),
    }


def _parse_report(data, report_date: str) -> list:
    """Extract site records from a raw report (handles list or dict top-level)."""
    records: list = []

    def _collect_sites(site_list, rdate):
        for site in site_list:
            if not isinstance(site, dict):
                continue
            r = _parse_site_record(site, rdate)
            if r:
                records.append(r)

    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            site_list = item.get("Sites") or item.get("sites") or []
            if site_list:
                rdate = (
                    (item.get("ReportTime") or item.get("report_date") or report_date or "")[:10]
                    or report_date
                )
                _collect_sites(site_list, rdate)
            elif _extract_url(item):
                r = _parse_site_record(item, report_date)
                if r:
                    records.append(r)
    elif isinstance(data, dict):
        site_list = data.get("Sites") or data.get("sites") or []
        rdate = (
            (data.get("ReportTime") or data.get("report_date") or report_date or "")[:10]
            or report_date
        )
        _collect_sites(site_list, rdate)

    return records


# ---------------------------------------------------------------------------
# Run log
# ---------------------------------------------------------------------------

def _write_run_log(cache_dir: Path, section: str, data: dict) -> None:
    import datetime as _dt
    path = cache_dir / "pipeline_run.json"
    log: dict = {}
    if path.exists():
        try:
            log = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            pass
    log.setdefault("run_date", _dt.date.today().isoformat())
    log[section] = {"timestamp": _dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"), **data}
    path.write_text(json.dumps(log, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main():
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    today   = date.today()
    cutoff  = today - timedelta(days=LOOKBACK_DAYS)
    token   = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")

    print(f"Fetching ClickGrab reports from {cutoff} → {today}")
    print(f"Listing {REPORTS_DIR}/ via GitHub API…")
    if token:
        print("  Using GITHUB_TOKEN for authenticated API access")
    else:
        print("  No GITHUB_TOKEN — using unauthenticated (60 req/hr limit)")

    async with httpx.AsyncClient() as client:
        all_files = await _list_report_files(client, token)
        print(f"  Found {len(all_files)} JSON files in {REPORTS_DIR}/")

        recent_files = [
            (f["name"], d)
            for f in all_files
            if (d := _parse_date_from_filename(f["name"])) and d >= cutoff
        ]
        recent_files.sort(key=lambda x: x[1], reverse=True)
        print(f"  {len(recent_files)} files in last {LOOKBACK_DAYS} days")

        async def _process_file(filename: str, file_date: date) -> tuple:
            """Fetch pointer → resolve URL → download → parse. Returns (records, skipped)."""
            date_str = file_date.isoformat()
            print(f"\n  {filename}")

            oid, size = await _fetch_lfs_pointer(client, filename, token)
            if not oid:
                print("    Skipping — could not read LFS pointer")
                return [], 1

            download_url = await _resolve_lfs_download_url(oid, size, client, token)
            if not download_url:
                print("    Skipping — LFS download URL unavailable (budget exceeded?)")
                return [], 1

            data = await _download_lfs_file(download_url, client)
            if data is None:
                print("    Skipping — download failed")
                return [], 1

            records = _parse_report(data, date_str)
            print(f"    {len(records)} URL records extracted")
            return records, 0

        results = await asyncio.gather(*[_process_file(n, d) for n, d in recent_files])

    all_records: list = []
    lfs_skipped = 0
    seen: set = set()

    for records, skipped in results:
        lfs_skipped += skipped
        for r in records:
            key = (r["url"], r["date"])
            if key not in seen:
                seen.add(key)
                all_records.append(r)

    print(f"\nTotal unique URL records: {len(all_records)}")

    OUTPUT_PATH.write_text(
        json.dumps(all_records, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"Written: {OUTPUT_PATH}")

    if not all_records:
        print(
            "\nNOTE: Zero records written. This is normal if:\n"
            "  - No ClickGrab reports were published in the last 7 days\n"
            "  - The repo's Git LFS bandwidth budget is exhausted (resets monthly)\n"
            "  - GITHUB_TOKEN is missing and the unauthenticated rate limit was hit\n"
            "Subsequent pipeline steps will run with empty input.",
            file=sys.stderr,
        )

    _write_run_log(CACHE_DIR, "ingest_clickgrab", {
        "files_found":     len(all_files),
        "files_in_window": len(recent_files),
        "lfs_skipped":     lfs_skipped,
        "records_ingested": len(all_records),
        "status": "ok" if all_records else "empty",
    })


if __name__ == "__main__":
    asyncio.run(main())
