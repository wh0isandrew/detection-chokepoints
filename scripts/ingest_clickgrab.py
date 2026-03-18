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

Requires: GITHUB_TOKEN env var (optional but avoids rate limits and gives
LFS access priority). Without it the script uses unauthenticated GitHub API
calls (60 req/hr limit) and may hit the repo's LFS bandwidth budget limit.

Output: cache/clickgrab_raw.json
"""

import base64
import json
import os
import re
import sys
import time
from datetime import date, timedelta
from urllib.parse import urlparse

import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE_DIR = os.path.join(REPO_ROOT, "cache")
OUTPUT_PATH = os.path.join(CACHE_DIR, "clickgrab_raw.json")

CLICKGRAB_OWNER = "MHaggis"
CLICKGRAB_REPO = "ClickGrab"
CLICKGRAB_BRANCH = "main"
REPORTS_DIR = "nightly_reports"

LOOKBACK_DAYS = 7
REQUEST_TIMEOUT = 30

GITHUB_API = "https://api.github.com"
LFS_API = f"https://github.com/{CLICKGRAB_OWNER}/{CLICKGRAB_REPO}.git/info/lfs/objects/batch"


# ---------------------------------------------------------------------------
# GitHub API helper
# ---------------------------------------------------------------------------

def _github_session():
    s = requests.Session()
    s.headers["User-Agent"] = "detection-chokepoints/enrichment-pipeline"
    s.headers["Accept"] = "application/vnd.github+json"
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        s.headers["Authorization"] = f"Bearer {token}"
        print("  Using GITHUB_TOKEN for authenticated API access")
    else:
        print("  No GITHUB_TOKEN — using unauthenticated (60 req/hr limit)")
    return s


def _list_report_files(session):
    """Return list of (filename, lfs_oid, lfs_size) for files in nightly_reports/."""
    url = (
        f"{GITHUB_API}/repos/{CLICKGRAB_OWNER}/{CLICKGRAB_REPO}"
        f"/contents/{REPORTS_DIR}?ref={CLICKGRAB_BRANCH}"
    )
    try:
        resp = session.get(url, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
    except requests.RequestException as exc:
        print(f"ERROR listing {REPORTS_DIR}: {exc}", file=sys.stderr)
        return []

    entries = resp.json()
    if not isinstance(entries, list):
        print(f"ERROR: unexpected response listing {REPORTS_DIR}", file=sys.stderr)
        return []

    files = []
    for entry in entries:
        name = entry.get("name", "")
        if not name.endswith(".json"):
            continue
        if name == "latest_consolidated_report.json":
            continue
        # LFS pointer files have a tiny size (≈130 bytes) — get oid from sha or fetch pointer
        files.append({
            "name": name,
            "sha": entry.get("sha", ""),
            "size": entry.get("size", 0),
        })
    return files


def _parse_date_from_filename(filename):
    """Extract date from clickgrab_report_YYYYMMDD_HHMMSS.json."""
    m = re.search(r"_(\d{8})_", filename)
    if m:
        raw = m.group(1)
        try:
            return date(int(raw[:4]), int(raw[4:6]), int(raw[6:8]))
        except ValueError:
            pass
    return None


def _fetch_lfs_pointer(session, filename):
    """Fetch the LFS pointer file content to extract oid and size."""
    url = (
        f"https://raw.githubusercontent.com/{CLICKGRAB_OWNER}"
        f"/{CLICKGRAB_REPO}/{CLICKGRAB_BRANCH}/{REPORTS_DIR}/{filename}"
    )
    try:
        resp = session.get(url, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        content = resp.text
    except requests.RequestException as exc:
        print(f"    Could not fetch LFS pointer for {filename}: {exc}", file=sys.stderr)
        return None, None

    oid_m = re.search(r"oid sha256:([0-9a-f]{64})", content)
    size_m = re.search(r"size (\d+)", content)
    if oid_m and size_m:
        return oid_m.group(1), int(size_m.group(1))
    print(f"    {filename}: not a valid LFS pointer", file=sys.stderr)
    return None, None


def _resolve_lfs_download_url(oid, size, session):
    """Use LFS Batch API to get the real download URL for an LFS object."""
    headers = {
        "Content-Type": "application/vnd.git-lfs+json",
        "Accept": "application/vnd.git-lfs+json",
    }
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        import base64 as _b64
        cred = _b64.b64encode(f"token:{token}".encode()).decode()
        headers["Authorization"] = f"Basic {cred}"

    payload = {
        "operation": "download",
        "transfers": ["basic"],
        "objects": [{"oid": oid, "size": size}],
    }
    try:
        resp = requests.post(
            LFS_API, json=payload, headers=headers, timeout=REQUEST_TIMEOUT
        )
        resp.raise_for_status()
    except requests.RequestException as exc:
        print(f"    LFS batch API error: {exc}", file=sys.stderr)
        return None

    data = resp.json()
    objects = data.get("objects", [])
    if not objects:
        msg = data.get("message", "unknown error")
        print(f"    LFS batch API returned no objects: {msg}", file=sys.stderr)
        return None

    obj = objects[0]
    error = obj.get("error")
    if error:
        print(f"    LFS object error: {error.get('message', error)}", file=sys.stderr)
        return None

    return obj.get("actions", {}).get("download", {}).get("href")


def _download_lfs_file(download_url, session):
    """Download the actual JSON content from an LFS download URL."""
    try:
        # LFS download URLs are pre-signed and may not accept our custom headers
        resp = requests.get(download_url, timeout=60)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as exc:
        print(f"    LFS download failed: {exc}", file=sys.stderr)
        return None
    except ValueError as exc:
        print(f"    LFS content JSON parse error: {exc}", file=sys.stderr)
        return None


# ---------------------------------------------------------------------------
# Report parsing — schema handles both old and new ClickGrab formats
# ---------------------------------------------------------------------------

def _extract_url(record):
    return (
        record.get("Url") or record.get("URL") or record.get("url")
        or record.get("SourceUrl") or record.get("source_url") or ""
    )


def _extract_tags(record):
    tags = record.get("Tags") or record.get("tags") or []
    if isinstance(tags, str):
        tags = [tags]
    for field in ("Verdict", "verdict", "DetectionType", "detection_type"):
        val = record.get(field)
        if isinstance(val, str) and val:
            tags = list(tags) + [val]
    return [str(t).strip() for t in tags if t]


def _extract_redirect_chain(record):
    chain = (
        record.get("RedirectChain") or record.get("redirect_chain")
        or record.get("Redirects") or []
    )
    if isinstance(chain, str):
        chain = [chain]
    return [str(u).strip() for u in chain if u]


def _extract_downloaded_files(record):
    files = []
    for dl in (record.get("PowerShellDownloads") or []):
        if not isinstance(dl, dict):
            continue
        fname = dl.get("FileName") or dl.get("file_name") or dl.get("SavedAs") or ""
        if not fname:
            url = dl.get("URL") or dl.get("url") or ""
            try:
                fname = os.path.basename(urlparse(url).path)
            except Exception:
                pass
        if fname:
            files.append(str(fname).strip())
    direct = record.get("DownloadedFiles") or record.get("downloaded_files") or []
    if isinstance(direct, str):
        direct = [direct]
    files.extend(str(f).strip() for f in direct if f)
    return list(dict.fromkeys(files))


def _extract_script_snippets(record, max_len=350):
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


def _extract_risk_score(record):
    score = (
        record.get("ThreatScore") or record.get("threat_score")
        or record.get("RiskScore") or 0
    )
    try:
        return int(float(score))
    except (TypeError, ValueError):
        return 0


def _parse_site_record(record, report_date):
    url = _extract_url(record)
    if not url:
        return None
    return {
        "url": url,
        "date": report_date,
        "tags": _extract_tags(record),
        "redirect_chain": _extract_redirect_chain(record),
        "downloaded_files": _extract_downloaded_files(record),
        "script_snippets": _extract_script_snippets(record),
        "risk_score": _extract_risk_score(record),
    }


def _parse_report(data, report_date):
    """Extract site records from a raw report (handles list or dict top-level)."""
    records = []

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
# Main
# ---------------------------------------------------------------------------

def main():
    os.makedirs(CACHE_DIR, exist_ok=True)

    today = date.today()
    cutoff = today - timedelta(days=LOOKBACK_DAYS)

    print(f"Fetching ClickGrab reports from {cutoff} → {today}")
    print(f"Listing {REPORTS_DIR}/ via GitHub API…")

    session = _github_session()
    all_files = _list_report_files(session)
    print(f"  Found {len(all_files)} JSON files in {REPORTS_DIR}/")

    # Filter to files within our lookback window
    recent_files = []
    for f in all_files:
        d = _parse_date_from_filename(f["name"])
        if d and d >= cutoff:
            recent_files.append((f["name"], d))

    recent_files.sort(key=lambda x: x[1], reverse=True)
    print(f"  {len(recent_files)} files in last {LOOKBACK_DAYS} days")

    all_records = []
    seen = set()

    for filename, file_date in recent_files:
        date_str = file_date.isoformat()
        print(f"\n  {filename}")

        # Step 1: Get LFS pointer
        oid, size = _fetch_lfs_pointer(session, filename)
        if not oid:
            print(f"    Skipping — could not read LFS pointer")
            continue

        # Step 2: Resolve download URL via LFS Batch API
        download_url = _resolve_lfs_download_url(oid, size, session)
        if not download_url:
            print(f"    Skipping — LFS download URL unavailable (budget exceeded?)")
            continue

        # Step 3: Download and parse
        data = _download_lfs_file(download_url, session)
        if data is None:
            print(f"    Skipping — download failed")
            continue

        records = _parse_report(data, date_str)
        print(f"    {len(records)} URL records extracted")

        for r in records:
            key = (r["url"], r["date"])
            if key not in seen:
                seen.add(key)
                all_records.append(r)

        time.sleep(0.3)  # polite pause

    print(f"\nTotal unique URL records: {len(all_records)}")

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(all_records, f, indent=2, ensure_ascii=False)

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


if __name__ == "__main__":
    main()
