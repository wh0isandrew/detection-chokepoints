#!/usr/bin/env python3
"""
ingest_clickgrab.py
Fetch the last 7 nightly ClickGrab reports from the public GitHub repo and
write a deduplicated list of per-URL records to cache/clickgrab_raw.json.

Source URL pattern:
  https://raw.githubusercontent.com/MHaggis/ClickGrab/main/nightly_reports/clickgrab_report_YYYY-MM-DD.json

Output: cache/clickgrab_raw.json
"""

import json
import os
import sys
import time
from datetime import date, timedelta
from urllib.parse import urlparse

import requests

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE_DIR = os.path.join(REPO_ROOT, "cache")
OUTPUT_PATH = os.path.join(CACHE_DIR, "clickgrab_raw.json")

BASE_URL = (
    "https://raw.githubusercontent.com/MHaggis/ClickGrab/main"
    "/nightly_reports/clickgrab_report_{date}.json"
)

LOOKBACK_DAYS = 7
REQUEST_TIMEOUT = 15


# ---------------------------------------------------------------------------
# Report parsing — mirrors analyze_clickgrab.py schema handling
# ---------------------------------------------------------------------------

def _extract_url(record):
    """Return the primary URL from a site record (handles multiple field names)."""
    return (
        record.get("Url")
        or record.get("URL")
        or record.get("url")
        or record.get("SourceUrl")
        or record.get("source_url")
        or ""
    )


def _extract_tags(record):
    """Return list of string tags from a site record."""
    tags = record.get("Tags") or record.get("tags") or []
    if isinstance(tags, str):
        tags = [tags]
    verdict = record.get("Verdict") or record.get("verdict") or ""
    if isinstance(verdict, str) and verdict:
        tags = list(tags) + [verdict]
    # Detection types like FakeCaptcha, ClickFix often appear here
    detection = record.get("DetectionType") or record.get("detection_type") or ""
    if isinstance(detection, str) and detection:
        tags = list(tags) + [detection]
    return [str(t).strip() for t in tags if t]


def _extract_redirect_chain(record):
    """Return list of redirect URLs, if present."""
    chain = (
        record.get("RedirectChain")
        or record.get("redirect_chain")
        or record.get("Redirects")
        or []
    )
    if isinstance(chain, str):
        chain = [chain]
    return [str(u).strip() for u in chain if u]


def _extract_downloaded_files(record):
    """Return list of downloaded file paths/names from PowerShellDownloads."""
    files = []
    downloads = record.get("PowerShellDownloads") or []
    if isinstance(downloads, dict):
        downloads = [downloads]
    for dl in downloads:
        if not isinstance(dl, dict):
            continue
        # File path stored as FileName, SavedAs, or derivable from URL
        fname = dl.get("FileName") or dl.get("file_name") or dl.get("SavedAs") or ""
        if not fname:
            # Fall back to the path component of the download URL
            url = dl.get("URL") or dl.get("url") or ""
            try:
                path = urlparse(url).path
                fname = os.path.basename(path)
            except Exception:
                pass
        if fname:
            files.append(str(fname).strip())
    # Also check direct DownloadedFiles field
    direct = record.get("DownloadedFiles") or record.get("downloaded_files") or []
    if isinstance(direct, str):
        direct = [direct]
    files.extend(str(f).strip() for f in direct if f)
    return list(dict.fromkeys(files))  # deduplicate, preserve order


def _extract_script_snippets(record, max_len=350):
    """Return truncated inline script content."""
    parts = []
    for field in ("PowerShellCommands", "HighRiskCommands", "ClipboardCommands"):
        val = record.get(field)
        if isinstance(val, str) and val:
            parts.append(val[:max_len])
        elif isinstance(val, list):
            for item in val:
                if item:
                    parts.append(str(item)[:max_len])
    return parts[:5]  # cap at 5 snippets per record


def _extract_risk_score(record):
    """Return numeric risk score (0 if absent)."""
    score = record.get("ThreatScore") or record.get("threat_score") or record.get("RiskScore") or 0
    try:
        return int(float(score))
    except (TypeError, ValueError):
        return 0


def _parse_site_record(record, report_date):
    """Convert a raw site record dict into a normalised enrichment-pipeline record."""
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
    """Extract site records from a raw report dict/list."""
    records = []

    def _collect_sites(site_list, fallback_date):
        for site in site_list:
            if not isinstance(site, dict):
                continue
            r = _parse_site_record(site, fallback_date)
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
                # Flat list of site records
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
# Fetching
# ---------------------------------------------------------------------------

def fetch_report(report_date_str, session):
    """Fetch one nightly report. Returns parsed list of site records or None on failure."""
    url = BASE_URL.format(date=report_date_str)
    try:
        resp = session.get(url, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 404:
            print(f"  {report_date_str}: no report (404), skipping")
            return None
        resp.raise_for_status()
    except requests.RequestException as exc:
        print(f"  {report_date_str}: fetch error — {exc}", file=sys.stderr)
        return None

    try:
        data = resp.json()
    except ValueError as exc:
        print(f"  {report_date_str}: JSON parse error — {exc}", file=sys.stderr)
        return None

    records = _parse_report(data, report_date_str)
    print(f"  {report_date_str}: {len(records)} URLs extracted")
    return records


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    os.makedirs(CACHE_DIR, exist_ok=True)

    today = date.today()
    date_range = [
        (today - timedelta(days=i)).isoformat()
        for i in range(1, LOOKBACK_DAYS + 1)
    ]

    print(f"Fetching ClickGrab reports for {date_range[0]} → {date_range[-1]}")

    all_records = []
    seen = set()  # dedup key: (url, date)

    with requests.Session() as session:
        session.headers["User-Agent"] = "detection-chokepoints/enrichment-pipeline"
        for report_date_str in date_range:
            records = fetch_report(report_date_str, session)
            if records:
                for r in records:
                    key = (r["url"], r["date"])
                    if key not in seen:
                        seen.add(key)
                        all_records.append(r)
            time.sleep(0.3)  # be polite to GitHub raw CDN

    print(f"\nTotal unique URL records: {len(all_records)}")

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(all_records, f, indent=2, ensure_ascii=False)

    print(f"Written: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
