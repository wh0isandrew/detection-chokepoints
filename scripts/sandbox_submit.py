#!/usr/bin/env python3
"""
sandbox_submit.py
Submit staging URLs from the ClickGrab pipeline to Hybrid Analysis (Falcon
Sandbox) for behavioral analysis. Only submits URLs that pass the
pre-submission filter:

  1. VT flags the domain as malicious (vt_malicious > 0)
  2. The downloaded file has an actionable extension (.ps1, .hta, .js, .bat,
     .exe, .msi)
  3. The URL is not a CDN root without a specific file path

WARNING: Hybrid Analysis free tier — all submissions are permanently public
and cannot be deleted. Only run this script on already-confirmed-public IOCs.

This step is gated in CI via the ENABLE_SANDBOX=true repository variable.

Reads:  cache/enriched_infra.json
Reads:  cache/ha_submitted.json   (state tracking, created if absent)
Writes: cache/ha_results.json
Writes: cache/ha_submitted.json   (updated)

Environment:
  HA_API_KEY — Hybrid Analysis API key (required)
"""

import json
import os
import sys
import time
from urllib.parse import urlparse

import requests

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE_DIR = os.path.join(REPO_ROOT, "cache")

INPUT_PATH = os.path.join(CACHE_DIR, "enriched_infra.json")
SUBMITTED_PATH = os.path.join(CACHE_DIR, "ha_submitted.json")
RESULTS_PATH = os.path.join(CACHE_DIR, "ha_results.json")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

HA_BASE_URL = "https://www.hybrid-analysis.com/api/v2"
HA_SUBMIT_URL = f"{HA_BASE_URL}/submit/url"
HA_STATE_URL = f"{HA_BASE_URL}/report/{{job_id}}/state"
HA_SUMMARY_URL = f"{HA_BASE_URL}/report/{{job_id}}/summary"

# Windows 10 64-bit environment
HA_ENVIRONMENT_ID = 160

ACTIONABLE_EXTENSIONS = {".ps1", ".hta", ".js", ".bat", ".exe", ".msi"}

# CDN roots — skip URLs pointing at these without a deep file path
CDN_ROOT_PATTERNS = (
    "cloudflare.com", "github.io", "githubusercontent.com",
    "web.app", "firebaseapp.com", "pages.dev",
)

POLL_INTERVAL = 30   # seconds between state polls
POLL_TIMEOUT = 900   # 15 minutes


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_json(path, default=None):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return default if default is not None else {}


def _save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def _get_file_extension(url):
    """Return lowercase extension of the URL path, e.g. '.ps1'. Empty string if none."""
    try:
        path = urlparse(url).path
        _, ext = os.path.splitext(path)
        return ext.lower()
    except Exception:
        return ""


def _is_cdn_root(url):
    """Return True if the URL points at a known CDN without a specific file path."""
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        path = parsed.path.rstrip("/")
        is_cdn = any(pat in host for pat in CDN_ROOT_PATTERNS)
        # If it's a CDN but has a deep path (more than 1 segment), it's probably a payload
        has_file_path = path.count("/") >= 2 and _get_file_extension(url) in ACTIONABLE_EXTENSIONS
        return is_cdn and not has_file_path
    except Exception:
        return False


def _candidate_urls(enriched_records):
    """Yield (staging_url, domain) tuples that pass the pre-submission filter."""
    for record in enriched_records:
        enr = record.get("enrichment", {})
        vt_malicious = enr.get("vt_malicious", 0) or 0

        # Require at least one malicious VT vote
        if vt_malicious <= 0:
            continue

        # Check downloaded files for actionable extensions
        downloaded_files = record.get("downloaded_files", [])
        has_actionable = any(
            os.path.splitext(f)[1].lower() in ACTIONABLE_EXTENSIONS
            for f in downloaded_files
        )
        if not has_actionable:
            continue

        # The staging URL is the primary URL
        url = record.get("url", "")
        if not url:
            continue

        ext = _get_file_extension(url)
        if ext not in ACTIONABLE_EXTENSIONS:
            # Try to find a better URL from downloaded_files context
            # If the primary URL doesn't have the right extension, skip —
            # we don't want to submit the lure page itself, only the payload host
            continue

        if _is_cdn_root(url):
            continue

        host = (urlparse(url).hostname or "").lower()
        yield url, host


# ---------------------------------------------------------------------------
# Hybrid Analysis API
# ---------------------------------------------------------------------------

def _ha_headers(api_key):
    return {
        "api-key": api_key,
        "user-agent": "Falcon Sandbox",
        "accept": "application/json",
    }


def submit_sample(url, api_key, session):
    """Submit a URL to Hybrid Analysis for fetch-and-execute analysis.

    Returns job_id string on success, None on failure.
    """
    try:
        resp = session.post(
            HA_SUBMIT_URL,
            headers=_ha_headers(api_key),
            data={"url": url, "environment_id": HA_ENVIRONMENT_ID},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        job_id = data.get("job_id")
        return job_id
    except Exception as exc:
        print(f"  [WARN] HA submit failed for {url}: {exc}", file=sys.stderr)
        return None


def poll_until_complete(job_id, api_key, session):
    """Poll the Hybrid Analysis state endpoint until state == 'SUCCESS'.

    Returns True on success, False on timeout or error.
    """
    state_url = HA_STATE_URL.format(job_id=job_id)
    headers = _ha_headers(api_key)
    deadline = time.monotonic() + POLL_TIMEOUT

    while time.monotonic() < deadline:
        try:
            resp = session.get(state_url, headers=headers, timeout=30)
            if resp.status_code == 404:
                # Sample not yet visible — keep polling
                pass
            else:
                resp.raise_for_status()
                state = resp.json().get("state", "")
                if state == "SUCCESS":
                    return True
                if state in ("ERROR", "FAILED"):
                    print(
                        f"  [WARN] HA job {job_id} ended with state: {state}",
                        file=sys.stderr,
                    )
                    return False
        except Exception as exc:
            print(f"  [WARN] Poll error for {job_id}: {exc}", file=sys.stderr)

        time.sleep(POLL_INTERVAL)

    print(f"  [WARN] HA poll timeout for {job_id}", file=sys.stderr)
    return False


def fetch_report(job_id, api_key, session):
    """Fetch the summary report for a completed Hybrid Analysis job.

    Returns parsed dict or None on failure.
    """
    summary_url = HA_SUMMARY_URL.format(job_id=job_id)
    try:
        resp = session.get(
            summary_url,
            headers=_ha_headers(api_key),
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        print(f"  [WARN] HA report fetch failed for {job_id}: {exc}", file=sys.stderr)
        return None


def parse_ha_report(report, url, job_id):
    """Extract family tags, network IOCs, and file hashes from a Hybrid Analysis summary."""
    if not report or not isinstance(report, dict):
        return {}

    families = []
    vx_family = report.get("vx_family")
    if vx_family:
        families = [vx_family]

    # Compromised hosts + contacted domains as network IOCs
    network_iocs = []
    for host in report.get("compromised_hosts", []):
        if host and host not in network_iocs:
            network_iocs.append(host)
    for domain in report.get("domains", []):
        if domain and domain not in network_iocs:
            network_iocs.append(domain)

    # Primary file hash from the detonated sample
    dropped_hashes = []
    sha256 = report.get("sha256")
    if sha256:
        dropped_hashes.append(sha256)

    return {
        "url": url,
        "job_id": job_id,
        "families": families,
        "network_iocs": network_iocs,
        "dropped_hashes": dropped_hashes,
        "threat_score": report.get("threat_score"),
        "verdict": report.get("verdict"),
    }


# ---------------------------------------------------------------------------
# Run log
# ---------------------------------------------------------------------------

def _write_run_log(cache_dir, section, data):
    import datetime as _dt
    path = os.path.join(cache_dir, "pipeline_run.json")
    log = {}
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                log = json.load(f)
        except Exception:
            pass
    log.setdefault("run_date", _dt.date.today().isoformat())
    log[section] = {"timestamp": _dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"), **data}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(log, f, indent=2)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    os.makedirs(CACHE_DIR, exist_ok=True)

    api_key = os.environ.get("HA_API_KEY", "").strip()
    if not api_key:
        print("ERROR: HA_API_KEY environment variable not set.", file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(INPUT_PATH):
        print(f"ERROR: {INPUT_PATH} not found. Run enrich_infra.py first.", file=sys.stderr)
        sys.exit(1)

    with open(INPUT_PATH, "r", encoding="utf-8") as f:
        enriched_records = json.load(f)

    submitted = _load_json(SUBMITTED_PATH, default={})
    existing_results = _load_json(RESULTS_PATH, default=[])
    results = list(existing_results)

    candidates = list(_candidate_urls(enriched_records))
    print(f"Candidate URLs for sandbox submission: {len(candidates)}")

    new_submissions = [
        (url, host) for (url, host) in candidates if url not in submitted
    ]
    print(f"New (not previously submitted): {len(new_submissions)}")

    if not new_submissions:
        print("Nothing new to submit.")
        _write_run_log(CACHE_DIR, "sandbox_submit", {
            "api_key_present": bool(api_key),
            "candidates": len(candidates),
            "submitted_new": 0,
            "completed": 0,
            "failed": 0,
            "timed_out": 0,
            "status": "ok",
        })
        return

    with requests.Session() as session:
        session.headers["User-Agent"] = "Falcon Sandbox"

        for url, host in new_submissions:
            print(f"\n  Submitting: {url}")
            job_id = submit_sample(url, api_key, session)
            if not job_id:
                submitted[url] = {"status": "submit_failed"}
                _save_json(SUBMITTED_PATH, submitted)
                continue

            submitted[url] = {"job_id": job_id, "status": "pending"}
            _save_json(SUBMITTED_PATH, submitted)

            print(f"  Job ID: {job_id} — polling for completion...")
            success = poll_until_complete(job_id, api_key, session)
            if not success:
                submitted[url]["status"] = "timeout_or_failed"
                _save_json(SUBMITTED_PATH, submitted)
                continue

            print(f"  Complete. Fetching summary report...")
            report = fetch_report(job_id, api_key, session)
            parsed = parse_ha_report(report, url, job_id)
            if parsed:
                families = parsed.get("families", [])
                verdict = parsed.get("verdict", "")
                print(f"  Verdict: {verdict or '(none)'}  Families: {families or '(none identified)'}")
                results.append(parsed)
                _save_json(RESULTS_PATH, results)

            submitted[url]["status"] = "completed"
            submitted[url]["families"] = parsed.get("families", [])
            _save_json(SUBMITTED_PATH, submitted)

    _save_json(RESULTS_PATH, results)
    print(f"\nWritten: {RESULTS_PATH} ({len(results)} total results)")

    completed_count = sum(1 for v in submitted.values() if v.get("status") == "completed")
    failed_count = sum(1 for v in submitted.values() if v.get("status") == "submit_failed")
    timed_out_count = sum(1 for v in submitted.values() if v.get("status") == "timeout_or_failed")
    _write_run_log(CACHE_DIR, "sandbox_submit", {
        "api_key_present": bool(api_key),
        "candidates": len(candidates),
        "submitted_new": len(new_submissions),
        "completed": completed_count,
        "failed": failed_count,
        "timed_out": timed_out_count,
        "status": "ok",
    })


if __name__ == "__main__":
    main()
