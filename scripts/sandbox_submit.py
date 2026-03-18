#!/usr/bin/env python3
"""
sandbox_submit.py
Submit staging URLs from the ClickGrab pipeline to Triage (tria.ge) for
behavioral analysis. Only submits URLs that pass the pre-submission filter:

  1. VT flags the domain as malicious (vt_malicious > 0)
  2. The downloaded file has an actionable extension (.ps1, .hta, .js, .bat,
     .exe, .msi)
  3. The URL is not a CDN root without a specific file path

WARNING: Triage free tier — all submissions are permanently public and
cannot be deleted. Only run this script on already-confirmed-public IOCs.

This step is gated in CI via the ENABLE_SANDBOX=true repository variable.

Reads:  cache/enriched_infra.json
Reads:  cache/triage_submitted.json  (state tracking, created if absent)
Writes: cache/triage_results.json
Writes: cache/triage_submitted.json  (updated)

Environment:
  TRIAGE_TOKEN — Triage API bearer token (required)
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
SUBMITTED_PATH = os.path.join(CACHE_DIR, "triage_submitted.json")
RESULTS_PATH = os.path.join(CACHE_DIR, "triage_results.json")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TRIAGE_SUBMIT_URL = "https://tria.ge/api/v0/samples"
TRIAGE_EVENTS_URL = "https://tria.ge/api/v0/samples/{sample_id}/events"
TRIAGE_REPORT_URL = (
    "https://tria.ge/api/v0/samples/{sample_id}/behavioral1/report_triage.json"
)

ACTIONABLE_EXTENSIONS = {".ps1", ".hta", ".js", ".bat", ".exe", ".msi"}

# CDN roots — skip URLs pointing at these without a deep file path
CDN_ROOT_PATTERNS = (
    "cloudflare.com", "github.io", "githubusercontent.com",
    "web.app", "firebaseapp.com", "pages.dev",
)

POLL_INTERVAL = 30   # seconds between event stream polls
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
# Triage API
# ---------------------------------------------------------------------------

def submit_sample(url, token, session):
    """Submit a URL to Triage for fetch-and-execute analysis.

    Returns sample_id string on success, None on failure.
    """
    try:
        resp = session.post(
            TRIAGE_SUBMIT_URL,
            json={"kind": "fetch", "url": url},
            headers={"Authorization": f"Bearer {token}"},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        sample_id = data.get("id") or data.get("sample_id")
        return sample_id
    except Exception as exc:
        print(f"  [WARN] Triage submit failed for {url}: {exc}", file=sys.stderr)
        return None


def poll_until_reported(sample_id, token, session):
    """Poll the Triage events JSONL stream until status == 'reported'.

    Returns True on success, False on timeout or error.
    """
    events_url = TRIAGE_EVENTS_URL.format(sample_id=sample_id)
    headers = {"Authorization": f"Bearer {token}"}
    deadline = time.monotonic() + POLL_TIMEOUT

    while time.monotonic() < deadline:
        try:
            resp = session.get(events_url, headers=headers, timeout=30)
            if resp.status_code == 404:
                # Sample not yet visible — keep polling
                pass
            else:
                resp.raise_for_status()
                for line in resp.text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except ValueError:
                        continue
                    status = event.get("status") or event.get("event")
                    if status == "reported":
                        return True
                    if status in ("failed", "error"):
                        print(
                            f"  [WARN] Triage sample {sample_id} failed: {event}",
                            file=sys.stderr,
                        )
                        return False
        except Exception as exc:
            print(f"  [WARN] Poll error for {sample_id}: {exc}", file=sys.stderr)

        time.sleep(POLL_INTERVAL)

    print(f"  [WARN] Triage poll timeout for {sample_id}", file=sys.stderr)
    return False


def fetch_report(sample_id, token, session):
    """Fetch the behavioral Triage report for a completed sample.

    Returns parsed dict or None on failure.
    """
    report_url = TRIAGE_REPORT_URL.format(sample_id=sample_id)
    try:
        resp = session.get(
            report_url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        print(f"  [WARN] Report fetch failed for {sample_id}: {exc}", file=sys.stderr)
        return None


def parse_triage_report(report, url, sample_id):
    """Extract family tags, network IOCs, and dropped file hashes from a Triage report."""
    families = []
    network_iocs = []
    dropped_hashes = []

    if not report or not isinstance(report, dict):
        return {}

    # Family tags from targets
    for target in report.get("targets", []):
        for fam in target.get("family", []):
            if isinstance(fam, str) and fam not in families:
                families.append(fam)
        # Dropped files
        for sig in target.get("signatures", []):
            for ioc in sig.get("iocs", []):
                if isinstance(ioc, dict):
                    h = ioc.get("sha256") or ioc.get("md5")
                    if h and h not in dropped_hashes:
                        dropped_hashes.append(h)

    # Network signatures
    for sig in report.get("signatures", []):
        for ioc in sig.get("iocs", []):
            if isinstance(ioc, dict):
                domain = ioc.get("domain") or ioc.get("host")
                if domain and domain not in network_iocs:
                    network_iocs.append(domain)

    return {
        "url": url,
        "sample_id": sample_id,
        "families": families,
        "network_iocs": network_iocs,
        "dropped_hashes": dropped_hashes,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    os.makedirs(CACHE_DIR, exist_ok=True)

    token = os.environ.get("TRIAGE_TOKEN", "").strip()
    if not token:
        print("ERROR: TRIAGE_TOKEN environment variable not set.", file=sys.stderr)
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
        return

    with requests.Session() as session:
        session.headers["User-Agent"] = "detection-chokepoints/enrichment-pipeline"

        for url, host in new_submissions:
            print(f"\n  Submitting: {url}")
            sample_id = submit_sample(url, token, session)
            if not sample_id:
                submitted[url] = {"status": "submit_failed"}
                _save_json(SUBMITTED_PATH, submitted)
                continue

            submitted[url] = {"sample_id": sample_id, "status": "pending"}
            _save_json(SUBMITTED_PATH, submitted)

            print(f"  Sample ID: {sample_id} — polling for completion...")
            success = poll_until_reported(sample_id, token, session)
            if not success:
                submitted[url]["status"] = "timeout_or_failed"
                _save_json(SUBMITTED_PATH, submitted)
                continue

            print(f"  Reported. Fetching behavioral report...")
            report = fetch_report(sample_id, token, session)
            parsed = parse_triage_report(report, url, sample_id)
            if parsed:
                families = parsed.get("families", [])
                print(f"  Families: {families or '(none identified)'}")
                results.append(parsed)
                _save_json(RESULTS_PATH, results)

            submitted[url]["status"] = "completed"
            submitted[url]["families"] = parsed.get("families", [])
            _save_json(SUBMITTED_PATH, submitted)

    _save_json(RESULTS_PATH, results)
    print(f"\nWritten: {RESULTS_PATH} ({len(results)} total results)")


if __name__ == "__main__":
    main()
