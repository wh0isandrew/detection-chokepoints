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

Multiple new submissions are processed concurrently; their polling loops run
in parallel so a slow job doesn't block others.

WARNING: Hybrid Analysis free tier — all submissions are permanently public
and cannot be deleted. Only run this script on already-confirmed-public IOCs.

This step is gated in CI via the ENABLE_SANDBOX=true repository variable.

Reads:  cache/enriched_infra.json
Reads:  cache/ha_submitted.json   (state tracking, created if absent)
Writes: cache/ha_results.json
Writes: cache/ha_submitted.json   (updated)

Environment:
  HA_API_KEY         — Hybrid Analysis API key (required)
  HA_BASE_URL        — override API base (default from .env.example)
  HA_ENVIRONMENT_ID  — sandbox environment (default 160 = Win10 64-bit)
  HA_POLL_INTERVAL   — seconds between state polls (default 30)
  HA_POLL_TIMEOUT    — max seconds to wait per job (default 900)
"""

import asyncio
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

import httpx
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT      = Path(__file__).parent.parent
CACHE_DIR      = REPO_ROOT / "cache"
INPUT_PATH     = CACHE_DIR / "enriched_infra.json"
SUBMITTED_PATH = CACHE_DIR / "ha_submitted.json"
RESULTS_PATH   = CACHE_DIR / "ha_results.json"

# ---------------------------------------------------------------------------
# Constants (overridable via .env)
# ---------------------------------------------------------------------------

HA_BASE_URL      = os.getenv("HA_BASE_URL",     "https://www.hybrid-analysis.com/api/v2")
HA_SUBMIT_URL    = f"{HA_BASE_URL}/submit/url"
HA_STATE_URL     = f"{HA_BASE_URL}/report/{{job_id}}/state"
HA_SUMMARY_URL   = f"{HA_BASE_URL}/report/{{job_id}}/summary"

HA_ENVIRONMENT_ID = int(os.getenv("HA_ENVIRONMENT_ID", "160"))  # Windows 10 64-bit
POLL_INTERVAL     = float(os.getenv("HA_POLL_INTERVAL", "30"))
POLL_TIMEOUT      = float(os.getenv("HA_POLL_TIMEOUT",  "900"))

ACTIONABLE_EXTENSIONS = {".ps1", ".hta", ".js", ".bat", ".exe", ".msi"}
CDN_ROOT_PATTERNS     = (
    "cloudflare.com", "github.io", "githubusercontent.com",
    "web.app", "firebaseapp.com", "pages.dev",
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_json(path: Path, default=None):
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return default if default is not None else {}


def _save_json(path: Path, data) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def _get_file_extension(url: str) -> str:
    try:
        return Path(urlparse(url).path).suffix.lower()
    except Exception:
        return ""


def _is_cdn_root(url: str) -> bool:
    try:
        parsed  = urlparse(url)
        host    = (parsed.hostname or "").lower()
        path    = parsed.path.rstrip("/")
        is_cdn  = any(pat in host for pat in CDN_ROOT_PATTERNS)
        has_file_path = (
            path.count("/") >= 2
            and _get_file_extension(url) in ACTIONABLE_EXTENSIONS
        )
        return is_cdn and not has_file_path
    except Exception:
        return False


def _candidate_urls(enriched_records):
    """Yield (staging_url, domain) tuples that pass the pre-submission filter."""
    for record in enriched_records:
        enr          = record.get("enrichment", {})
        vt_malicious = enr.get("vt_malicious", 0) or 0

        if vt_malicious <= 0:
            continue

        downloaded_files = record.get("downloaded_files", [])
        has_actionable   = any(
            Path(f).suffix.lower() in ACTIONABLE_EXTENSIONS for f in downloaded_files
        )
        if not has_actionable:
            continue

        url = record.get("url", "")
        if not url:
            continue
        if _get_file_extension(url) not in ACTIONABLE_EXTENSIONS:
            continue
        if _is_cdn_root(url):
            continue

        host = (urlparse(url).hostname or "").lower()
        yield url, host


# ---------------------------------------------------------------------------
# Hybrid Analysis API (async)
# ---------------------------------------------------------------------------

def _ha_headers(api_key: str) -> dict:
    return {
        "api-key":    api_key,
        "user-agent": "Falcon Sandbox",
        "accept":     "application/json",
    }


async def submit_sample(url: str, api_key: str, client: httpx.AsyncClient) -> str | None:
    """Submit a URL to Hybrid Analysis. Returns job_id on success, None on failure."""
    try:
        resp = await client.post(
            HA_SUBMIT_URL,
            headers=_ha_headers(api_key),
            data={"url": url, "environment_id": HA_ENVIRONMENT_ID},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json().get("job_id")
    except Exception as exc:
        print(f"  [WARN] HA submit failed for {url}: {exc}", file=sys.stderr)
        return None


async def poll_until_complete(job_id: str, api_key: str, client: httpx.AsyncClient) -> bool:
    """Poll job state until SUCCESS, ERROR/FAILED, or timeout. Returns True on success."""
    state_url = HA_STATE_URL.format(job_id=job_id)
    headers   = _ha_headers(api_key)
    deadline  = asyncio.get_event_loop().time() + POLL_TIMEOUT

    while asyncio.get_event_loop().time() < deadline:
        try:
            resp = await client.get(state_url, headers=headers, timeout=30)
            if resp.status_code != 404:
                resp.raise_for_status()
                state = resp.json().get("state", "")
                if state == "SUCCESS":
                    return True
                if state in ("ERROR", "FAILED"):
                    print(f"  [WARN] HA job {job_id} ended with state: {state}", file=sys.stderr)
                    return False
        except Exception as exc:
            print(f"  [WARN] Poll error for {job_id}: {exc}", file=sys.stderr)

        await asyncio.sleep(POLL_INTERVAL)

    print(f"  [WARN] HA poll timeout for {job_id}", file=sys.stderr)
    return False


async def fetch_report(job_id: str, api_key: str, client: httpx.AsyncClient) -> dict | None:
    """Fetch the summary report for a completed Hybrid Analysis job."""
    try:
        resp = await client.get(
            HA_SUMMARY_URL.format(job_id=job_id),
            headers=_ha_headers(api_key),
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        print(f"  [WARN] HA report fetch failed for {job_id}: {exc}", file=sys.stderr)
        return None


def parse_ha_report(report: dict | None, url: str, job_id: str) -> dict:
    """Extract family tags, network IOCs, and file hashes from an HA summary."""
    if not report or not isinstance(report, dict):
        return {}

    vx_family   = report.get("vx_family")
    network_iocs: list = []
    for host in report.get("compromised_hosts", []):
        if host and host not in network_iocs:
            network_iocs.append(host)
    for domain in report.get("domains", []):
        if domain and domain not in network_iocs:
            network_iocs.append(domain)

    dropped_hashes = []
    sha256 = report.get("sha256")
    if sha256:
        dropped_hashes.append(sha256)

    return {
        "url":           url,
        "job_id":        job_id,
        "families":      [vx_family] if vx_family else [],
        "network_iocs":  network_iocs,
        "dropped_hashes": dropped_hashes,
        "threat_score":  report.get("threat_score"),
        "verdict":       report.get("verdict"),
    }


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

    api_key = os.environ.get("HA_API_KEY", "").strip()
    if not api_key:
        print("ERROR: HA_API_KEY environment variable not set.", file=sys.stderr)
        sys.exit(1)

    if not INPUT_PATH.exists():
        print(f"ERROR: {INPUT_PATH} not found. Run enrich_infra.py first.", file=sys.stderr)
        sys.exit(1)

    enriched_records  = json.loads(INPUT_PATH.read_text(encoding="utf-8"))
    submitted         = _load_json(SUBMITTED_PATH, default={})
    existing_results  = _load_json(RESULTS_PATH, default=[])
    results           = list(existing_results)
    lock              = asyncio.Lock()

    candidates     = list(_candidate_urls(enriched_records))
    new_submissions = [(url, host) for url, host in candidates if url not in submitted]
    print(f"Candidate URLs for sandbox submission: {len(candidates)}")
    print(f"New (not previously submitted): {len(new_submissions)}")

    if not new_submissions:
        print("Nothing new to submit.")
        _write_run_log(CACHE_DIR, "sandbox_submit", {
            "api_key_present": bool(api_key),
            "candidates":    len(candidates),
            "submitted_new": 0,
            "completed":     0,
            "failed":        0,
            "timed_out":     0,
            "status": "ok",
        })
        return

    async def _handle(url: str, host: str, client: httpx.AsyncClient) -> None:
        print(f"\n  Submitting: {url}")
        job_id = await submit_sample(url, api_key, client)
        if not job_id:
            async with lock:
                submitted[url] = {"status": "submit_failed"}
                _save_json(SUBMITTED_PATH, submitted)
            return

        async with lock:
            submitted[url] = {"job_id": job_id, "status": "pending"}
            _save_json(SUBMITTED_PATH, submitted)

        print(f"  Job ID: {job_id} — polling for completion...")
        success = await poll_until_complete(job_id, api_key, client)
        if not success:
            async with lock:
                submitted[url]["status"] = "timeout_or_failed"
                _save_json(SUBMITTED_PATH, submitted)
            return

        print(f"  Complete. Fetching summary report...")
        report = await fetch_report(job_id, api_key, client)
        parsed = parse_ha_report(report, url, job_id)
        if parsed:
            verdict  = parsed.get("verdict", "")
            families = parsed.get("families", [])
            print(f"  Verdict: {verdict or '(none)'}  Families: {families or '(none identified)'}")
            async with lock:
                results.append(parsed)
                _save_json(RESULTS_PATH, results)

        async with lock:
            submitted[url]["status"]   = "completed"
            submitted[url]["families"] = parsed.get("families", []) if parsed else []
            _save_json(SUBMITTED_PATH, submitted)

    async with httpx.AsyncClient(headers={"User-Agent": "Falcon Sandbox"}) as client:
        await asyncio.gather(*[_handle(url, host, client) for url, host in new_submissions])

    _save_json(RESULTS_PATH, results)
    print(f"\nWritten: {RESULTS_PATH} ({len(results)} total results)")

    completed_count  = sum(1 for v in submitted.values() if v.get("status") == "completed")
    failed_count     = sum(1 for v in submitted.values() if v.get("status") == "submit_failed")
    timed_out_count  = sum(1 for v in submitted.values() if v.get("status") == "timeout_or_failed")
    _write_run_log(CACHE_DIR, "sandbox_submit", {
        "api_key_present": bool(api_key),
        "candidates":    len(candidates),
        "submitted_new": len(new_submissions),
        "completed":     completed_count,
        "failed":        failed_count,
        "timed_out":     timed_out_count,
        "status": "ok",
    })


if __name__ == "__main__":
    asyncio.run(main())
