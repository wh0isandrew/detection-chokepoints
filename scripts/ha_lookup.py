#!/usr/bin/env python3
"""
ha_lookup.py
Query Hybrid Analysis for existing public reports matching domains and IPs
from the enrichment pipeline. Complements sandbox_submit.py by finding
already-analysed samples without requiring new submissions.

Results are cached across runs — only new IOCs (not in cache) are queried.

Reads:  cache/enriched_infra.json
Writes: cache/ha_lookup_results.json

Environment:
  HA_API_KEY — Hybrid Analysis API key (required)
"""

import json
import os
import sys
import time

import requests

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE_DIR = os.path.join(REPO_ROOT, "cache")

INPUT_PATH = os.path.join(CACHE_DIR, "enriched_infra.json")
OUTPUT_PATH = os.path.join(CACHE_DIR, "ha_lookup_results.json")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

HA_BASE_URL = "https://www.hybrid-analysis.com/api/v2"
HA_SEARCH_URL = f"{HA_BASE_URL}/search/terms"

# Free tier allows ~100 req/min; stay well under with a small delay
REQUEST_DELAY = 0.8  # seconds between requests

# Cap results per term — we want signal, not noise
MAX_RESULTS_PER_TERM = 5


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


def _ha_headers(api_key):
    return {
        "api-key": api_key,
        "user-agent": "Falcon Sandbox",
        "accept": "application/json",
    }


# ---------------------------------------------------------------------------
# IOC extraction
# ---------------------------------------------------------------------------

def extract_iocs(enriched_records):
    """Return deduplicated (term_type, value) pairs for HA lookup."""
    seen = set()
    terms = []
    for record in enriched_records:
        enr = record.get("enrichment", {})
        host = (enr.get("host") or "").lower()
        ip = enr.get("ip", "")
        if host and ("domain", host) not in seen:
            seen.add(("domain", host))
            terms.append(("domain", host))
        if ip and ("ip", ip) not in seen:
            seen.add(("ip", ip))
            terms.append(("ip", ip))
    return terms


# ---------------------------------------------------------------------------
# Hybrid Analysis search
# ---------------------------------------------------------------------------

def search_term(term_type, value, api_key, session):
    """Query HA /search/terms for existing reports matching term_type=value.

    Returns list of raw result dicts (may be empty).
    """
    try:
        resp = session.post(
            HA_SEARCH_URL,
            headers=_ha_headers(api_key),
            data={term_type: value},
            timeout=30,
        )
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        return resp.json().get("result", [])[:MAX_RESULTS_PER_TERM]
    except Exception as exc:
        print(f"  [WARN] HA search failed for {term_type}={value}: {exc}", file=sys.stderr)
        return []


def _parse_hit(hit, term_type, value):
    """Extract payload analysis fields from a single HA search result."""
    families = []
    vx_family = hit.get("vx_family")
    if vx_family:
        families = [vx_family]

    return {
        "matched_term": f"{term_type}:{value}",
        "job_id": hit.get("job_id"),
        "sha256": hit.get("sha256"),
        "threat_score": hit.get("threat_score"),
        "verdict": hit.get("verdict"),
        "families": families,
        "tags": hit.get("tags") or [],
        "analysis_start_time": hit.get("analysis_start_time"),
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

    enriched_records = _load_json(INPUT_PATH, default=[])
    terms = extract_iocs(enriched_records)

    domain_count = sum(1 for t, _ in terms if t == "domain")
    ip_count = sum(1 for t, _ in terms if t == "ip")
    print(f"IOC terms to look up: {len(terms)} ({domain_count} domains, {ip_count} IPs)")

    # Load cache — skip terms already queried in previous runs
    cached = _load_json(OUTPUT_PATH, default={})
    results = dict(cached)

    new_count = 0
    hit_count = 0

    with requests.Session() as session:
        for term_type, value in terms:
            key = f"{term_type}:{value}"
            if key in results:
                continue  # already cached from a previous run

            hits = search_term(term_type, value, api_key, session)
            parsed_hits = [_parse_hit(h, term_type, value) for h in hits]
            results[key] = parsed_hits

            if parsed_hits:
                families = [f for h in parsed_hits for f in h.get("families", [])]
                verdicts = [h["verdict"] for h in parsed_hits if h.get("verdict")]
                print(f"  {key}: {len(parsed_hits)} report(s)  families={families or '(none)'}  verdicts={verdicts or '(none)'}")
                hit_count += len(parsed_hits)

            new_count += 1
            time.sleep(REQUEST_DELAY)

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"\nWritten: {OUTPUT_PATH}")
    print(f"  New lookups: {new_count}  Total cached: {len(results)}  Reports found: {hit_count}")

    _write_run_log(CACHE_DIR, "ha_lookup", {
        "api_key_present": bool(api_key),
        "new_lookups": new_count,
        "reports_found": hit_count,
        "total_cached": len(results),
        "status": "ok",
    })


if __name__ == "__main__":
    main()
