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
  HA_API_KEY            — Hybrid Analysis API key (required)
  HA_BASE_URL           — override API base (default from .env.example)
  HA_REQUEST_DELAY      — polite floor between requests in seconds (default 0.8)
  HA_MAX_RESULTS_PER_TERM — max reports to store per IOC (default 5)
"""

import asyncio
import json
import os
import sys
from pathlib import Path

import httpx
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT   = Path(__file__).parent.parent
CACHE_DIR   = REPO_ROOT / "cache"
INPUT_PATH  = CACHE_DIR / "enriched_infra.json"
OUTPUT_PATH = CACHE_DIR / "ha_lookup_results.json"

# ---------------------------------------------------------------------------
# Constants (overridable via .env)
# ---------------------------------------------------------------------------

HA_BASE_URL          = os.getenv("HA_BASE_URL", "https://www.hybrid-analysis.com/api/v2")
HA_SEARCH_URL        = f"{HA_BASE_URL}/search/terms"
HA_REQUEST_DELAY     = float(os.getenv("HA_REQUEST_DELAY", "0.8"))
MAX_RESULTS_PER_TERM = int(os.getenv("HA_MAX_RESULTS_PER_TERM", "5"))
HA_CONCURRENCY       = 6   # well under the free-tier ~100 req/min ceiling

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


def _ha_headers(api_key: str) -> dict:
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
        enr  = record.get("enrichment", {})
        host = (enr.get("host") or "").lower()
        ip   = enr.get("ip", "")
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

async def search_term(
    term_type: str,
    value: str,
    api_key: str,
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
) -> list:
    """Query HA /search/terms for existing reports matching term_type=value."""
    async with sem:
        try:
            resp = await client.post(
                HA_SEARCH_URL,
                headers=_ha_headers(api_key),
                data={term_type: value},
                timeout=30,
            )
            if resp.status_code == 404:
                return []
            resp.raise_for_status()
            results = resp.json().get("result", [])[:MAX_RESULTS_PER_TERM]
            # polite floor — keeps us well under rate limit even with concurrency
            await asyncio.sleep(HA_REQUEST_DELAY)
            return results
        except Exception as exc:
            print(f"  [WARN] HA search failed for {term_type}={value}: {exc}", file=sys.stderr)
            return []


def _parse_hit(hit: dict, term_type: str, value: str) -> dict:
    """Extract payload analysis fields from a single HA search result."""
    vx_family = hit.get("vx_family")
    return {
        "matched_term": f"{term_type}:{value}",
        "job_id":       hit.get("job_id"),
        "sha256":       hit.get("sha256"),
        "threat_score": hit.get("threat_score"),
        "verdict":      hit.get("verdict"),
        "families":     [vx_family] if vx_family else [],
        "tags":         hit.get("tags") or [],
        "analysis_start_time": hit.get("analysis_start_time"),
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

    enriched_records = _load_json(INPUT_PATH, default=[])
    terms = extract_iocs(enriched_records)

    domain_count = sum(1 for t, _ in terms if t == "domain")
    ip_count     = sum(1 for t, _ in terms if t == "ip")
    print(f"IOC terms to look up: {len(terms)} ({domain_count} domains, {ip_count} IPs)")

    cached  = _load_json(OUTPUT_PATH, default={})
    results = dict(cached)

    new_terms = [(t, v) for t, v in terms if f"{t}:{v}" not in results]
    print(f"New terms (not cached): {len(new_terms)}")

    sem = asyncio.Semaphore(HA_CONCURRENCY)
    async with httpx.AsyncClient() as client:
        raw_hits = await asyncio.gather(*[
            search_term(t, v, api_key, client, sem) for t, v in new_terms
        ])

    hit_count = 0
    for (term_type, value), hits in zip(new_terms, raw_hits):
        key = f"{term_type}:{value}"
        parsed = [_parse_hit(h, term_type, value) for h in hits]
        results[key] = parsed
        if parsed:
            families = [f for h in parsed for f in h.get("families", [])]
            verdicts = [h["verdict"] for h in parsed if h.get("verdict")]
            print(f"  {key}: {len(parsed)} report(s)  families={families or '(none)'}  verdicts={verdicts or '(none)'}")
            hit_count += len(parsed)

    OUTPUT_PATH.write_text(
        json.dumps(results, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    print(f"\nWritten: {OUTPUT_PATH}")
    print(f"  New lookups: {len(new_terms)}  Total cached: {len(results)}  Reports found: {hit_count}")

    _write_run_log(CACHE_DIR, "ha_lookup", {
        "api_key_present": bool(api_key),
        "new_lookups":  len(new_terms),
        "reports_found": hit_count,
        "total_cached": len(results),
        "status": "ok",
    })


if __name__ == "__main__":
    asyncio.run(main())
