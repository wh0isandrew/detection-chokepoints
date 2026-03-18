#!/usr/bin/env python3
"""
enrich_infra.py
For each unique domain/IP extracted from cache/clickgrab_raw.json, fetch
ASN + geo data via IPinfo Lite and reputation data via VirusTotal.

Reads:  cache/clickgrab_raw.json
Writes: cache/enriched_infra.json
Caches: cache/dns_cache.json  — hostname → resolved IP
        cache/vt_cache.json   — domain/IP → VT response

Environment variables:
  IPINFO_TOKEN   — IPinfo API token (optional; unauthenticated gets 1000 req/day)
  VT_API_KEY     — VirusTotal API key (required for VT enrichment)
"""

import collections
import json
import os
import socket
import sys
import time
from urllib.parse import urlparse

import requests

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE_DIR = os.path.join(REPO_ROOT, "cache")

INPUT_PATH = os.path.join(CACHE_DIR, "clickgrab_raw.json")
OUTPUT_PATH = os.path.join(CACHE_DIR, "enriched_infra.json")
DNS_CACHE_PATH = os.path.join(CACHE_DIR, "dns_cache.json")
VT_CACHE_PATH = os.path.join(CACHE_DIR, "vt_cache.json")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

IPINFO_URL = "https://api.ipinfo.io/lite/{ip}"
VT_DOMAIN_URL = "https://www.virustotal.com/api/v3/domains/{domain}"
VT_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"

IPINFO_SLEEP = 0.05   # 50 ms between IPinfo requests
REQUEST_TIMEOUT = 10

# VT free tier: 4 requests/minute, 500/day
VT_RATE_PER_MIN = 4
VT_DAILY_BUDGET = 500

# IP address pattern
_RE_IP = __import__("re").compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _is_ip(host):
    return bool(_RE_IP.match(host))


# ---------------------------------------------------------------------------
# Rate limiter (sliding window)
# ---------------------------------------------------------------------------

class RateLimiter:
    """Sliding-window rate limiter.

    Tracks request timestamps in a deque. Before each request, drops timestamps
    outside the window, then sleeps if the window is full.
    """

    def __init__(self, max_per_minute=4, daily_budget=500):
        self.max_per_minute = max_per_minute
        self.daily_budget = daily_budget
        self.window = collections.deque()   # timestamps of recent requests
        self.daily_count = 0
        self.budget_exhausted = False

    def acquire(self):
        """Block until a request slot is available. Returns False if daily budget exceeded."""
        if self.budget_exhausted:
            return False

        if self.daily_count >= self.daily_budget:
            print(
                f"  [WARN] VT daily budget of {self.daily_budget} requests exhausted. "
                "Skipping remaining VT lookups.",
                file=sys.stderr,
            )
            self.budget_exhausted = True
            return False

        now = time.monotonic()
        # Drop timestamps older than 60 seconds
        while self.window and now - self.window[0] > 60.0:
            self.window.popleft()

        if len(self.window) >= self.max_per_minute:
            sleep_for = 60.0 - (now - self.window[0]) + 0.1
            if sleep_for > 0:
                print(f"  [VT] Rate limit: sleeping {sleep_for:.1f}s", file=sys.stderr)
                time.sleep(sleep_for)
            # Re-drop stale entries after sleep
            now = time.monotonic()
            while self.window and now - self.window[0] > 60.0:
                self.window.popleft()

        self.window.append(time.monotonic())
        self.daily_count += 1
        return True


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------

def _load_json_cache(path):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def _save_json_cache(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# DNS resolution
# ---------------------------------------------------------------------------

def resolve_hostnames(hostnames, dns_cache):
    """Resolve a list of hostnames to IPs. Updates dns_cache in place."""
    updated = False
    for host in hostnames:
        if host in dns_cache:
            continue
        if _is_ip(host):
            dns_cache[host] = host
            updated = True
            continue
        try:
            ip = socket.gethostbyname(host)
            dns_cache[host] = ip
        except socket.gaierror:
            dns_cache[host] = None
        updated = True

    return updated


# ---------------------------------------------------------------------------
# IPinfo Lite enrichment
# ---------------------------------------------------------------------------

def enrich_ipinfo(ip, token, session):
    """Query IPinfo Lite for ASN + country data.

    Returns dict with keys: asn, as_name, as_domain, country_code, country,
    continent_code. All may be None on failure.
    Free tier fields only — city/region/lat/lon are NOT available without upgrade.
    """
    empty = {
        "asn": None, "as_name": None, "as_domain": None,
        "country_code": None, "country": None, "continent_code": None,
    }
    if not ip:
        return empty

    params = {}
    if token:
        params["token"] = token

    try:
        resp = session.get(
            IPINFO_URL.format(ip=ip),
            params=params,
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code == 404:
            return empty
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        print(f"  [WARN] IPinfo error for {ip}: {exc}", file=sys.stderr)
        return empty

    return {
        "asn": data.get("asn") or None,
        "as_name": data.get("as_name") or None,
        "as_domain": data.get("as_domain") or None,
        "country_code": data.get("country_code") or None,
        "country": data.get("country") or None,
        "continent_code": data.get("continent_code") or None,
    }


# ---------------------------------------------------------------------------
# VirusTotal enrichment
# ---------------------------------------------------------------------------

def enrich_vt_domain(domain, api_key, session, limiter, vt_cache):
    """Query VT for domain reputation + creation date. Respects rate limiter."""
    if domain in vt_cache:
        return vt_cache[domain]

    empty = {
        "vt_malicious": 0, "vt_suspicious": 0, "vt_harmless": 0,
        "vt_creation_date": None, "vt_checked": True,
    }

    if not api_key or not limiter.acquire():
        return {"vt_checked": False}

    try:
        resp = session.get(
            VT_DOMAIN_URL.format(domain=domain),
            headers={"x-apikey": api_key},
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code == 404:
            result = empty
        else:
            resp.raise_for_status()
            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            result = {
                "vt_malicious": stats.get("malicious", 0),
                "vt_suspicious": stats.get("suspicious", 0),
                "vt_harmless": stats.get("harmless", 0),
                "vt_creation_date": attrs.get("creation_date"),
                "vt_checked": True,
            }
    except Exception as exc:
        print(f"  [WARN] VT domain error for {domain}: {exc}", file=sys.stderr)
        result = {"vt_checked": False}

    vt_cache[domain] = result
    return result


def enrich_vt_ip(ip, api_key, session, limiter, vt_cache):
    """Query VT for IP reputation. Respects rate limiter."""
    cache_key = f"ip:{ip}"
    if cache_key in vt_cache:
        return vt_cache[cache_key]

    empty = {
        "vt_malicious": 0, "vt_suspicious": 0, "vt_harmless": 0,
        "vt_creation_date": None, "vt_checked": True,
    }

    if not api_key or not limiter.acquire():
        return {"vt_checked": False}

    try:
        resp = session.get(
            VT_IP_URL.format(ip=ip),
            headers={"x-apikey": api_key},
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code == 404:
            result = empty
        else:
            resp.raise_for_status()
            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            result = {
                "vt_malicious": stats.get("malicious", 0),
                "vt_suspicious": stats.get("suspicious", 0),
                "vt_harmless": stats.get("harmless", 0),
                "vt_creation_date": None,   # IPs don't have a creation_date
                "vt_checked": True,
            }
    except Exception as exc:
        print(f"  [WARN] VT IP error for {ip}: {exc}", file=sys.stderr)
        result = {"vt_checked": False}

    vt_cache[cache_key] = result
    return result


# ---------------------------------------------------------------------------
# Hostname extraction
# ---------------------------------------------------------------------------

def extract_hostnames(raw_records):
    """Return sorted list of unique hostnames from all URLs in raw records."""
    hostnames = set()
    for record in raw_records:
        for url in [record.get("url", "")] + record.get("redirect_chain", []):
            if not url:
                continue
            try:
                host = urlparse(url).hostname or ""
                if host:
                    hostnames.add(host.lower())
            except Exception:
                pass
    return sorted(hostnames)


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

    # Read environment
    ipinfo_token = os.environ.get("IPINFO_TOKEN", "").strip()
    vt_api_key = os.environ.get("VT_API_KEY", "").strip()

    if not vt_api_key:
        print("[WARN] VT_API_KEY not set — VirusTotal enrichment will be skipped.", file=sys.stderr)
    if not ipinfo_token:
        print("[INFO] IPINFO_TOKEN not set — using unauthenticated tier (1000 req/day).", file=sys.stderr)

    # Load inputs
    if not os.path.exists(INPUT_PATH):
        print(f"ERROR: {INPUT_PATH} not found. Run ingest_clickgrab.py first.", file=sys.stderr)
        sys.exit(1)

    with open(INPUT_PATH, "r", encoding="utf-8") as f:
        raw_records = json.load(f)

    dns_cache = _load_json_cache(DNS_CACHE_PATH)
    vt_cache = _load_json_cache(VT_CACHE_PATH)

    # Collect unique hostnames
    hostnames = extract_hostnames(raw_records)
    print(f"Unique hostnames to enrich: {len(hostnames)}")

    # DNS resolution
    print("Resolving hostnames...")
    resolve_hostnames(hostnames, dns_cache)
    _save_json_cache(DNS_CACHE_PATH, dns_cache)

    # Per-hostname enrichment
    limiter = RateLimiter(max_per_minute=VT_RATE_PER_MIN, daily_budget=VT_DAILY_BUDGET)
    enriched = {}
    ipinfo_ok = 0
    ipinfo_failed = 0

    with requests.Session() as session:
        session.headers["User-Agent"] = "detection-chokepoints/enrichment-pipeline"

        for i, host in enumerate(hostnames, 1):
            print(f"  [{i}/{len(hostnames)}] {host}", end=" ", flush=True)
            ip = dns_cache.get(host)

            # IPinfo Lite (country + ASN only on free tier)
            ipinfo_data = {}
            if ip:
                ipinfo_data = enrich_ipinfo(ip, ipinfo_token, session)
                if ipinfo_data.get("asn"):
                    ipinfo_ok += 1
                else:
                    ipinfo_failed += 1
                time.sleep(IPINFO_SLEEP)

            # VirusTotal
            if _is_ip(host):
                vt_data = enrich_vt_ip(host, vt_api_key, session, limiter, vt_cache)
            else:
                vt_data = enrich_vt_domain(host, vt_api_key, session, limiter, vt_cache)

            enriched[host] = {
                "host": host,
                "ip": ip,
                "is_ip": _is_ip(host),
                **ipinfo_data,
                **vt_data,
            }
            print("✓" if vt_data.get("vt_checked") else "–")

            # Persist VT cache after every request so progress survives interruption
            if vt_data.get("vt_checked"):
                _save_json_cache(VT_CACHE_PATH, vt_cache)

            # Stop VT lookups gracefully if budget is exhausted (IPinfo continues)
            if limiter.budget_exhausted:
                print(
                    f"  VT budget exhausted after {limiter.daily_count} requests. "
                    "Remaining hosts will have ipinfo data only.",
                    file=sys.stderr,
                )

    # Save final caches
    _save_json_cache(DNS_CACHE_PATH, dns_cache)
    _save_json_cache(VT_CACHE_PATH, vt_cache)

    # Build output: merge enrichment back onto raw URL records
    output_records = []
    for record in raw_records:
        url = record.get("url", "")
        host = ""
        try:
            host = urlparse(url).hostname or ""
            host = host.lower()
        except Exception:
            pass
        enr = enriched.get(host, {})
        output_records.append({**record, "enrichment": enr})

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(output_records, f, indent=2, ensure_ascii=False)

    print(f"\nWritten: {OUTPUT_PATH} ({len(output_records)} records)")
    print(f"VT requests used: {limiter.daily_count}/{VT_DAILY_BUDGET}")

    _write_run_log(CACHE_DIR, "enrich_infra", {
        "ipinfo": {
            "token_present": bool(ipinfo_token),
            "queried": ipinfo_ok + ipinfo_failed,
            "enriched": ipinfo_ok,
            "failed": ipinfo_failed,
        },
        "virustotal": {
            "api_key_present": bool(vt_api_key),
            "requests_used": limiter.daily_count,
            "budget_exhausted": limiter.budget_exhausted,
        },
        "records_enriched": len(output_records),
        "status": "ok",
    })


if __name__ == "__main__":
    main()
