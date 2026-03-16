#!/usr/bin/env python3
"""
update_masq_infra.py — Weekly pipeline for masq-infra trend data.

Queries URLScan, crt.sh, Shodan, Validin, URLHaus, MalwareBazaar, and VirusTotal
to populate _data/masq_infra.json with real-world stats and payload/lure data.

Usage:
    python scripts/update_masq_infra.py           # write to _data/masq_infra.json
    python scripts/update_masq_infra.py --dry-run # write to /tmp/masq_infra_test.json
"""

import argparse
import base64
import json
import os
import re
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import mmh3
import requests

# ── Configuration ──────────────────────────────────────────────────────────────

BRANDS = [
    "7-zip", "winrar", "vlc", "notepad-plus", "audacity",
    "obs-studio", "handbrake", "filezilla", "putty", "winscp",
    "rufus", "crystaldiskinfo", "hwinfo", "cpu-z", "gpu-z",
    "blender", "gimp", "inkscape", "krita", "libreoffice",
    "anydesk", "teamviewer", "telegram", "discord", "signal",
    "chatgpt", "midjourney", "claude",
    "steam", "epicgames", "minecraft", "roblox",
]

# Pre-computed brand favicon URLs. Hashes are fetched at runtime so they remain
# accurate even when brands update their icons.
# Credit budget: ~11 brands × 1 Shodan query credit each = ~11 credits/week.
BRAND_FAVICON_SEEDS = {
    "7-zip":      "https://www.7-zip.org/favicon.ico",
    "winrar":     "https://www.win-rar.com/favicon.ico",
    "vlc":        "https://www.videolan.org/favicon.ico",
    "notepad++":  "https://notepad-plus-plus.org/favicon.ico",
    "obs-studio": "https://obsproject.com/favicon.ico",
    "audacity":   "https://www.audacityteam.org/favicon.ico",
    "putty":      "https://www.putty.org/favicon.ico",
    "winscp":     "https://winscp.net/favicon.ico",
    "gimp":       "https://www.gimp.org/favicon.ico",
    "discord":    "https://discord.com/favicon.ico",
    "telegram":   "https://telegram.org/favicon.ico",
}

LURE_PATTERNS = {
    "fake_ai_tool":  ["chatgpt", "gpt", "midjourney", "claude", "gemini", "copilot"],
    "game_crack":    ["crack", "cheat", "hack", "mod", "trainer", "keygen", "warez"],
    "media_piracy":  ["movie", "series", "episode", "codec", "torrent", "mkv", "iptv"],
    "fake_update":   ["update", "patch", "upgrade", "latest", "v2", "new"],
    "fake_tool":     ["tool", "cleaner", "booster", "optimizer", "driver", "fix"],
    "fake_software": ["install", "setup", "download", "free", "portable", "official", "get"],
}

LOOKBACK_DAYS             = 30
URLSCAN_RATE_LIMIT_SLEEP  = 2    # seconds between brand queries
MB_RATE_LIMIT_SLEEP       = 1
SHODAN_RATE_LIMIT_SLEEP   = 1    # 1 req/sec; each search costs 1 credit per 100 result pages
VALIDIN_RATE_LIMIT_SLEEP  = 1
CRTSH_RATE_LIMIT_SLEEP    = 1
SHODAN_MAX_RESULTS        = 100  # cap per favicon hash query to protect credits

URLSCAN_SEARCH_URL = "https://urlscan.io/api/v1/search/"
MB_API_URL         = "https://mb-api.abuse.ch/api/v1/"
VT_FILES_URL       = "https://www.virustotal.com/api/v3/files/{sha256}"
VALIDIN_DNS_URL    = "https://api.validin.com/api/axfr/dns/history/A/{domain}"
URLHAUS_RECENT_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
URLHAUS_TAG_URL    = "https://urlhaus-api.abuse.ch/v1/tag/"
CRTSH_URL          = "https://crt.sh/?q={domain}&output=json"


# ── Favicon hash (must match Shodan's algorithm exactly) ──────────────────────

def compute_favicon_hash(url: str) -> int | None:
    """
    Fetch a favicon and compute its Murmur3 hash using Shodan's exact algorithm:
    RFC 2045 base64 (76-char line wrapping) with a trailing newline.
    """
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        b64 = base64.b64encode(r.content).decode("utf-8")
        b64_wrapped = re.sub("(.{76})", "\\1\n", b64) + "\n"
        return mmh3.hash(b64_wrapped)
    except Exception as e:
        print(f"  [WARN] Could not fetch favicon {url}: {e}", file=sys.stderr)
        return None


# ── URLScan collector ──────────────────────────────────────────────────────────

def _urlscan_request_with_backoff(url: str, params: dict, headers: dict) -> dict | None:
    for attempt in range(4):
        r = requests.get(url, params=params, headers=headers, timeout=20)
        if r.status_code == 429:
            wait = 2 ** (attempt + 1)
            print(f"  [WARN] URLScan 429 — waiting {wait}s", file=sys.stderr)
            time.sleep(wait)
            continue
        if r.status_code in (400, 403):
            # 403: query requires elevated API tier.
            # 400: malformed request — most commonly a bad search_after cursor;
            #      stop paginating for this brand rather than crashing.
            print(
                f"  [WARN] URLScan {r.status_code} — stopping pagination. "
                f"URL: {r.url}",
                file=sys.stderr,
            )
            return None
        r.raise_for_status()
        return r.json()
    return None


def collect_urlscan(api_key: str) -> list[dict]:
    """
    Query URLScan for confirmed malicious scans of brand-impersonating domains.
    Returns a deduplicated list of raw records (keyed by domain, earliest first_seen kept).
    """
    headers = {"API-Key": api_key}
    seen_domains: dict[str, dict] = {}

    for brand in BRANDS:
        # verdicts.malicious:true requires an elevated URLScan API tier (403 on free keys).
        # Filter malicious results client-side from verdicts.overall.malicious instead.
        query = (
            f'page.domain:*{brand}* '
            f'AND date:>now-{LOOKBACK_DAYS}d'
        )
        params: dict = {"q": query, "size": 100}
        brand_count = 0

        while True:
            data = _urlscan_request_with_backoff(URLSCAN_SEARCH_URL, params, headers)
            if not data:
                break

            results = data.get("results", [])
            for item in results:
                page = item.get("page", {})
                domain = page.get("domain", "")
                if not domain:
                    continue

                # Store URLScan's verdict for informational use in recent_samples,
                # but do NOT gate on it — verdicts.overall.malicious is only populated
                # when URLScan's scanner or community explicitly flags the domain, which
                # misses many impersonation sites scanned before weaponization.
                verdicts = item.get("verdicts", {})
                urlscan_malicious = (
                    verdicts.get("overall", {}).get("malicious", False)
                    or verdicts.get("urlscan", {}).get("malicious", False)
                )

                payload_sha256 = None
                download_url = None
                mime_type = None
                lists = item.get("lists", {})
                for h in lists.get("hashes", []):
                    if str(h.get("mimeType", "")).startswith("application/"):
                        payload_sha256 = h.get("sha256")
                        download_url   = h.get("url")
                        mime_type      = h.get("mimeType")
                        break

                rec = {
                    "domain":             domain,
                    "asnname":            page.get("asnname", "Unknown"),
                    "first_seen":         item.get("task", {}).get("time", ""),
                    "page_title":         page.get("title", ""),
                    "payload_sha256":     payload_sha256,
                    "download_url":       download_url,
                    "mime_type":          mime_type,
                    "urlscan_malicious":  urlscan_malicious,
                }

                # Keep earliest first_seen per domain
                if domain not in seen_domains:
                    seen_domains[domain] = rec
                else:
                    existing_ts = seen_domains[domain]["first_seen"]
                    if rec["first_seen"] and rec["first_seen"] < existing_ts:
                        seen_domains[domain] = rec

            brand_count += len(results)
            if not data.get("has_more") or brand_count >= 500:
                break

            # Bug guards: results may be empty even when has_more is true (edge case);
            # sort may be an explicit empty array rather than a missing key.
            if not results:
                break
            sort_val = results[-1].get("sort") or []
            if not sort_val:
                break
            # Pass the full sort array so requests encodes it as repeated params:
            # search_after=v1&search_after=v2 — required by URLScan's Elasticsearch
            # backend. Passing only sort_val[0] produces a 400 on page 2+.
            params["search_after"] = sort_val

        time.sleep(URLSCAN_RATE_LIMIT_SLEEP)
        print(f"  URLScan: {brand} → {brand_count} result(s)", file=sys.stderr)

    return list(seen_domains.values())


# ── Lure classifier ────────────────────────────────────────────────────────────

def classify_lure(download_url: str, page_title: str, domain: str) -> str:
    """
    Classify a record into a lure category based on URL, title, and domain.
    Precedence: fake_ai_tool > game_crack > media_piracy > fake_update > fake_tool > fake_software
    Any argument may be None (e.g. download_url when no payload was found).
    """
    text = " ".join(v or "" for v in [download_url, page_title, domain]).lower()
    for category, keywords in LURE_PATTERNS.items():
        if any(kw in text for kw in keywords):
            return category
    return "unknown"


# ── MalwareBazaar enricher ─────────────────────────────────────────────────────

def enrich_malwarebazaar(sha256: str, api_key: str) -> dict | None:
    if not sha256:
        return None
    try:
        data = {"query": "get_info", "hash": sha256}
        headers = {"API-KEY": api_key} if api_key else {}
        r = requests.post(MB_API_URL, data=data, headers=headers, timeout=15)
        r.raise_for_status()
        resp = r.json()
        if resp.get("query_status") != "hash_info":
            return None
        info = resp.get("data", [{}])[0]
        return {
            "malware_family": info.get("signature"),
            "file_type":      info.get("file_type"),
            "mb_tags":        info.get("tags", []) or [],
        }
    except Exception:
        return None
    finally:
        time.sleep(MB_RATE_LIMIT_SLEEP)


# ── VirusTotal fallback enricher ───────────────────────────────────────────────

def enrich_virustotal(sha256: str, api_key: str) -> dict | None:
    if not sha256 or not api_key:
        return None
    try:
        r = requests.get(
            VT_FILES_URL.format(sha256=sha256),
            headers={"x-apikey": api_key},
            timeout=15,
        )
        if r.status_code == 404:
            return None
        r.raise_for_status()
        attrs = r.json().get("data", {}).get("attributes", {})
        ptc = attrs.get("popular_threat_classification", {})
        return {
            "malware_family": ptc.get("suggested_threat_label"),
            "file_type":      attrs.get("type_tag"),
            "mb_tags":        [],
        }
    except Exception:
        return None


# ── Shodan favicon cluster collector ──────────────────────────────────────────

def collect_shodan_favicon_clusters(api_key: str) -> list[dict]:
    """
    Fetch brand favicons, compute their MMH3 hashes, and query Shodan for
    infrastructure serving those hashes (impersonators).

    Credit budget: ~11 brand seeds × 1 query credit each ≈ 11 credits/week.
    api.count() is free (no credit cost).
    """
    try:
        import shodan as shodan_lib
    except ImportError:
        print("[WARN] shodan package not installed — skipping favicon clustering", file=sys.stderr)
        return []

    api = shodan_lib.Shodan(api_key)
    clusters: list[dict] = []

    for brand, favicon_url in BRAND_FAVICON_SEEDS.items():
        print(f"  Shodan: computing favicon hash for {brand} ...", file=sys.stderr)
        hash_val = compute_favicon_hash(favicon_url)
        if hash_val is None:
            continue

        try:
            count_resp = api.count(f"http.favicon.hash:{hash_val}")
            total = count_resp.get("total", 0)
            print(f"  Shodan: {brand} hash={hash_val} total_hits={total}", file=sys.stderr)
            if total == 0:
                continue

            results = []
            brand_canonical_tld = favicon_url.split("/")[2]  # e.g. "www.7-zip.org"

            for banner in api.search_cursor(f"http.favicon.hash:{hash_val}"):
                hostnames = banner.get("hostnames", [])
                # Exclude the legitimate brand's own servers
                if any(brand_canonical_tld in h for h in hostnames):
                    continue
                results.append({
                    "ip":        banner.get("ip_str"),
                    "hostnames": hostnames,
                    "org":       banner.get("org"),
                    "asn":       banner.get("asn"),
                })
                if len(results) >= SHODAN_MAX_RESULTS:
                    break

            # Log remaining credits
            try:
                info = api.info()
                print(
                    f"  Shodan credits remaining: {info.get('query_credits', '?')}",
                    file=sys.stderr,
                )
            except Exception:
                pass

            if results:
                sample_hosts = [
                    h for r in results[:5] for h in (r["hostnames"] or [r["ip"]])
                ][:5]
                clusters.append({
                    "hash":         hash_val,
                    "brand":        brand,
                    "count":        len(results),
                    "sample_hosts": sample_hosts,
                })

            time.sleep(SHODAN_RATE_LIMIT_SLEEP)

        except Exception as e:
            print(f"  [WARN] Shodan error for {brand}: {e}", file=sys.stderr)

    return sorted(clusters, key=lambda c: c["count"], reverse=True)


# ── Validin pDNS delta collector ───────────────────────────────────────────────

def collect_validin_dns_delta(domains: list[str], api_key: str) -> dict:
    """
    For each domain, fetch A record history from Validin and cert issuance time
    from crt.sh, then compute the hours between cert issuance and first DNS resolution.
    """
    if not api_key:
        print("[WARN] VALIDIN_API_KEY not set — skipping pDNS delta", file=sys.stderr)
        return {}

    headers = {"Authorization": f"Bearer {api_key}"}
    deltas: list[float] = []
    fast_deploy_count = 0
    checked = 0

    for domain in domains[:100]:
        try:
            # Validin: first DNS resolution timestamp
            r = requests.get(
                VALIDIN_DNS_URL.format(domain=domain),
                headers=headers,
                timeout=15,
            )
            r.raise_for_status()
            records = r.json().get("response", {}).get("records", [])
            if not records:
                continue
            first_dns_ts = min(
                rec["first_seen"] for rec in records if rec.get("first_seen")
            )
            first_dns_dt = datetime.fromisoformat(first_dns_ts.replace("Z", "+00:00"))

            # crt.sh: cert issuance timestamp
            cr = requests.get(CRTSH_URL.format(domain=domain), timeout=15)
            cr.raise_for_status()
            certs = cr.json()
            if not certs:
                continue
            not_before_str = min(c["not_before"] for c in certs if c.get("not_before"))
            not_before_dt = datetime.fromisoformat(not_before_str.replace(" ", "T") + "+00:00")

            delta_hours = (first_dns_dt - not_before_dt).total_seconds() / 3600
            deltas.append(delta_hours)
            if delta_hours <= 6:
                fast_deploy_count += 1
            checked += 1

        except requests.exceptions.ConnectionError as e:
            # DNS failure means the API is unreachable from this environment.
            # Break immediately — no point trying remaining 99 domains.
            if "NameResolutionError" in str(e) or "Failed to resolve" in str(e):
                print(
                    "[WARN] Validin API unreachable (DNS resolution failed) — "
                    "skipping pDNS delta. Check that api.validin.com is accessible "
                    "from this runner.",
                    file=sys.stderr,
                )
                break
            print(f"  [WARN] Validin connection error for {domain}: {e}", file=sys.stderr)
        except Exception as e:
            print(f"  [WARN] Validin/crt.sh error for {domain}: {e}", file=sys.stderr)
        finally:
            time.sleep(VALIDIN_RATE_LIMIT_SLEEP)

    if not deltas:
        return {}

    return {
        "domain_to_resolution_hours_median": round(statistics.median(deltas), 1),
        "fast_deploy_pct": round(fast_deploy_count / checked * 100, 1),
        "total_checked": checked,
    }


# ── URLHaus delivery URL collector ─────────────────────────────────────────────

def collect_urlhaus(brands: list[str], api_key: str = "") -> list[dict]:
    """
    Collect confirmed malware delivery URLs from URLHaus that match brand names.
    api_key is optional but required since abuse.ch moved to Auth-Key authentication.
    Register for a free key at https://abuse.ch/
    """
    records: list[dict] = []
    seen_urls: set[str] = set()
    # Auth-Key header — required on all /v1/ endpoints since late 2024.
    # Requests without it receive 401. Key is free at abuse.ch.
    headers = {"Auth-Key": api_key} if api_key else {}

    # Recent URLs feed
    try:
        r = requests.get(URLHAUS_RECENT_URL, timeout=20, headers=headers)
        r.raise_for_status()
        for item in r.json().get("urls", []):
            url = item.get("url", "")
            host = item.get("host", "")
            combined = (url + host).lower()
            if any(brand in combined for brand in brands):
                if url not in seen_urls:
                    seen_urls.add(url)
                    records.append({
                        "url":           url,
                        "host":          host,
                        "tags":          item.get("tags") or [],
                        "threat":        item.get("threat"),
                        "date_added":    item.get("date_added"),
                        "urlhaus_status": item.get("url_status"),
                    })
    except Exception as e:
        print(f"  [WARN] URLHaus recent feed error: {e}", file=sys.stderr)

    time.sleep(2)

    # Per-tag queries for common malware families
    malware_tags = ["Lumma", "RedLine", "Vidar", "StealC", "AsyncRAT", "Remcos", "AgentTesla"]
    for tag in malware_tags:
        try:
            r = requests.post(URLHAUS_TAG_URL, data={"tag": tag}, timeout=15, headers=headers)
            r.raise_for_status()
            for item in r.json().get("urls", []):
                url = item.get("url", "")
                host = item.get("host", "")
                combined = (url + host).lower()
                if any(brand in combined for brand in brands):
                    if url not in seen_urls:
                        seen_urls.add(url)
                        records.append({
                            "url":           url,
                            "host":          host,
                            "tags":          item.get("tags") or [],
                            "threat":        item.get("threat"),
                            "date_added":    item.get("date_added"),
                            "urlhaus_status": item.get("url_status"),
                        })
        except Exception as e:
            print(f"  [WARN] URLHaus tag '{tag}' error: {e}", file=sys.stderr)
        time.sleep(2)

    print(f"  URLHaus: {len(records)} matching records", file=sys.stderr)
    return records


# ── crt.sh TLS issuer collector ────────────────────────────────────────────────

def collect_crtsh_stats(domains: list[str]) -> dict:
    """
    Query crt.sh for each domain and compute Let's Encrypt issuance percentage.
    Limited to first 100 domains to avoid rate limits.
    """
    le_count = 0
    total = 0
    le_names = ("let's encrypt", "letsencrypt", "e1", "e2", "r3", "r4", "r10", "r11")

    for domain in domains[:100]:
        try:
            r = requests.get(CRTSH_URL.format(domain=domain), timeout=15)
            r.raise_for_status()
            certs = r.json()
            if certs:
                total += 1
                issuer_name = (certs[0].get("issuer_name") or "").lower()
                if any(le in issuer_name for le in le_names):
                    le_count += 1
        except Exception:
            pass
        time.sleep(CRTSH_RATE_LIMIT_SLEEP)

    if total == 0:
        return {"lets_encrypt_pct": 0, "total_checked": 0}

    return {
        "lets_encrypt_pct": round(le_count / total * 100, 1),
        "total_checked": total,
    }


# ── Stats aggregator ───────────────────────────────────────────────────────────

def _top_n(items: list[tuple[str, int]], n: int = 10) -> list[dict]:
    total = sum(c for _, c in items)
    return [
        {"name": k, "count": v, "pct": round(v / total * 100, 1) if total else 0}
        for k, v in sorted(items, key=lambda x: x[1], reverse=True)[:n]
    ]


def aggregate(
    records: list[dict],
    crt_stats: dict,
    shodan_clusters: list[dict],
    validin_stats: dict,
    urlhaus_records: list[dict],
) -> dict:
    from collections import Counter

    # Hosting providers
    asn_counter: Counter = Counter()
    for r in records:
        asn = (r.get("asnname") or "Unknown").strip()
        if asn:
            asn_counter[asn] += 1
    hosting_providers = _top_n(list(asn_counter.items()))

    # Lure types
    lure_counter: Counter = Counter(r.get("lure_type", "unknown") for r in records)
    lure_total = sum(lure_counter.values())
    lure_types = [
        {"tag": k, "count": v, "pct": round(v / lure_total * 100, 1) if lure_total else 0}
        for k, v in lure_counter.most_common()
    ]

    # Payload families
    family_counter: Counter = Counter(
        r["malware_family"] for r in records if r.get("malware_family")
    )
    payload_families = _top_n(list(family_counter.items()))
    for item in payload_families:
        item["family"] = item.pop("name")

    # Payload file types
    type_counter: Counter = Counter(
        r["file_type"] for r in records if r.get("file_type")
    )
    payload_file_types = _top_n(list(type_counter.items()))
    for item in payload_file_types:
        item["type"] = item.pop("name")

    # URLHaus tags aggregation
    tag_counter: Counter = Counter()
    for u in urlhaus_records:
        for tag in u.get("tags", []):
            tag_counter[tag] += 1
    urlhaus_tags = [
        {"tag": k, "count": v}
        for k, v in tag_counter.most_common(20)
    ]

    # Recent samples — last 20 by first_seen desc
    sorted_records = sorted(
        records,
        key=lambda r: r.get("first_seen") or "",
        reverse=True,
    )
    recent_samples = [
        {
            "domain":         r.get("domain"),
            "asn":            r.get("asnname"),
            "lure_type":      r.get("lure_type"),
            "payload_sha256": r.get("payload_sha256"),
            "malware_family": r.get("malware_family"),
            "file_type":      r.get("file_type"),
            "first_seen":     r.get("first_seen"),
            "urlhaus_tags":   r.get("urlhaus_tags", []),
        }
        for r in sorted_records[:20]
    ]

    # Favicon stats
    total_shodan_hits = sum(c["count"] for c in shodan_clusters)
    favicon_reuse_pct = 0.0
    if records:
        favicon_reuse_pct = round(min(total_shodan_hits / len(records) * 100, 100), 1)

    # Favicon clusters — top 10
    favicon_clusters = [
        {
            "hash":         c["hash"],
            "brand":        c["brand"],
            "count":        c["count"],
            "sample_hosts": c.get("sample_hosts", []),
        }
        for c in shodan_clusters[:10]
    ]

    return {
        "meta": {
            "last_updated":  datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "lookback_days": LOOKBACK_DAYS,
            "sample_size":   len(records),
        },
        "stats": {
            "tls_lets_encrypt_pct":              crt_stats.get("lets_encrypt_pct", 0),
            "domain_to_resolution_hours_median": validin_stats.get("domain_to_resolution_hours_median", 0),
            "favicon_reuse_pct":                 favicon_reuse_pct,
            "favicon_clusters_found":            len(shodan_clusters),
        },
        "hosting_providers": hosting_providers,
        "lure_types":        lure_types,
        "payload_families":  payload_families,
        "payload_file_types": payload_file_types,
        "urlhaus_tags":      urlhaus_tags,
        "favicon_clusters":  favicon_clusters,
        "recent_samples":    recent_samples,
    }


# ── Main entrypoint ────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Update masq-infra trend data")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Write output to /tmp/masq_infra_test.json instead of _data/masq_infra.json",
    )
    args = parser.parse_args()

    # API keys
    urlscan_key  = os.environ.get("URLSCAN_API_KEY",  "").strip()
    shodan_key   = os.environ.get("SHODAN_API_KEY",   "").strip()
    mb_key       = os.environ.get("MB_API_KEY",       "").strip()
    vt_key       = os.environ.get("VT_API_KEY",       "").strip()
    validin_key  = os.environ.get("VALIDIN_API_KEY",  "").strip()
    urlhaus_key  = os.environ.get("URLHAUS_API_KEY",  "").strip()
    if not urlhaus_key:
        print("[WARN] URLHAUS_API_KEY not set — URLHaus queries will be skipped (401)", file=sys.stderr)

    if not urlscan_key:
        print("[ERROR] URLSCAN_API_KEY is required", file=sys.stderr)
        sys.exit(1)

    output_path = (
        Path("/tmp/masq_infra_test.json") if args.dry_run
        else Path("_data/masq_infra.json")
    )

    # Read existing file as fallback
    existing_data: dict = {}
    if output_path.exists():
        try:
            existing_data = json.loads(output_path.read_text())
        except Exception:
            pass

    # --- Collect ---
    print("[1/6] Collecting URLScan results ...", file=sys.stderr)
    raw_records = collect_urlscan(urlscan_key)

    if not raw_records:
        print(
            "[ERROR] URLScan returned 0 results for all brands. "
            "Keeping existing data file unchanged.",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"[2/6] Collecting URLHaus records ...", file=sys.stderr)
    urlhaus_records = collect_urlhaus(BRANDS, urlhaus_key)

    # --- Enrich ---
    print(f"[3/6] Enriching {len(raw_records)} records ...", file=sys.stderr)
    enriched: list[dict] = []
    for rec in raw_records:
        sha256 = rec.get("payload_sha256")
        enrichment: dict = {}
        if sha256:
            enrichment = enrich_malwarebazaar(sha256, mb_key) or {}
            if not enrichment and vt_key:
                enrichment = enrich_virustotal(sha256, vt_key) or {}
        rec.update(enrichment)
        rec["lure_type"] = classify_lure(
            rec.get("download_url", ""),
            rec.get("page_title", ""),
            rec.get("domain", ""),
        )
        # Cross-reference URLHaus tags
        matching_uh = [u for u in urlhaus_records if rec.get("domain") in u.get("url", "")]
        rec["urlhaus_tags"] = list({t for u in matching_uh for t in u.get("tags", [])})
        enriched.append(rec)

    # --- Infrastructure stats ---
    domains = [r["domain"] for r in enriched]

    print("[4/6] Collecting crt.sh TLS stats ...", file=sys.stderr)
    crt_stats = collect_crtsh_stats(domains)

    print("[5/6] Collecting Shodan favicon clusters ...", file=sys.stderr)
    if shodan_key:
        shodan_clusters = collect_shodan_favicon_clusters(shodan_key)
    else:
        print("[WARN] SHODAN_API_KEY not set — skipping favicon clustering", file=sys.stderr)
        shodan_clusters = []

    print("[6/6] Collecting Validin pDNS delta ...", file=sys.stderr)
    validin_stats = collect_validin_dns_delta(domains, validin_key) if validin_key else {}

    # --- Aggregate and write ---
    output = aggregate(enriched, crt_stats, shodan_clusters, validin_stats, urlhaus_records)

    try:
        output_path.write_text(json.dumps(output, indent=2, default=str))
        print(
            f"\nDone. Written {len(enriched)} records to {output_path}",
            file=sys.stderr,
        )
    except Exception as e:
        print(f"[ERROR] Failed to write output: {e}", file=sys.stderr)
        if existing_data:
            print("[INFO] Keeping existing data file unchanged.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
