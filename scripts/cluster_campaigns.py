#!/usr/bin/env python3
"""
cluster_campaigns.py
Group domains from the enrichment pipeline into probable campaigns using
a composite key of (favicon_hash, ASN, registration_week).

Two domains share a cluster if they share at least 2 of 3 signals.
Minimum cluster size: 3 domains (singletons/pairs are noise at weekly granularity).

Cluster IDs: CLUSTER-{YYYY-WW}-{ASN}

Reads:  cache/enriched_infra.json
Writes: cache/campaign_clusters.json

Environment: FAVICON_TIMEOUT, FAVICON_CONCURRENCY (see .env.example)
"""

import asyncio
import base64
import collections
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import httpx
import mmh3
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT   = Path(__file__).parent.parent
CACHE_DIR   = REPO_ROOT / "cache"
INPUT_PATH  = CACHE_DIR / "enriched_infra.json"
OUTPUT_PATH = CACHE_DIR / "campaign_clusters.json"

# ---------------------------------------------------------------------------
# Constants (overridable via .env)
# ---------------------------------------------------------------------------

FAVICON_TIMEOUT     = float(os.getenv("FAVICON_TIMEOUT", "5"))
FAVICON_CONCURRENCY = int(os.getenv("FAVICON_CONCURRENCY", "10"))

# Known common/default favicon hashes that produce false cluster merges.
COMMON_FAVICON_BLOCKLIST = {
    -1507574776,   # Apache default
    -335242539,    # Nginx default
    -1026074561,   # cPanel/WHM default
    116323821,     # WordPress default
    -1269494984,   # Cloudflare generic
}

# ---------------------------------------------------------------------------
# Favicon hash (Shodan-compatible algorithm)
# ---------------------------------------------------------------------------

async def compute_favicon_hash(domain: str, client: httpx.AsyncClient, sem: asyncio.Semaphore):
    """Fetch /favicon.ico and return Murmur3 hash (Shodan algorithm).

    Returns None on any error or if the hash is on the blocklist.
    RFC 2045 base64 (76-char line wrapping + trailing newline).
    """
    url = f"https://{domain}/favicon.ico"
    try:
        async with sem:
            resp = await client.get(url, timeout=FAVICON_TIMEOUT, follow_redirects=True)
        resp.raise_for_status()
        if not resp.content:
            return None
        b64 = base64.b64encode(resp.content).decode("utf-8")
        b64_wrapped = re.sub("(.{76})", "\\1\n", b64) + "\n"
        h = mmh3.hash(b64_wrapped)
        return None if h in COMMON_FAVICON_BLOCKLIST else h
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _iso_week(creation_date):
    """Convert a VT creation_date (Unix timestamp or ISO string) to ISO week 'YYYY-WW'."""
    if creation_date is None:
        return None
    try:
        if isinstance(creation_date, (int, float)):
            dt = datetime.fromtimestamp(creation_date, tz=timezone.utc)
        else:
            s = str(creation_date).strip()
            for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"):
                try:
                    dt = datetime.strptime(s[:19], fmt[:len(s[:19])])
                    break
                except ValueError:
                    continue
            else:
                return None
        iso = dt.isocalendar()
        return f"{iso[0]:04d}-{iso[1]:02d}"
    except Exception:
        return None


def _extract_domains(enriched_records):
    """Build a dict of domain → {asn, registration_week, date_first, date_last}."""
    domain_info = {}
    for record in enriched_records:
        url = record.get("url", "")
        enr = record.get("enrichment", {})
        try:
            host = (urlparse(url).hostname or "").lower()
        except Exception:
            continue
        if not host:
            continue

        asn          = enr.get("asn") or None
        creation_date = enr.get("vt_creation_date")
        week         = _iso_week(creation_date)
        record_date  = record.get("date", "")

        if host not in domain_info:
            domain_info[host] = {
                "asn": asn,
                "registration_week": week,
                "date_first": record_date,
                "date_last": record_date,
                "country_codes": set(),
            }
        else:
            existing = domain_info[host]
            if record_date and (not existing["date_first"] or record_date < existing["date_first"]):
                existing["date_first"] = record_date
            if record_date and (not existing["date_last"] or record_date > existing["date_last"]):
                existing["date_last"] = record_date
        if enr.get("country_code"):
            domain_info[host]["country_codes"].add(enr["country_code"])

    for info in domain_info.values():
        info["country_codes"] = sorted(info["country_codes"])

    return domain_info


# ---------------------------------------------------------------------------
# Clustering
# ---------------------------------------------------------------------------

def _shared_signals(a_info, a_fav, b_info, b_fav):
    """Return count of signals shared between domains a and b (max 3)."""
    count = 0
    if a_fav is not None and b_fav is not None and a_fav == b_fav:
        count += 1
    if a_info["asn"] and b_info["asn"] and a_info["asn"] == b_info["asn"]:
        count += 1
    if (
        a_info["registration_week"]
        and b_info["registration_week"]
        and a_info["registration_week"] == b_info["registration_week"]
    ):
        count += 1
    return count


def cluster_domains(domain_info, favicon_hashes):
    """Build clusters using union-find over the domain graph.

    Two domains are linked if they share ≥2 of 3 signals.
    Returns list of cluster dicts (only those with ≥3 members).
    """
    domains = list(domain_info.keys())
    n = len(domains)

    parent = list(range(n))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x, y):
        parent[find(x)] = find(y)

    idx = {d: i for i, d in enumerate(domains)}

    for i in range(n):
        for j in range(i + 1, n):
            da, db = domains[i], domains[j]
            if _shared_signals(domain_info[da], favicon_hashes.get(da),
                               domain_info[db], favicon_hashes.get(db)) >= 2:
                union(i, j)

    groups: dict = collections.defaultdict(list)
    for i, d in enumerate(domains):
        groups[find(i)].append(d)

    clusters = []
    for members in groups.values():
        if len(members) < 3:
            continue

        asns  = [domain_info[d]["asn"] for d in members if domain_info[d]["asn"]]
        weeks = [domain_info[d]["registration_week"] for d in members if domain_info[d]["registration_week"]]
        favs  = [favicon_hashes.get(d) for d in members if favicon_hashes.get(d) is not None]

        rep_asn  = collections.Counter(asns).most_common(1)[0][0] if asns else "UNKNOWN"
        rep_week = collections.Counter(weeks).most_common(1)[0][0] if weeks else "unknown"
        rep_fav  = collections.Counter(favs).most_common(1)[0][0] if favs else None

        cluster_id  = f"CLUSTER-{rep_week}-{rep_asn}"
        dates_first = [domain_info[d]["date_first"] for d in members if domain_info[d]["date_first"]]
        dates_last  = [domain_info[d]["date_last"]  for d in members if domain_info[d]["date_last"]]
        countries   = sorted({cc for d in members for cc in domain_info[d].get("country_codes", [])})

        clusters.append({
            "id": cluster_id,
            "asn": rep_asn,
            "favicon_hash": rep_fav,
            "registration_week": rep_week,
            "domain_count": len(members),
            "first_seen": min(dates_first) if dates_first else None,
            "last_seen":  max(dates_last)  if dates_last  else None,
            "countries": countries,
            "domains": sorted(members),
        })

    clusters.sort(key=lambda c: c["domain_count"], reverse=True)
    return clusters


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

    if not INPUT_PATH.exists():
        print(f"ERROR: {INPUT_PATH} not found. Run enrich_infra.py first.", file=sys.stderr)
        sys.exit(1)

    enriched_records = json.loads(INPUT_PATH.read_text(encoding="utf-8"))
    domain_info = _extract_domains(enriched_records)
    domains = list(domain_info.keys())
    print(f"Unique domains to cluster: {len(domains)}")

    # Fetch favicon hashes concurrently
    print(f"Fetching favicons (concurrency={FAVICON_CONCURRENCY})...")
    sem = asyncio.Semaphore(FAVICON_CONCURRENCY)
    headers = {"User-Agent": "detection-chokepoints/enrichment-pipeline"}

    async with httpx.AsyncClient(headers=headers) as client:
        hashes = await asyncio.gather(*[
            compute_favicon_hash(d, client, sem) for d in domains
        ])

    favicon_hashes = {}
    for domain, h in zip(domains, hashes):
        if h is not None:
            favicon_hashes[domain] = h
            print(f"  {domain}: {h}")
        else:
            print(f"  {domain}: (no favicon)")

    print(f"Favicons obtained: {len(favicon_hashes)}/{len(domains)}")

    print("Clustering...")
    clusters = cluster_domains(domain_info, favicon_hashes)
    print(f"Clusters identified (≥3 domains): {len(clusters)}")
    for c in clusters:
        print(f"  {c['id']}: {c['domain_count']} domains")

    OUTPUT_PATH.write_text(
        json.dumps(clusters, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"Written: {OUTPUT_PATH}")

    _write_run_log(CACHE_DIR, "cluster_campaigns", {
        "domains_processed": len(domains),
        "favicons_obtained": len(favicon_hashes),
        "clusters_identified": len(clusters),
        "status": "ok",
    })


if __name__ == "__main__":
    asyncio.run(main())
