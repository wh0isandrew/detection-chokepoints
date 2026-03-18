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

Environment: none required (network calls only for favicon fetches)
"""

import base64
import collections
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import mmh3
import requests

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE_DIR = os.path.join(REPO_ROOT, "cache")

INPUT_PATH = os.path.join(CACHE_DIR, "enriched_infra.json")
OUTPUT_PATH = os.path.join(CACHE_DIR, "campaign_clusters.json")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FAVICON_TIMEOUT = 5
FAVICON_SLEEP = 0.1   # 100 ms between favicon fetches

# Known common/default favicon hashes that produce false cluster merges.
# Let's Encrypt doesn't serve a favicon of its own, but common CMS/framework
# defaults do.  Extend this list as false positives are discovered.
COMMON_FAVICON_BLOCKLIST = {
    # Apache default (blank or apache feather)
    -1507574776,
    # Nginx default (blank)
    -335242539,
    # cPanel/WHM default
    -1026074561,
    # WordPress default
    116323821,
    # Cloudflare 1.1.1.1 / generic "no favicon" redirects to CF
    -1269494984,
}

# ---------------------------------------------------------------------------
# Favicon hash (Shodan-compatible algorithm, reused from update_masq_infra.py)
# ---------------------------------------------------------------------------

def compute_favicon_hash(domain, session):
    """Fetch /favicon.ico and return Murmur3 hash (Shodan algorithm).

    Returns None on any error — callers must handle None gracefully.
    RFC 2045 base64 (76-char line wrapping + trailing newline).
    """
    url = f"https://{domain}/favicon.ico"
    try:
        resp = session.get(url, timeout=FAVICON_TIMEOUT, allow_redirects=True)
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
            # ISO 8601 string
            s = str(creation_date).strip()
            # Accept 'YYYY-MM-DDTHH:MM:SS+00:00' or 'YYYY-MM-DD'
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

        asn = enr.get("asn") or None
        creation_date = enr.get("vt_creation_date")
        week = _iso_week(creation_date)
        record_date = record.get("date", "")

        if host not in domain_info:
            domain_info[host] = {
                "asn": asn,
                "registration_week": week,
                "date_first": record_date,
                "date_last": record_date,
                "country_codes": set(),
            }
        else:
            # Keep earliest first_seen, latest last_seen
            existing = domain_info[host]
            if record_date and (not existing["date_first"] or record_date < existing["date_first"]):
                existing["date_first"] = record_date
            if record_date and (not existing["date_last"] or record_date > existing["date_last"]):
                existing["date_last"] = record_date
        if enr.get("country_code"):
            domain_info[host]["country_codes"].add(enr["country_code"])

    # Convert sets to lists for JSON serialisation
    for info in domain_info.values():
        info["country_codes"] = sorted(info["country_codes"])

    return domain_info


# ---------------------------------------------------------------------------
# Clustering
# ---------------------------------------------------------------------------

def _shared_signals(a_info, a_fav, b_info, b_fav):
    """Return count of signals shared between domains a and b (max 3)."""
    count = 0
    # Signal 1: favicon hash (both non-None and equal)
    if a_fav is not None and b_fav is not None and a_fav == b_fav:
        count += 1
    # Signal 2: ASN (both non-None and equal)
    if a_info["asn"] and b_info["asn"] and a_info["asn"] == b_info["asn"]:
        count += 1
    # Signal 3: registration week (both non-None and equal)
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

    # Union-Find
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
            if _shared_signals(domain_info[da], favicon_hashes.get(da), domain_info[db], favicon_hashes.get(db)) >= 2:
                union(i, j)

    # Group by root
    groups = collections.defaultdict(list)
    for i, d in enumerate(domains):
        groups[find(i)].append(d)

    clusters = []
    for members in groups.values():
        if len(members) < 3:
            continue  # noise

        # Representative signals: use the most common ASN / week among members
        asns = [domain_info[d]["asn"] for d in members if domain_info[d]["asn"]]
        weeks = [domain_info[d]["registration_week"] for d in members if domain_info[d]["registration_week"]]
        favs = [favicon_hashes.get(d) for d in members if favicon_hashes.get(d) is not None]

        rep_asn = collections.Counter(asns).most_common(1)[0][0] if asns else "UNKNOWN"
        rep_week = collections.Counter(weeks).most_common(1)[0][0] if weeks else "unknown"
        rep_fav = collections.Counter(favs).most_common(1)[0][0] if favs else None

        cluster_id = f"CLUSTER-{rep_week}-{rep_asn}"

        dates_first = [domain_info[d]["date_first"] for d in members if domain_info[d]["date_first"]]
        dates_last = [domain_info[d]["date_last"] for d in members if domain_info[d]["date_last"]]
        countries = sorted({cc for d in members for cc in domain_info[d].get("country_codes", [])})

        clusters.append({
            "id": cluster_id,
            "asn": rep_asn,
            "favicon_hash": rep_fav,
            "registration_week": rep_week,
            "domain_count": len(members),
            "first_seen": min(dates_first) if dates_first else None,
            "last_seen": max(dates_last) if dates_last else None,
            "countries": countries,
            "domains": sorted(members),
        })

    # Sort by domain count descending
    clusters.sort(key=lambda c: c["domain_count"], reverse=True)
    return clusters


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

    if not os.path.exists(INPUT_PATH):
        print(f"ERROR: {INPUT_PATH} not found. Run enrich_infra.py first.", file=sys.stderr)
        sys.exit(1)

    with open(INPUT_PATH, "r", encoding="utf-8") as f:
        enriched_records = json.load(f)

    domain_info = _extract_domains(enriched_records)
    domains = list(domain_info.keys())
    print(f"Unique domains to cluster: {len(domains)}")

    # Fetch favicon hashes
    print("Fetching favicons...")
    favicon_hashes = {}

    with requests.Session() as session:
        session.headers["User-Agent"] = "detection-chokepoints/enrichment-pipeline"
        for i, domain in enumerate(domains, 1):
            h = compute_favicon_hash(domain, session)
            if h is not None:
                favicon_hashes[domain] = h
                print(f"  [{i}/{len(domains)}] {domain}: {h}")
            else:
                print(f"  [{i}/{len(domains)}] {domain}: (no favicon)")
            time.sleep(FAVICON_SLEEP)

    print(f"Favicons obtained: {len(favicon_hashes)}/{len(domains)}")

    # Cluster
    print("Clustering...")
    clusters = cluster_domains(domain_info, favicon_hashes)
    print(f"Clusters identified (≥3 domains): {len(clusters)}")
    for c in clusters:
        print(f"  {c['id']}: {c['domain_count']} domains")

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(clusters, f, indent=2, ensure_ascii=False)

    print(f"Written: {OUTPUT_PATH}")

    _write_run_log(CACHE_DIR, "cluster_campaigns", {
        "domains_processed": len(domains),
        "favicons_obtained": len(favicon_hashes),
        "clusters_identified": len(clusters),
        "status": "ok",
    })


if __name__ == "__main__":
    main()
