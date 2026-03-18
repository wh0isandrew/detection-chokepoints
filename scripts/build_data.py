#!/usr/bin/env python3
"""
build_data.py
Merge enrichment pipeline outputs into _data/masq_infra.json.

Loads the existing masq_infra.json (written by update_masq_infra.py) and
adds / updates the ClickGrab-derived sections without removing existing
hosting_providers, lure_types, traffic_sources, or urlhaus_tags fields.

Reads:
  cache/enriched_infra.json
  cache/campaign_clusters.json
  cache/triage_results.json      (optional — absent when sandbox step skipped)
  cache/ha_lookup_results.json   (optional — HA IOC search results)
  _data/masq_infra.json          (existing; must be preserved)

Writes:
  _data/masq_infra.json       (merged output)
"""

import collections
import json
import os
import sys
from datetime import datetime, date, timedelta, timezone
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE_DIR = os.path.join(REPO_ROOT, "cache")
DATA_DIR = os.path.join(REPO_ROOT, "_data")

ENRICHED_PATH = os.path.join(CACHE_DIR, "enriched_infra.json")
CLUSTERS_PATH = os.path.join(CACHE_DIR, "campaign_clusters.json")
TRIAGE_PATH = os.path.join(CACHE_DIR, "triage_results.json")
HA_LOOKUP_PATH = os.path.join(CACHE_DIR, "ha_lookup_results.json")
OUTPUT_PATH = os.path.join(DATA_DIR, "masq_infra.json")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_json(path, default=None):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as exc:
            print(f"  [WARN] Could not load {path}: {exc}", file=sys.stderr)
    return default if default is not None else {}


def _domain_age_bucket(creation_date):
    """Map a VT creation_date (Unix timestamp or ISO string) to an age-at-observation bucket."""
    if not creation_date:
        return None
    try:
        if isinstance(creation_date, (int, float)):
            from datetime import datetime, timezone
            reg_date = datetime.fromtimestamp(creation_date, tz=timezone.utc).date()
        else:
            s = str(creation_date).strip()[:10]
            reg_date = date.fromisoformat(s)
    except Exception:
        return None

    age_days = (date.today() - reg_date).days
    if age_days < 0:
        return None
    if age_days <= 1:
        return "0-1d"
    if age_days <= 7:
        return "1-7d"
    if age_days <= 30:
        return "7-30d"
    if age_days <= 90:
        return "30-90d"
    return "90d+"


AGE_BUCKETS = ["0-1d", "1-7d", "7-30d", "30-90d", "90d+"]


# ---------------------------------------------------------------------------
# Build new sections from enriched data
# ---------------------------------------------------------------------------

def build_asn_distribution(enriched_records):
    """Top ASNs by domain count (deduplicated by hostname)."""
    asn_counts = collections.Counter()
    asn_names = {}
    seen_hosts = set()

    for record in enriched_records:
        enr = record.get("enrichment", {})
        host = (enr.get("host") or "").lower()
        if not host or host in seen_hosts:
            continue
        seen_hosts.add(host)

        asn = enr.get("asn")
        if asn:
            asn_counts[asn] += 1
            if asn not in asn_names:
                asn_names[asn] = enr.get("as_name") or ""

    total = sum(asn_counts.values()) or 1
    return [
        {
            "asn": asn,
            "org": asn_names.get(asn, ""),
            "count": count,
            "pct": round(count / total * 100, 1),
        }
        for asn, count in asn_counts.most_common(20)
    ]


def build_country_distribution(enriched_records):
    """Domain count per country (deduplicated by hostname)."""
    country_counts = collections.Counter()
    country_names = {}
    seen_hosts = set()

    for record in enriched_records:
        enr = record.get("enrichment", {})
        host = (enr.get("host") or "").lower()
        if not host or host in seen_hosts:
            continue
        seen_hosts.add(host)

        cc = enr.get("country_code")
        if cc:
            country_counts[cc] += 1
            if cc not in country_names:
                country_names[cc] = enr.get("country") or ""

    return [
        {
            "country_code": cc,
            "country": country_names.get(cc, ""),
            "count": count,
        }
        for cc, count in country_counts.most_common()
    ]


def build_domain_age_histogram(enriched_records):
    """Count domains per age-at-observation bucket (deduplicated by hostname)."""
    bucket_counts = collections.Counter()
    seen_hosts = set()

    for record in enriched_records:
        enr = record.get("enrichment", {})
        host = (enr.get("host") or "").lower()
        if not host or host in seen_hosts:
            continue
        seen_hosts.add(host)

        bucket = _domain_age_bucket(enr.get("vt_creation_date"))
        if bucket:
            bucket_counts[bucket] += 1

    return [{"bucket": b, "count": bucket_counts.get(b, 0)} for b in AGE_BUCKETS]


def build_payload_families(triage_results, ha_lookup_results):
    """Aggregate family tags from sandbox submissions and HA IOC lookups."""
    family_counts = collections.Counter()

    for result in (triage_results or []):
        for fam in result.get("families", []):
            if fam:
                family_counts[fam.lower()] += 1

    # ha_lookup_results is a dict keyed by "domain:x" / "ip:x", values are lists of hits
    for hits in (ha_lookup_results or {}).values():
        for hit in (hits or []):
            for fam in hit.get("families", []):
                if fam:
                    family_counts[fam.lower()] += 1

    return [{"family": fam, "count": count} for fam, count in family_counts.most_common()]


def build_tls_cert_authorities(enriched_records):
    """
    TLS CA distribution — derived from existing stats in masq_infra.json since
    crt.sh data comes from update_masq_infra.py. Returns a placeholder here;
    the existing value is preserved during merge if already present.
    """
    # This field is populated by update_masq_infra.py via crt.sh.
    # We return an empty list as a safe default; the merge logic below
    # preserves any existing value written by the other pipeline.
    return []


def build_campaigns(clusters, triage_results):
    """Build campaign records from cluster data, enriched with Triage family tags."""
    # Build lookup: domain → families from Triage
    domain_families = collections.defaultdict(set)
    for result in (triage_results or []):
        url = result.get("url", "")
        families = result.get("families", [])
        try:
            host = (urlparse(url).hostname or "").lower()
        except Exception:
            host = ""
        if host:
            for fam in families:
                domain_families[host].add(fam)

    campaigns = []
    for cluster in (clusters or []):
        domains = cluster.get("domains", [])
        # Collect families across all domains in the cluster
        all_families = sorted({
            fam
            for d in domains
            for fam in domain_families.get(d, set())
        })

        # Derive org from ASN field (keep as-is; enriched org name is in asn_distribution)
        campaigns.append({
            "id": cluster.get("id", ""),
            "asn": cluster.get("asn", ""),
            "favicon_hash": cluster.get("favicon_hash"),
            "domain_count": cluster.get("domain_count", len(domains)),
            "first_seen": cluster.get("first_seen"),
            "last_seen": cluster.get("last_seen"),
            "countries": cluster.get("countries", []),
            "families": all_families,
            "domains": domains,
        })
    return campaigns


# ---------------------------------------------------------------------------
# Summary counters
# ---------------------------------------------------------------------------

def build_summary(enriched_records, clusters, triage_results):
    seen_hosts = set()
    seen_asns = set()
    seen_countries = set()

    for record in enriched_records:
        enr = record.get("enrichment", {})
        host = (enr.get("host") or "").lower()
        if host:
            seen_hosts.add(host)
        if enr.get("asn"):
            seen_asns.add(enr["asn"])
        if enr.get("country_code"):
            seen_countries.add(enr["country_code"])

    return {
        "total_domains": len(seen_hosts),
        "unique_asns": len(seen_asns),
        "unique_countries": len(seen_countries),
        "campaigns_identified": len([c for c in (clusters or []) if c.get("domain_count", 0) >= 3]),
        "payloads_sandboxed": len(triage_results or []),
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
    # Check required inputs
    if not os.path.exists(ENRICHED_PATH):
        print(f"ERROR: {ENRICHED_PATH} not found. Run enrich_infra.py first.", file=sys.stderr)
        sys.exit(1)

    enriched_records = _load_json(ENRICHED_PATH, default=[])
    clusters = _load_json(CLUSTERS_PATH, default=[])
    triage_results = _load_json(TRIAGE_PATH, default=[])
    ha_lookup_results = _load_json(HA_LOOKUP_PATH, default={})
    existing = _load_json(OUTPUT_PATH, default={})

    ha_hit_count = sum(len(v) for v in ha_lookup_results.values())
    print(f"Loaded {len(enriched_records)} enriched records")
    print(f"Loaded {len(clusters)} campaign clusters")
    print(f"Loaded {len(triage_results)} sandbox results")
    print(f"Loaded {len(ha_lookup_results)} HA lookup terms ({ha_hit_count} report hits)")

    today = date.today()
    week_ago = today - timedelta(days=7)

    # Build new sections
    asn_dist = build_asn_distribution(enriched_records)
    country_dist = build_country_distribution(enriched_records)
    age_hist = build_domain_age_histogram(enriched_records)
    payload_families = build_payload_families(triage_results, ha_lookup_results)
    campaigns = build_campaigns(clusters, triage_results)
    summary = build_summary(enriched_records, clusters, triage_results)

    print(f"  ASN distribution: {len(asn_dist)} entries")
    print(f"  Country distribution: {len(country_dist)} entries")
    print(f"  Age histogram: {age_hist}")
    print(f"  Payload families: {payload_families}")
    print(f"  Campaigns: {len(campaigns)}")

    # Merge: start from existing to preserve all fields from update_masq_infra.py
    merged = dict(existing)

    # Update / add new enrichment sections
    merged["generated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    merged["date_range"] = {
        "start": week_ago.isoformat(),
        "end": today.isoformat(),
    }
    merged["summary"] = summary
    merged["asn_distribution"] = asn_dist
    merged["country_distribution"] = country_dist
    merged["domain_age_histogram"] = age_hist
    merged["campaigns"] = campaigns

    # payload_families: only overwrite with new data if non-empty;
    # otherwise preserve whatever update_masq_infra.py wrote
    if payload_families:
        merged["payload_families"] = payload_families
    elif "payload_families" not in merged:
        merged["payload_families"] = []

    # tls_cert_authorities: preserve from update_masq_infra.py if already present
    if "tls_cert_authorities" not in merged:
        merged["tls_cert_authorities"] = build_tls_cert_authorities(enriched_records)

    os.makedirs(DATA_DIR, exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(merged, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"\nWritten: {OUTPUT_PATH}")
    print(f"Summary: {summary}")

    _write_run_log(CACHE_DIR, "build_data", {
        "records_merged": len(enriched_records),
        "clusters_merged": len(clusters),
        "payload_families": len(payload_families),
        **summary,
        "status": "ok",
    })


if __name__ == "__main__":
    main()
