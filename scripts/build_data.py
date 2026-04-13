"""
build_data.py — Final data assembly for the masq-infra pipeline.

Merges triaged IOC records and campaign clusters into _data/masq_infra.json
using the schema defined in _data/masq_infra_schema.md.

Run standalone:
    python scripts/build_data.py [--dry-run]
"""

import argparse
import collections
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env")

from pipeline_utils import confidence_label

CACHE_DIR  = Path(__file__).parent.parent / "cache"
DATA_DIR   = Path(__file__).parent.parent / "_data"

TRIAGED_PATH  = CACHE_DIR / "triaged_records.json"
CAMPAIGNS_PATH = CACHE_DIR / "campaigns.json"
HISTORY_PATH  = DATA_DIR  / "masq_infra_history.json"
OUTPUT_PATH   = DATA_DIR  / "masq_infra.json"

PIPELINE_VERSION    = "2.0.0"
CONFIDENCE_THRESHOLD = 40  # minimum confidence to be published
MIN_RECORD_FLOOR     = 5   # abort if fewer records pass threshold


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def build_meta(records: list) -> dict:
    """Build the pipeline run metadata section."""
    sources = sorted({r["source"] for r in records if r.get("source")})
    return {
        "last_updated":         datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "record_count":         len(records),
        "lookback_days":        30,
        "confidence_threshold": CONFIDENCE_THRESHOLD,
        "sources":              sources,
        "pipeline_version":     PIPELINE_VERSION,
    }


def build_payload_summary(records: list) -> dict:
    """Derive payload class/family statistics from the record set."""
    # --- class_breakdown ---
    class_breakdown: dict = collections.Counter(
        r.get("payload_class", "unknown") for r in records
    )
    for cls in ("stealer", "c2", "rmm", "loader", "unknown"):
        class_breakdown.setdefault(cls, 0)

    # --- top_families ---
    family_records = [r for r in records if r.get("payload_family")]
    family_counts  = collections.Counter(r["payload_family"] for r in family_records)
    # For each family, track which payload_class it most often belongs to
    family_class_map: dict = {}
    for r in family_records:
        fam = r["payload_family"]
        family_class_map.setdefault(fam, collections.Counter())[
            r.get("payload_class", "unknown")
        ] += 1

    top_families = [
        {
            "family": fam,
            "count":  cnt,
            "class":  family_class_map[fam].most_common(1)[0][0],
        }
        for fam, cnt in family_counts.most_common(10)
    ]

    # --- lure_payload_matrix ---
    matrix_counter: collections.Counter = collections.Counter()
    matrix_top_family: dict = {}
    for r in records:
        lt  = r.get("lure_type") or "unknown"
        pc  = r.get("payload_class", "unknown")
        matrix_counter[(lt, pc)] += 1
        if r.get("payload_family"):
            matrix_top_family.setdefault(
                (lt, pc), collections.Counter()
            )[r["payload_family"]] += 1

    lure_payload_matrix = [
        {
            "lure_type":    lt,
            "payload_class": pc,
            "count":         cnt,
            "top_family":    (
                matrix_top_family[(lt, pc)].most_common(1)[0][0]
                if matrix_top_family.get((lt, pc)) else None
            ),
        }
        for (lt, pc), cnt in sorted(matrix_counter.items(), key=lambda x: -x[1])
    ]

    # --- chain stats ---
    chain_obs = sum(1 for r in records if r.get("chain_observed"))
    chain_pct = round(100.0 * chain_obs / len(records), 1) if records else 0.0

    return {
        "class_breakdown":     dict(class_breakdown),
        "top_families":        top_families,
        "lure_payload_matrix": lure_payload_matrix,
        "chain_observed_count": chain_obs,
        "chain_observed_pct":   chain_pct,
    }


def build_infrastructure_summary(records: list) -> dict:
    """Derive infrastructure statistics (domains, IPs, ASNs, favicon clusters)."""
    domains = [r["domain"] for r in records if r.get("domain")]
    ips     = [r["ip"]     for r in records if r.get("ip")]

    # top_asns: aggregate by domain count per ASN
    asn_counter: collections.Counter = collections.Counter()
    for r in records:
        asn = (r.get("asn") or "").strip()
        if asn and asn.lower() not in ("unknown", "none", ""):
            asn_counter[asn] += 1
    top_asns = [
        {"asn": asn, "count": cnt}
        for asn, cnt in asn_counter.most_common(10)
    ]

    # favicon_clusters: hashes appearing on 2+ domains
    fav_map: dict = collections.defaultdict(list)
    for r in records:
        fh = r.get("favicon_hash")
        dm = r.get("domain")
        if fh and dm:
            fav_map[fh].append(dm)

    favicon_clusters = sorted(
        [
            {
                "favicon_hash":  fh,
                "count":         len(doms),
                "sample_domain": doms[0],
            }
            for fh, doms in fav_map.items()
            if len(doms) >= 2
        ],
        key=lambda x: -x["count"],
    )

    return {
        "confirmed_domains":  len(set(domains)),
        "confirmed_ips":      len(set(ips)),
        "top_asns":           top_asns,
        "favicon_clusters":   favicon_clusters,
    }


def load_weekly_summary() -> list:
    """Load historical weekly metrics and return as a sorted list."""
    if not HISTORY_PATH.exists():
        return []
    try:
        history = json.loads(HISTORY_PATH.read_text(encoding="utf-8"))
        return sorted(history.values(), key=lambda x: x.get("week", ""))
    except Exception as exc:
        print(f"[WARN] Could not load {HISTORY_PATH}: {exc}", file=sys.stderr)
        return []


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Merge pipeline cache outputs into _data/masq_infra.json."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Write output to /tmp/masq_infra_test.json instead of _data/masq_infra.json.",
    )
    parser.add_argument(
        "--min-records",
        type=int,
        default=MIN_RECORD_FLOOR,
        help=f"Minimum record count to proceed (default: {MIN_RECORD_FLOOR}). Set to 0 to disable.",
    )
    args = parser.parse_args()

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # Load inputs
    records: list = []
    if TRIAGED_PATH.exists():
        try:
            records = json.loads(TRIAGED_PATH.read_text(encoding="utf-8"))
            print(f"[INFO] Loaded {len(records)} triaged records", file=sys.stderr)
        except Exception as exc:
            print(f"[WARN] Failed to load {TRIAGED_PATH}: {exc}", file=sys.stderr)
    else:
        print(f"[WARN] {TRIAGED_PATH} not found — run the collection pipeline first", file=sys.stderr)

    campaigns: list = []
    if CAMPAIGNS_PATH.exists():
        try:
            campaigns = json.loads(CAMPAIGNS_PATH.read_text(encoding="utf-8"))
            print(f"[INFO] Loaded {len(campaigns)} campaigns", file=sys.stderr)
        except Exception as exc:
            print(f"[WARN] Failed to load {CAMPAIGNS_PATH}: {exc}", file=sys.stderr)
    else:
        print(f"[WARN] {CAMPAIGNS_PATH} not found — no campaign data will be included", file=sys.stderr)

    # Filter to publishable confidence threshold and sort
    filtered = [r for r in records if r.get("confidence", 0) >= CONFIDENCE_THRESHOLD]
    filtered.sort(key=lambda r: r.get("last_seen", ""), reverse=True)

    dropped = len(records) - len(filtered)
    print(
        f"[INFO] {len(filtered)} records pass confidence threshold "
        f"({CONFIDENCE_THRESHOLD}); {dropped} filtered out",
        file=sys.stderr,
    )

    # PIPE-03: Minimum record floor guard (override with --min-records 0 to disable)
    floor = args.min_records
    if floor > 0 and len(filtered) < floor:
        print(
            f"[ERROR] Only {len(filtered)} records pass confidence threshold "
            f"({CONFIDENCE_THRESHOLD}) — minimum floor is {floor}. "
            f"Aborting without writing output.",
            file=sys.stderr,
        )
        sys.exit(1)

    output = {
        "meta":                    build_meta(filtered),
        "records":                 filtered,
        "campaigns":               campaigns,
        "payload_summary":         build_payload_summary(filtered),
        "infrastructure_summary":  build_infrastructure_summary(filtered),
        "weekly_summary":          load_weekly_summary(),
    }

    dest = Path("/tmp/masq_infra_test.json") if args.dry_run else OUTPUT_PATH
    dest.write_text(json.dumps(output, indent=2, ensure_ascii=False))

    # Summary output
    class_bd = output["payload_summary"]["class_breakdown"]
    top3     = output["payload_summary"]["top_families"][:3]
    top3_names = [f["family"] for f in top3]

    print(
        f"[SUMMARY] records_written={len(filtered)}  "
        f"campaigns_written={len(campaigns)}  "
        f"class_breakdown={dict(class_bd)}  "
        f"top3_families={top3_names}",
        file=sys.stderr,
    )
    print(f"[INFO] Wrote output → {dest}", file=sys.stderr)


if __name__ == "__main__":
    main()
