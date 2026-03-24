"""
cluster_campaigns.py — Hard-signal campaign clustering for the masq-infra pipeline.

Reads cache/triaged_records.json and clusters records into campaigns using hard
signals only (shared payload hash, shared favicon hash, shared IP within 30 days,
shared self-signed cert pattern on cheap TLDs).

Writes confirmed campaigns (confidence >= 70) to cache/campaigns.json and
lower-confidence clusters to cache/low_confidence_campaigns.json.

Run standalone:
    python scripts/cluster_campaigns.py [--narratives]
"""

import argparse
import collections
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path

from dateutil.parser import parse as parse_date
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env")

CACHE_DIR            = Path(__file__).parent.parent / "cache"
INPUT_PATH           = CACHE_DIR / "triaged_records.json"
OUTPUT_PATH          = CACHE_DIR / "campaigns.json"
LOW_CONF_OUTPUT_PATH = CACHE_DIR / "low_confidence_campaigns.json"

MODEL                = "claude-sonnet-4-6"
MAX_NARRATIVE_CALLS  = 20
NARRATIVE_RATE_SLEEP = 1  # seconds between Anthropic API calls

# Hard-signal priority order (highest → lowest)
PRIORITY_ORDER = ["shared_payload", "shared_favicon", "shared_ip", "shared_cert_pattern"]

# Cert-pattern: cheap disposable TLDs with self-signed certs
CERT_PATTERN = re.compile(
    r"^[a-z0-9-]+\.(tk|ml|ga|cf|gq|top|xyz|site|online|click|buzz|fun)$"
)

CONF_HIGH_THRESHOLD = 70


# ---------------------------------------------------------------------------
# Confidence helpers
# ---------------------------------------------------------------------------

def confidence_label(score: int) -> str:
    if score >= 90:
        return "confirmed"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def campaign_id(signal_type: str, signal_value: str) -> str:
    return hashlib.sha256(f"{signal_type}:{signal_value}".encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Date helpers
# ---------------------------------------------------------------------------

def _parse_date_safe(s: str):
    """Parse a date string; return None on failure."""
    if not s:
        return None
    try:
        return parse_date(s[:10])
    except Exception:
        return None


def date_range_days(records: list):
    """Return the span in days between the earliest first_seen and latest last_seen, or None."""
    firsts = [_parse_date_safe(r.get("first_seen", "")) for r in records]
    lasts  = [_parse_date_safe(r.get("last_seen", ""))  for r in records]
    firsts = [d for d in firsts if d]
    lasts  = [d for d in lasts  if d]
    all_dates = firsts + lasts
    if len(all_dates) < 2:
        return None
    return (max(all_dates) - min(all_dates)).days


def _within_30_days(records: list) -> bool:
    """Return True if all records in this IP group fall within a 30-day window."""
    days = date_range_days(records)
    if days is None:
        return True
    return days <= 30


# ---------------------------------------------------------------------------
# Signal group construction
# ---------------------------------------------------------------------------

def build_signal_groups(records: list) -> dict:
    """Group records by each hard signal type.

    Returns a nested dict:
        {signal_type: {signal_value: [record, ...]}}

    Each inner list is filtered to 2+ members (the minimum to form a cluster).
    """
    groups = {
        "shared_payload":      {},
        "shared_favicon":      {},
        "shared_ip":           {},
        "shared_cert_pattern": {},
    }

    for rec in records:
        if sha256 := rec.get("payload_sha256"):
            groups["shared_payload"].setdefault(sha256, []).append(rec)

        if fav := rec.get("favicon_hash"):
            groups["shared_favicon"].setdefault(str(fav), []).append(rec)

        if ip := rec.get("ip"):
            groups["shared_ip"].setdefault(ip, []).append(rec)

        cn = (rec.get("cert_cn") or "").strip().lower()
        if rec.get("cert_self_signed") and cn and CERT_PATTERN.match(cn):
            groups["shared_cert_pattern"].setdefault(cn, []).append(rec)

    # Filter shared_ip groups to 30-day window
    groups["shared_ip"] = {
        k: v for k, v in groups["shared_ip"].items() if _within_30_days(v)
    }

    # Drop groups with fewer than 2 records
    for sig in list(groups.keys()):
        groups[sig] = {k: v for k, v in groups[sig].items() if len(v) >= 2}

    return groups


# ---------------------------------------------------------------------------
# Cluster scoring
# ---------------------------------------------------------------------------

def score_cluster(signal_type: str, records: list) -> int:
    """Compute a 0–100 confidence score for a campaign cluster."""
    base_pts = {
        "shared_payload":      40,
        "shared_favicon":      30,
        "shared_ip":           30,
        "shared_cert_pattern": 20,
    }
    score = base_pts[signal_type]

    # Corroborating signals (additive)
    classes  = {r.get("payload_class") for r in records}
    families = {r.get("payload_family") for r in records if r.get("payload_family")}

    if len(classes) == 1:
        score += 10
    if len(families) == 1:
        score += 10

    dr = date_range_days(records)
    if dr is not None and dr <= 14:
        score += 10

    if len(records) >= 5:
        score += 5

    if any(r.get("chain_observed") for r in records):
        score += 5

    return min(score, 100)


# ---------------------------------------------------------------------------
# Campaign record construction
# ---------------------------------------------------------------------------

def build_campaign(signal_type: str, signal_value: str, records: list) -> dict:
    """Assemble a campaign record dict from a group of linked records."""
    domains    = sorted({r["domain"] for r in records if r.get("domain")})
    families   = sorted({r["payload_family"] for r in records if r.get("payload_family")})
    classes    = sorted({r.get("payload_class", "unknown") for r in records})
    lure_types = sorted({r["lure_type"] for r in records if r.get("lure_type")})

    first_dates = [r["first_seen"][:10] for r in records if r.get("first_seen")]
    last_dates  = [r["last_seen"][:10]  for r in records if r.get("last_seen")]

    score = score_cluster(signal_type, records)

    return {
        "id":                campaign_id(signal_type, signal_value),
        "hard_signal":       signal_type,
        "hard_signal_value": signal_value,
        "domain_count":      len(domains),
        "domains":           domains,
        "payload_families":  families,
        "payload_classes":   classes,
        "lure_types":        lure_types,
        "first_seen":        min(first_dates) if first_dates else "",
        "last_seen":         max(last_dates)  if last_dates  else "",
        "confidence":        score,
        "confidence_label":  confidence_label(score),
        "narrative":         None,
        "record_ids":        [r["id"] for r in records],
    }


# ---------------------------------------------------------------------------
# Priority-based record assignment
# ---------------------------------------------------------------------------

def assign_records_to_clusters(records: list) -> list:
    """
    Assign each record to at most one cluster using hard-signal priority order.

    Returns a list of campaign dicts.
    """
    all_groups = build_signal_groups(records)
    assigned_ids: set = set()
    campaigns: list = []

    for signal_type in PRIORITY_ORDER:
        for signal_value, group_records in all_groups[signal_type].items():
            # Only keep records not already claimed by a higher-priority cluster
            eligible = [r for r in group_records if r["id"] not in assigned_ids]
            if len(eligible) < 2:
                continue
            campaign = build_campaign(signal_type, signal_value, eligible)
            campaigns.append(campaign)
            for r in eligible:
                assigned_ids.add(r["id"])

    return campaigns


# ---------------------------------------------------------------------------
# Narrative generation
# ---------------------------------------------------------------------------

def generate_narrative(client, campaign: dict) -> str:
    """Call the Anthropic API to write a 2-3 sentence campaign summary."""
    families_str = ", ".join(campaign["payload_families"]) or "unknown"
    classes_str  = ", ".join(campaign["payload_classes"])  or "unknown"
    lure_str     = ", ".join(campaign["lure_types"])        or "unknown"

    user_msg = (
        f"Summarize this malware campaign cluster:\n"
        f"- Hard signal: {campaign['hard_signal']} ({campaign['hard_signal_value']})\n"
        f"- Domains: {campaign['domain_count']} confirmed delivery domains\n"
        f"- Payload families: {families_str}\n"
        f"- Payload class: {classes_str}\n"
        f"- Lure types: {lure_str}\n"
        f"- Active: {campaign['first_seen']} to {campaign['last_seen']}\n"
        f"- Confidence: {campaign['confidence_label']} ({campaign['confidence']} pts)"
    )

    resp = client.messages.create(
        model=MODEL,
        max_tokens=200,
        system=(
            "You are a threat intelligence analyst writing concise campaign summaries. "
            "Be factual and specific. Respond in 2-3 sentences only."
        ),
        messages=[{"role": "user", "content": user_msg}],
    )
    return resp.content[0].text.strip()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Cluster triaged IOC records into campaigns using hard signals."
    )
    parser.add_argument(
        "--narratives",
        action="store_true",
        help="Generate AI narrative summaries for high-confidence campaigns.",
    )
    args = parser.parse_args()

    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    if not INPUT_PATH.exists():
        print(f"[WARN] {INPUT_PATH} not found — writing empty campaign files", file=sys.stderr)
        OUTPUT_PATH.write_text("[]", encoding="utf-8")
        LOW_CONF_OUTPUT_PATH.write_text("[]", encoding="utf-8")
        return

    try:
        records: list = json.loads(INPUT_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"[WARN] Failed to load {INPUT_PATH}: {exc}", file=sys.stderr)
        OUTPUT_PATH.write_text("[]", encoding="utf-8")
        LOW_CONF_OUTPUT_PATH.write_text("[]", encoding="utf-8")
        return

    print(f"[INFO] Clustering {len(records)} records …", file=sys.stderr)
    campaigns = assign_records_to_clusters(records)

    # Optional narrative generation
    if args.narratives:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
        if not api_key:
            print(
                "[WARN] ANTHROPIC_API_KEY not set — skipping narrative generation",
                file=sys.stderr,
            )
        else:
            client = None
            try:
                from anthropic import Anthropic
                client = Anthropic(api_key=api_key)
            except ImportError:
                print(
                    "[WARN] anthropic package not installed — skipping narratives",
                    file=sys.stderr,
                )

            if client:
                narrative_calls = 0
                for c in campaigns:
                    if c["confidence"] < CONF_HIGH_THRESHOLD or c["narrative"] is not None:
                        continue
                    if narrative_calls >= MAX_NARRATIVE_CALLS:
                        print(
                            f"[WARN] Narrative call limit reached ({MAX_NARRATIVE_CALLS}).",
                            file=sys.stderr,
                        )
                        break
                    try:
                        c["narrative"] = generate_narrative(client, c)
                    except Exception as exc:
                        print(
                            f"[WARN] Narrative generation failed for {c['id']}: {exc}",
                            file=sys.stderr,
                        )
                    narrative_calls += 1
                    time.sleep(NARRATIVE_RATE_SLEEP)

                print(
                    f"[INFO] Generated {narrative_calls} campaign narratives.",
                    file=sys.stderr,
                )

    # Split by confidence threshold
    high_conf = [c for c in campaigns if c["confidence"] >= CONF_HIGH_THRESHOLD]
    low_conf  = [c for c in campaigns if c["confidence"] <  CONF_HIGH_THRESHOLD]

    OUTPUT_PATH.write_text(json.dumps(high_conf, indent=2, ensure_ascii=False))
    LOW_CONF_OUTPUT_PATH.write_text(json.dumps(low_conf, indent=2, ensure_ascii=False))

    clustered_ids = {rid for c in campaigns for rid in c["record_ids"]}
    unclustered   = len(records) - len(clustered_ids)

    conf_dist = collections.Counter(confidence_label(c["confidence"]) for c in campaigns)

    print(
        f"[SUMMARY] total_clusters={len(campaigns)}  "
        f"high_conf_clusters={len(high_conf)}  "
        f"low_conf_clusters={len(low_conf)}  "
        f"confirmed={conf_dist.get('confirmed', 0)}  "
        f"high={conf_dist.get('high', 0)}  "
        f"medium={conf_dist.get('medium', 0)}  "
        f"low={conf_dist.get('low', 0)}  "
        f"records_clustered={len(clustered_ids)}  "
        f"records_unclustered={unclustered}",
        file=sys.stderr,
    )
    print(f"[INFO] Wrote {len(high_conf)} campaigns → {OUTPUT_PATH}", file=sys.stderr)
    print(
        f"[INFO] Wrote {len(low_conf)} low-confidence clusters → {LOW_CONF_OUTPUT_PATH}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
