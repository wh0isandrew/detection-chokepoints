"""
pipeline_utils.py — Shared scoring and labeling functions for the masq-infra pipeline.

All pipeline scripts import confidence_label() and rescore_record() from here.
This is the single source of truth for confidence scoring logic.
"""


def confidence_label(score: int) -> str:
    """Map a 0-100 confidence score to a human-readable label."""
    if score >= 90:
        return "confirmed"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def rescore_record(record: dict) -> dict:
    """Re-compute confidence score using behavioral evidence signals.

    Scoring philosophy (PIPE-02): reward adversary-behavior evidence
    (traced chains, multi-source corroboration, payload family match),
    not structural completeness (has SHA-256, has domain, feed membership).

    Weight breakdown:
      Behavioral evidence  0-60  (chain_observed 40, multi_source 20)
      Payload confirmation 0-20  (family 15, sha256 5)
      Corroboration        0-20  (vt_detected 10, vt_count>=5 5, chain_depth>=3 5)
    """
    chain_obs    = bool(record.get("chain_observed"))
    multi_source = bool(record.get("multi_source"))
    has_sha256   = bool(record.get("payload_sha256"))
    has_family   = bool(record.get("payload_family"))
    vt_detected  = bool(record.get("vt_detected"))
    vt_count     = record.get("vt_detection_count") or 0
    chain_depth  = record.get("chain_depth") or 0

    # Behavioral evidence (0-60)
    behavior_pts = (40 if chain_obs else 0) + (20 if multi_source else 0)

    # Payload confirmation (0-20)
    payload_pts = (15 if has_family else 0) + (5 if has_sha256 else 0)

    # Corroboration (0-20)
    corroboration_pts = 0
    if vt_detected:
        corroboration_pts += 10
    if vt_count >= 5:
        corroboration_pts += 5
    if chain_depth >= 3:
        corroboration_pts += 5

    score = min(behavior_pts + payload_pts + corroboration_pts, 100)
    record["confidence"] = score
    record["confidence_label"] = confidence_label(score)
    return record
