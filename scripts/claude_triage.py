"""
claude_triage.py — AI-powered payload classification for the masq-infra pipeline.

Reads cache/enriched_records.json, finds records where payload_class is unknown
or payload_family is null, and uses the Anthropic API to classify them.
Writes all records (triaged and untriaged) to cache/triaged_records.json.

Run standalone:
    python scripts/claude_triage.py
"""

import collections
import json
import os
import shutil
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env")

from pipeline_utils import confidence_label

CACHE_DIR     = Path(__file__).parent.parent / "cache"
ENRICHED_PATH = CACHE_DIR / "enriched_records.json"
OUTPUT_PATH   = CACHE_DIR / "triaged_records.json"

MODEL         = "claude-sonnet-4-6"
MAX_API_CALLS = 50
API_RATE_SLEEP = 1  # seconds between Anthropic API calls

SYSTEM_PROMPT = (
    "You are a malware analyst classifying malicious payloads delivered via "
    "software impersonation infrastructure. Classify the payload based on the "
    "evidence provided. Respond with valid JSON only. No explanation, no markdown."
)

VALID_CLASSES = {"stealer", "c2", "rmm", "loader", "unknown"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def needs_triage(record: dict) -> bool:
    """Return True if the record needs AI classification."""
    return (
        record.get("payload_class") == "unknown"
        or record.get("payload_family") is None
    )


def build_user_prompt(record: dict) -> str:
    """Assemble the classification prompt for a single record."""
    domain        = record.get("domain") or "unknown"
    file_type     = record.get("payload_file_type") or "unknown"
    sha256        = record.get("payload_sha256") or "unknown"
    lure_type     = record.get("lure_type") or "unknown"
    lure_brand    = record.get("lure_brand") or "unknown"
    source        = record.get("source") or "unknown"
    vt_detected   = record.get("vt_detected")
    vt_count      = record.get("vt_detection_count") or 0

    # Assemble available context as "tags"
    feed_tags: list[str] = []
    if lure_brand and lure_brand != "unknown":
        feed_tags.append(f"lure_brand:{lure_brand}")
    if source and source != "unknown":
        feed_tags.append(f"source:{source}")
    tags_str = ", ".join(feed_tags) if feed_tags else "none"

    return f"""Classify this payload record:
- File name: unknown
- File type: {file_type}
- SHA256: {sha256}
- Delivery domain: {domain}
- Lure type: {lure_type}
- Source feed tags: {tags_str}
- VirusTotal detected: {vt_detected}
- VT detection count: {vt_count}

Respond with this exact JSON structure:
{{
  "payload_class": "stealer|c2|rmm|loader|unknown",
  "payload_family": "family name or null",
  "confidence_adjustment": -10 to +10,
  "reasoning": "one sentence"
}}

payload_class values:
- stealer: credential, cookie, or wallet theft
- c2: persistent access or beaconing framework
- rmm: remote management tool being abused
- loader: drops further stages
- unknown: cannot determine from available evidence"""


def triage_record(client, record: dict) -> dict:
    """Call the Anthropic API to classify a record. Returns an updated copy."""
    from anthropic import Anthropic  # imported here so the module is importable without the package

    resp = client.messages.create(
        model=MODEL,
        max_tokens=256,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": build_user_prompt(record)}],
    )

    text = resp.content[0].text.strip()
    # Strip accidental markdown fences
    if text.startswith("```"):
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]
        text = text.strip()

    parsed = json.loads(text)  # raises JSONDecodeError if malformed — caught by caller

    rec = dict(record)

    cls = parsed.get("payload_class", "unknown")
    rec["payload_class"] = cls if cls in VALID_CLASSES else "unknown"

    if parsed.get("payload_family"):
        rec["payload_family"] = str(parsed["payload_family"])

    try:
        adj = int(parsed.get("confidence_adjustment", 0))
    except (TypeError, ValueError):
        adj = 0

    rec["confidence"] = max(0, min(100, rec.get("confidence", 0) + adj))
    rec["confidence_label"] = confidence_label(rec["confidence"])
    rec["triage_note"] = str(parsed.get("reasoning", ""))
    rec["triage_source"] = "claude"

    return rec


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()

    if not api_key:
        print(
            "[WARN] ANTHROPIC_API_KEY not set — copying enriched_records.json to "
            "triaged_records.json unchanged",
            file=sys.stderr,
        )
        if ENRICHED_PATH.exists():
            shutil.copy(str(ENRICHED_PATH), str(OUTPUT_PATH))
            print(f"[INFO] Copied {ENRICHED_PATH} → {OUTPUT_PATH}", file=sys.stderr)
        else:
            print(f"[WARN] {ENRICHED_PATH} not found — writing empty triaged_records.json", file=sys.stderr)
            OUTPUT_PATH.write_text("[]", encoding="utf-8")
        return

    if not ENRICHED_PATH.exists():
        print(f"[WARN] {ENRICHED_PATH} not found — writing empty triaged_records.json", file=sys.stderr)
        OUTPUT_PATH.write_text("[]", encoding="utf-8")
        return

    try:
        records: list[dict] = json.loads(ENRICHED_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"[WARN] Failed to load {ENRICHED_PATH}: {exc}", file=sys.stderr)
        OUTPUT_PATH.write_text("[]", encoding="utf-8")
        return

    print(f"[INFO] Loaded {len(records)} records. Identifying triage candidates …", file=sys.stderr)

    from anthropic import Anthropic
    client = Anthropic(api_key=api_key)

    calls_used       = 0
    errors           = 0
    triaged          = 0
    classes_assigned: collections.Counter = collections.Counter()
    families_identified = 0
    limit_hit        = False

    for i, rec in enumerate(records):
        if not needs_triage(rec):
            continue
        if calls_used >= MAX_API_CALLS:
            remaining = sum(1 for r in records[i:] if needs_triage(r))
            print(
                f"[WARN] API call limit reached ({MAX_API_CALLS}). "
                f"{remaining} records left untriaged.",
                file=sys.stderr,
            )
            limit_hit = True
            break

        try:
            records[i] = triage_record(client, rec)
            triaged += 1
            classes_assigned[records[i]["payload_class"]] += 1
            if records[i].get("payload_family"):
                families_identified += 1
        except Exception as exc:
            print(
                f"[WARN] Triage failed for record {rec.get('id', '?')}: {exc}",
                file=sys.stderr,
            )
            errors += 1

        calls_used += 1
        time.sleep(API_RATE_SLEEP)

    OUTPUT_PATH.write_text(json.dumps(records, indent=2, ensure_ascii=False))

    print(
        f"[SUMMARY] records_triaged={triaged}  api_calls={calls_used}  "
        f"errors={errors}  limit_hit={limit_hit}  "
        f"classes={dict(classes_assigned)}  families_identified={families_identified}",
        file=sys.stderr,
    )
    print(f"[INFO] Wrote {len(records)} records → {OUTPUT_PATH}", file=sys.stderr)


if __name__ == "__main__":
    main()
