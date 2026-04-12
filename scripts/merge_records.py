"""
merge_records.py — Merge source cache files into cache/enriched_records.json.

Reads:  cache/ioc_records.json      (from collect_ioc_feeds.py)
        cache/infra_records.json    (from collect_infra_hunts.py)
        cache/enriched_infra.json   (from enrich_infra.py)
Writes: cache/enriched_records.json

Deduplicates by domain (case-insensitive). Sets multi_source=True on records
whose domain appears in 2+ source files. Re-scores all records using
pipeline_utils.rescore_record(). Does NOT make any API calls.

Run standalone:
    python scripts/merge_records.py
"""

import json
import sys
from pathlib import Path

from pipeline_utils import confidence_label, rescore_record

CACHE_DIR = Path(__file__).parent.parent / "cache"

SOURCES = [
    (CACHE_DIR / "ioc_records.json",      "ioc"),
    (CACHE_DIR / "infra_records.json",    "infra"),
    (CACHE_DIR / "enriched_infra.json",   "enriched_infra"),
]

OUTPUT_PATH = CACHE_DIR / "enriched_records.json"


def load_source(path: Path, label: str) -> list[dict]:
    """Load a JSON array from path, returning [] on missing/corrupt files."""
    if not path.exists():
        print(f"[WARN] {path} not found — skipping", file=sys.stderr)
        return []
    try:
        records = json.loads(path.read_text(encoding="utf-8"))
        print(f"[INFO] Loaded {len(records)} records from {path}", file=sys.stderr)
        return records
    except Exception as exc:
        print(f"[WARN] Failed to load {path}: {exc}", file=sys.stderr)
        return []


def merge(sources: list[tuple[Path, str]]) -> list[dict]:
    """Merge records from all sources, dedup by domain, flag multi-source."""
    # First pass: collect domain -> set of source labels
    domain_sources: dict[str, set[str]] = {}
    for path, label in sources:
        for r in load_source(path, label):
            domain = (r.get("domain") or "").lower().strip()
            if domain:
                domain_sources.setdefault(domain, set()).add(label)

    # Second pass: deduplicate by domain, keeping the first occurrence,
    # and set multi_source flag
    seen: set[str] = set()
    merged: list[dict] = []

    for path, label in sources:
        if not path.exists():
            continue
        try:
            records = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue

        for r in records:
            domain = (r.get("domain") or "").lower().strip()
            if not domain:
                # Keep domainless records (rare but possible)
                merged.append(r)
                continue
            if domain in seen:
                continue
            seen.add(domain)

            # Flag multi-source corroboration
            source_count = len(domain_sources.get(domain, set()))
            r["multi_source"] = source_count >= 2

            # Re-score with behavioral weights
            rescore_record(r)
            merged.append(r)

    return merged


def main() -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    merged = merge(SOURCES)

    if not merged:
        print(
            "[ERROR] All three source files are missing or empty — "
            "no records to merge. Run collection scripts first.",
            file=sys.stderr,
        )
        sys.exit(1)

    OUTPUT_PATH.write_text(
        json.dumps(merged, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    # Summary
    multi = sum(1 for r in merged if r.get("multi_source"))
    labels = {}
    for r in merged:
        lbl = r.get("confidence_label", "low")
        labels[lbl] = labels.get(lbl, 0) + 1

    print(
        f"[SUMMARY] records_merged={len(merged)}  "
        f"multi_source={multi}  "
        f"confidence_dist={labels}",
        file=sys.stderr,
    )
    print(f"[INFO] Wrote {len(merged)} records -> {OUTPUT_PATH}", file=sys.stderr)


if __name__ == "__main__":
    main()
