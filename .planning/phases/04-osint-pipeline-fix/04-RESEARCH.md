# Phase 4: OSINT Pipeline Fix - Research

**Researched:** 2026-04-11
**Domain:** Python data pipeline — record merging, confidence scoring, guard clauses
**Confidence:** HIGH

---

## Summary

The OSINT pipeline is a multi-stage Python collection and enrichment system that produces `_data/masq_infra.json` for the Jekyll site. The structural gap is concrete and narrow: `fetch_payload_chains.py` already reads `cache/ioc_records.json` and `cache/infra_records.json`, merges them, enriches them, and writes `cache/enriched_records.json` — but the REQUIREMENTS.md spec calls for a dedicated `merge_records.py` that does this merge step explicitly and independently, so the pipeline stages are cleanly separated and `claude_triage.py` has a guaranteed input.

The confidence scoring problem is also clearly located. `rescore_record()` in `fetch_payload_chains.py` awards up to 30 points for SHA-256 presence and up to 40 points for domain presence from a known feed — neither of which is adversary-behavior evidence. A record can score 70 ("high") just by having a SHA-256 and coming from MalwareBazaar, regardless of whether a chain was traced or multi-source corroboration exists.

`build_data.py` has no minimum-record guard. It reads `cache/triaged_records.json`, applies a confidence threshold filter (≥40), and writes output whether the filtered set contains 0 or 1000 records. The history append is called externally (via `append_history.py`) and is not guarded either.

**Primary recommendation:** Write `merge_records.py` as a thin, explicit merge step that combines the three source cache files (resolving the naming question below), rewrite `rescore_record()` to reward behavioral signals, and add a configurable minimum-floor guard at the top of `build_data.py`'s filter block.

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| PIPE-01 | `scripts/merge_records.py` written and merges `cache/ioc_records.json` + `cache/infra_records.json` + `cache/enriched_infra.json` into `cache/enriched_records.json` using the shared record schema | Full pipeline trace completed — inputs/outputs confirmed |
| PIPE-02 | Confidence scoring separated from data quality — `confirmed`/`high` labels reflect adversary-behavior evidence, not structural completeness | `rescore_record()` in `fetch_payload_chains.py` fully read; scoring logic documented |
| PIPE-03 | `build_data.py` exits non-zero and skips history append when assembled record count falls below configurable minimum floor | `build_data.py` read in full; no guard exists today |
</phase_requirements>

---

## Pipeline Structure Audit

[VERIFIED: read all scripts in scripts/]

### Script inventory and data flow

| Script | Reads | Writes | Role |
|--------|-------|--------|------|
| `collect_ioc_feeds.py` | External APIs (MalwareBazaar, ThreatFox, URLhaus) | `cache/ioc_records.json` | Stage 1A: feed collection |
| `collect_infra_hunts.py` | Shodan, URLScan APIs | `cache/infra_records.json` | Stage 1B: proactive infra hunting |
| `enrich_infra.py` | `cache/clickgrab_raw.json` | `cache/enriched_infra.json` | Stage 1C: enriches clickgrab infra records with IPinfo + VT |
| `fetch_payload_chains.py` | `cache/ioc_records.json` + `cache/infra_records.json` | `cache/enriched_records.json` | Stage 2: merges 1A+1B, reconstructs URLScan chains, rescores |
| `claude_triage.py` | `cache/enriched_records.json` | `cache/triaged_records.json` | Stage 3: AI payload classification |
| `cluster_campaigns.py` | `cache/triaged_records.json` | `cache/campaigns.json` + `cache/low_confidence_campaigns.json` | Stage 4: hard-signal campaign clustering |
| `build_data.py` | `cache/triaged_records.json` + `cache/campaigns.json` | `_data/masq_infra.json` | Stage 5: final assembly for Jekyll |
| `append_history.py` | `_data/masq_infra.json` | `_data/masq_infra_history.json` | Stage 6: weekly history snapshot |
| `aggregate.py` | YAML chokepoints | `_data/chokepoints.yml` etc. | Independent — Jekyll data build, not pipeline |

### The structural gap

`fetch_payload_chains.py` currently does two things: (1) merges `ioc_records.json` + `infra_records.json` and (2) runs URLScan chain reconstruction. PIPE-01 requires a dedicated `merge_records.py` to make the merge step explicit and independently runnable. The key question is whether `merge_records.py` replaces `fetch_payload_chains.py`'s merge logic, or sits before it.

The REQUIREMENTS.md spec says `merge_records.py` merges three files:
- `cache/ioc_records.json`
- `cache/infra_records.json`
- `cache/enriched_infra.json`

Note: `cache/enriched_infra.json` (written by `enrich_infra.py`) is the third source. `fetch_payload_chains.py` currently reads only the first two, ignoring `enriched_infra.json`. This is a real gap — enriched infra records with ASN/VT data are not flowing into the merged output today.

The intended split after Phase 4: `merge_records.py` → deduplicates and combines all three source files → writes `cache/enriched_records.json`. `fetch_payload_chains.py` would either be retired or become a separate optional URLScan chain enrichment step running on the merged output.

---

## Source Cache Files — What Exists and What Each Writes

[VERIFIED: read each script's I/O declarations]

### Three source cache files (from PIPE-01)

| File | Written by | Schema source | Content |
|------|-----------|---------------|---------|
| `cache/ioc_records.json` | `collect_ioc_feeds.py` | `masq_infra_schema.md` record schema | Feed-confirmed IOC records with SHA-256, family, class, source |
| `cache/infra_records.json` | `collect_infra_hunts.py` | Same schema | Proactively hunted infra candidates; `chain_observed: false`, lower initial confidence |
| `cache/enriched_infra.json` | `enrich_infra.py` | Same schema | `clickgrab_raw.json` entries enriched with IPinfo/VT; distinct from the above two |

### Intermediate files (pipeline stages, not merge inputs)

| File | Written by | Read by |
|------|-----------|---------|
| `cache/enriched_records.json` | `fetch_payload_chains.py` (today) / `merge_records.py` (Phase 4) | `claude_triage.py` |
| `cache/triaged_records.json` | `claude_triage.py` | `cluster_campaigns.py`, `build_data.py` |
| `cache/campaigns.json` | `cluster_campaigns.py` | `build_data.py` |
| `cache/dns_cache.json` | `enrich_infra.py` | `enrich_infra.py` (cache) |
| `cache/vt_cache.json` | `enrich_infra.py` | `enrich_infra.py` (cache) |

The `cache/` directory is empty in git (only `.gitkeep` is tracked) — all cache files are generated at runtime.

---

## Current Confidence Scoring — The Problem

[VERIFIED: read `rescore_record()` in `fetch_payload_chains.py` lines 256-292]

### How `rescore_record()` works today

```python
# Payload confirmation (0–40)
payload_pts = (30 if has_sha256 else 0) + (10 if has_family else 0)

# Delivery confirmation (0–40)
if chain_obs:
    delivery_pts = 40
else:
    source = record.get("source", "")
    if source in ("malwarebazaar", "threatfox", "urlhaus"):
        delivery_pts = 40 if has_domain else 0  # ← feed membership = full points
    else:
        delivery_pts = 30 if has_domain else 0

# Infrastructure signal (0–20)
infra_pts += 10  # if favicon_hash present
infra_pts += 5   # if urlscan_uuid present
infra_pts += 5   # if vt_detected
```

### Why this scores structural completeness, not adversary behavior

A MalwareBazaar record with a SHA-256 and a domain gets `30 + 10 + 40 = 80` → labeled `high` before any chain is traced. The `high` label is awarded for "this record is structurally complete," not "we traced the attacker's delivery chain."

A "confirmed" (≥90) record today requires: SHA-256 + family + chain_observed + favicon + VT detection. Most of those signals are additive data quality indicators, not behavioral evidence.

### What behavior-evidence scoring looks like instead

The behavioral signals already present in the schema that should drive `high`/`confirmed`:

| Signal | Behavioral meaning | Current weight |
|--------|--------------------|---------------|
| `chain_observed: true` | Redirect chain traced end-to-end — attacker infrastructure confirmed | 40 pts (but only used here) |
| `chain_depth >= 2` | Multi-hop delivery chain — strong indicator of evasion intent | Not scored |
| Multi-source: record appears in both IOC feeds AND infra hunts | Two independent collection paths hit the same domain | Not scored (merge doesn't exist) |
| `vt_detected: true` with high count | Community corroboration | 5 pts — underweighted |
| `payload_sha256` appears across multiple domains | Shared payload → campaign-level evidence | Not scored at record level |

A behavior-evidence scoring approach for PIPE-02:
- `confirmed` (≥90): chain traced AND (multi-source corroboration OR shared payload SHA-256 across domains)
- `high` (70-89): chain traced OR (IOC feed + VT detected + family known)
- `medium` (40-69): IOC feed record with SHA-256, no chain
- `low` (<40): hunt candidate with no IOC corroboration

The `confidence_label()` threshold function is duplicated across four scripts (`fetch_payload_chains.py`, `claude_triage.py`, `cluster_campaigns.py`, `build_data.py`) — should be consolidated into a shared utility.

---

## `build_data.py` — Failure Behavior Audit

[VERIFIED: read `build_data.py` in full]

### Current behavior with empty/sparse cache

```python
# build_data.py lines 208-237
records: list = []
if TRIAGED_PATH.exists():
    records = json.loads(TRIAGED_PATH.read_text(...))
# ... no else: sys.exit(1)

filtered = [r for r in records if r.get("confidence", 0) >= CONFIDENCE_THRESHOLD]
# No guard here — filtered can be empty list

output = { "records": filtered, ... }
dest.write_text(json.dumps(output, ...))  # writes empty records to _data/masq_infra.json
```

If `cache/triaged_records.json` is missing, `records = []`. If it exists but all records are below threshold (or cache is sparse), `filtered = []`. In both cases, `build_data.py` exits zero and writes `_data/masq_infra.json` with `"records": []`. The trends page then renders blank.

`append_history.py` is called externally — it is not called from within `build_data.py`. So the history append is not guarded by any check inside `build_data.py` today.

### What PIPE-03 requires

After PIPE-03, `build_data.py` must:
1. Accept a configurable minimum floor (e.g., `MIN_RECORD_FLOOR = 10` as a constant, or `--min-records N` CLI arg)
2. After filtering, check `len(filtered) < MIN_RECORD_FLOOR`
3. If below floor: print error to stderr, `sys.exit(1)` — do NOT write output, do NOT call history append
4. Verifiable by: `echo '[]' > cache/triaged_records.py && python scripts/build_data.py` → exits non-zero

The history append call is external (`append_history.py` is a separate script), so the non-zero exit from `build_data.py` naturally prevents any orchestration script from calling `append_history.py` downstream. No change to `append_history.py` is needed if the pipeline runner checks exit codes.

---

## `claude_triage.py` — What It Expects in `enriched_records.json`

[VERIFIED: read `claude_triage.py` in full]

`claude_triage.py` reads `cache/enriched_records.json` and expects a JSON array of record objects. Each record must have at minimum:
- `domain` (string or None)
- `payload_file_type` (string or None)
- `payload_sha256` (string or None)
- `lure_type` (string or None)
- `lure_brand` (string or None)
- `source` (string or None)
- `vt_detected` (bool or None)
- `vt_detection_count` (int or None)
- `payload_class` (string — `"unknown"` triggers triage)
- `payload_family` (string or None — None triggers triage)
- `confidence` (int — used as base score for `confidence_adjustment`)

If `ENRICHED_PATH` does not exist, `claude_triage.py` writes an empty `triaged_records.json` and exits. This is the exact gap `merge_records.py` closes — nothing currently guarantees `cache/enriched_records.json` exists before `claude_triage.py` runs, because `fetch_payload_chains.py` requires both `ioc_records.json` and `infra_records.json` to be present first, and does not handle the `enriched_infra.json` source at all.

---

## Schema — `_data/masq_infra_schema.md` and Template Contract

[VERIFIED: read `_data/masq_infra_schema.md` in full]

### Top-level output structure (`_data/masq_infra.json`)

| Key | Type | Built by |
|-----|------|---------|
| `meta` | object | `build_data.build_meta()` |
| `records` | array | filtered triaged records |
| `campaigns` | array | from `cache/campaigns.json` |
| `payload_summary` | object | `build_data.build_payload_summary()` |
| `infrastructure_summary` | object | `build_data.build_infrastructure_summary()` |
| `weekly_summary` | array | from `_data/masq_infra_history.json` |

Note: `masq_infra_schema.md` specifies `weekly_summary` as an object, but `build_data.py` writes it as a sorted list from `load_weekly_summary()`. The Liquid template and `append_history.py` are the ground truth for what format is actually consumed.

### Schema mismatch between `build_data.py` and `masq_infra_schema.md`

`masq_infra_schema.md` defines `meta.generated_at` and `meta.schema_version` — `build_data.py` writes `meta.last_updated` and `meta.pipeline_version` (no `schema_version`). This mismatch pre-exists Phase 4 and is documented as: "The trends page is blank because `_data/masq_infra.json` uses the old schema." Phase 4 does not need to fix this unless it blocks PIPE-01/02/03. It is a pre-existing issue to note in the plan.

---

## Architecture Patterns

### Recommended `merge_records.py` structure

```python
"""
merge_records.py — Merge source cache files into cache/enriched_records.json.

Reads:  cache/ioc_records.json
        cache/infra_records.json
        cache/enriched_infra.json
Writes: cache/enriched_records.json

Deduplicates by domain+source. Does NOT enrich (no API calls).
Run before: fetch_payload_chains.py (optional chain enrichment) or claude_triage.py.
"""

SOURCES = [
    (CACHE_DIR / "ioc_records.json",    "ioc"),
    (CACHE_DIR / "infra_records.json",  "infra"),
    (CACHE_DIR / "enriched_infra.json", "enriched_infra"),
]

def merge(sources) -> list[dict]:
    seen: set[str] = set()
    merged: list[dict] = []
    for path, label in sources:
        if not path.exists():
            print(f"[WARN] {path} not found — skipping", file=sys.stderr)
            continue
        records = json.loads(path.read_text(encoding="utf-8"))
        for r in records:
            key = (r.get("domain", ""), r.get("source", label))
            if key not in seen:
                seen.add(key)
                merged.append(r)
    return merged
```

The deduplication key should be `domain` alone, or `domain + source` if the same domain can come from two different feeds legitimately.

### Confidence scoring refactor pattern

Move `confidence_label()` and `rescore_record()` into a shared module (e.g., `scripts/pipeline_utils.py`) and import from there. All four scripts that currently duplicate `confidence_label()` import from the shared module instead.

New `rescore_record()` signal priority:

```python
# Behavioral evidence (0–60)
chain_pts = 40 if chain_observed else 0
multi_source_pts = 20 if multi_source else 0  # requires merge step to set flag

# Payload confirmation (0–30)  
payload_pts = (20 if has_sha256 else 0) + (10 if has_family else 0)

# Corroboration (0–10)
corroboration_pts = (5 if vt_detected else 0) + (5 if vt_count >= 5 else 0)
```

Multi-source flag: `merge_records.py` can set `multi_source: true` on records where the same domain appears in more than one source file before dedup.

### `build_data.py` guard clause pattern

```python
MIN_RECORD_FLOOR = 10  # configurable constant at top of file

filtered = [r for r in records if r.get("confidence", 0) >= CONFIDENCE_THRESHOLD]
if len(filtered) < MIN_RECORD_FLOOR:
    print(
        f"[ERROR] Only {len(filtered)} records pass confidence threshold — "
        f"minimum floor is {MIN_RECORD_FLOOR}. Aborting without writing output.",
        file=sys.stderr,
    )
    sys.exit(1)
```

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead |
|---------|-------------|-------------|
| Deduplication key generation | Custom hashing logic | `domain.lower()` string as dict key — already established pattern in this codebase |
| JSON file I/O with encoding | Custom file writing | `path.write_text(json.dumps(..., ensure_ascii=False), encoding="utf-8")` — already the pattern everywhere |
| Confidence label mapping | New threshold logic | Refactor existing `confidence_label()` into shared util — don't create a new one |
| Argument parsing | `getopt` / manual | `argparse` — already used in `build_data.py` and `cluster_campaigns.py` |

---

## Common Pitfalls

### Pitfall 1: `merge_records.py` duplicates `fetch_payload_chains.py`'s merge

**What goes wrong:** Writing `merge_records.py` that re-implements the full chain enrichment rather than being a pure merge. `fetch_payload_chains.py` already runs URLScan lookups — `merge_records.py` must be a no-API-call merge only.

**How to avoid:** `merge_records.py` reads, deduplicates, and writes. No HTTP calls. Chain enrichment stays in `fetch_payload_chains.py` (or is collapsed into `merge_records.py` and `fetch_payload_chains.py` is retired — either way, the merge step itself must be pure I/O).

### Pitfall 2: The three source files may not all exist

**What goes wrong:** `merge_records.py` crashes if any source file is absent (e.g., `enriched_infra.json` doesn't exist because `enrich_infra.py` wasn't run). The pipeline should degrade gracefully.

**How to avoid:** Wrap each source load in `if path.exists()` with a `[WARN]` log. Output whatever records are available. Only exit non-zero if ALL three sources are missing.

### Pitfall 3: Confidence scoring refactor breaks `claude_triage.py`'s `confidence_adjustment`

**What goes wrong:** `claude_triage.py` applies an additive `confidence_adjustment` (-10 to +10) from the Claude API response. If `rescore_record()` is rewritten to use a new scale, the adjustment may push scores across thresholds differently.

**How to avoid:** Test the new scoring against the existing `confidence_threshold = 40` filter in `build_data.py`. The adjustment range is small (-10 to +10) — just verify the thresholds still make sense.

### Pitfall 4: `build_data.py` guard triggers on legitimately sparse cache

**What goes wrong:** Setting `MIN_RECORD_FLOOR` too high causes the guard to fire in dev/test environments where the cache is intentionally small.

**How to avoid:** Make the floor configurable via `--min-records N` CLI arg with a sensible default (10). Document the `--dry-run` and `--min-records 0` combo for dev use.

### Pitfall 5: `confidence_label()` is duplicated in four scripts

**What goes wrong:** PIPE-02 requires changing confidence label thresholds. If the function isn't consolidated, changing it in `rescore_record()` doesn't affect `claude_triage.py` or `build_data.py`.

**How to avoid:** Create `scripts/pipeline_utils.py` with the shared function and update all four import sites.

---

## Environment Availability

Step 2.6: SKIPPED — Phase 4 is pure Python code changes to existing scripts. No new external services, runtimes, or CLIs are introduced. Existing pipeline API dependencies (URLScan, VT, Anthropic) are unchanged.

---

## Validation Architecture

The project has no test framework configured. [ASSUMED] Based on Python project conventions and the validation harness mentioned in STATE.md (`Streamlit validation harness`), the intended verification approach is:

1. Run `merge_records.py` with synthetic cache files and verify `enriched_records.json` output
2. Run `build_data.py` with a sparse synthetic `triaged_records.json` and verify non-zero exit
3. Spot-check confidence labels on a sample of records against the new scoring logic

No pytest infrastructure exists. [ASSUMED] The plan should include manual verification steps rather than automated test commands.

### Phase Requirements to Test Map

| ID | Behavior | Verification |
|----|----------|-------------|
| PIPE-01 | `merge_records.py` produces `cache/enriched_records.json` from three sources | Run script with mock inputs, check file exists and contains records from all three sources |
| PIPE-02 | `confirmed`/`high` records reflect behavioral evidence | Sample 10 records from output; manually verify each high/confirmed record has `chain_observed: true` or multi-source flag |
| PIPE-03 | `build_data.py` exits non-zero on sparse cache | `echo '[]' > cache/triaged_records.json && python scripts/build_data.py; echo $?` should print non-zero |

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | No pytest or test framework is configured | Validation Architecture | If tests exist elsewhere, plan should include running them |
| A2 | `merge_records.py` should be a pure merge with no API calls | Architecture Patterns | If chain enrichment should also move here, `fetch_payload_chains.py` needs retirement plan |
| A3 | `MIN_RECORD_FLOOR = 10` is a reasonable default | `build_data.py` guard | If Tyler has a different floor in mind, make it a CLI arg default |

---

## Open Questions

1. **Should `merge_records.py` replace `fetch_payload_chains.py`?**
   - What we know: `fetch_payload_chains.py` does both merge AND URLScan enrichment. PIPE-01 calls for a dedicated merge script.
   - What's unclear: Does Phase 4 retire `fetch_payload_chains.py`, or does `merge_records.py` become a pre-step that feeds into it?
   - Recommendation: Write `merge_records.py` as the explicit merge step. Leave `fetch_payload_chains.py` runnable as an optional chain-enrichment step. Document the recommended run order.

2. **Multi-source deduplication key**
   - What we know: Records from `ioc_records.json` and `infra_records.json` could have the same domain with different `source` values.
   - What's unclear: Should a domain from both MalwareBazaar and a Shodan hunt be merged into one record (domain as key) or kept as two (domain+source as key)?
   - Recommendation: Deduplicate by domain only; set `multi_source: true` if seen in 2+ source files. This enables the multi-source corroboration signal for PIPE-02.

---

## Sources

### Primary (HIGH confidence)
- `scripts/build_data.py` — read in full; all behavior documented directly
- `scripts/claude_triage.py` — read in full; input expectations confirmed
- `scripts/fetch_payload_chains.py` — read in full; `rescore_record()` logic extracted
- `scripts/collect_ioc_feeds.py` — read header + paths; output file confirmed
- `scripts/collect_infra_hunts.py` — read header + paths; output file confirmed
- `scripts/enrich_infra.py` — read header + paths; output file confirmed
- `scripts/cluster_campaigns.py` — read header + paths; input/output confirmed
- `scripts/append_history.py` — read in full; called externally, no guard
- `_data/masq_infra_schema.md` — read in full; field definitions verified

### Secondary (MEDIUM confidence)
- `cache/.gitkeep` — confirms cache/ exists in git with no actual cache files
- STATE.md notes on pipeline gap — consistent with code audit findings

---

## Metadata

**Confidence breakdown:**
- Pipeline structure: HIGH — every script read directly
- Source cache files: HIGH — confirmed by reading each script's I/O paths
- Confidence scoring problem: HIGH — `rescore_record()` read in full, scoring math extracted
- `build_data.py` failure behavior: HIGH — read in full, no guard confirmed
- Schema: HIGH — `masq_infra_schema.md` read in full
- `claude_triage.py` expectations: HIGH — read in full

**Research date:** 2026-04-11
**Valid until:** 2026-05-11 (scripts are stable; no external dependencies changing)
