---
phase: 04-osint-pipeline-fix
plan: "01"
subsystem: scripts/pipeline
tags: [python, pipeline, scoring, merge, osint]
dependency_graph:
  requires: []
  provides: [pipeline_utils.py, merge_records.py]
  affects: [scripts/collect_ioc_feeds.py, scripts/collect_infra_hunts.py, scripts/enrich_infra.py, scripts/fetch_payload_chains.py]
tech_stack:
  added: []
  patterns: [behavioral-scoring, two-pass-dedup, graceful-degradation]
key_files:
  created:
    - scripts/pipeline_utils.py
    - scripts/merge_records.py
  modified: []
decisions:
  - "SHA-256 presence dropped from 30pts to 5pts — structural completeness is not behavioral evidence"
  - "Feed membership (malwarebazaar/threatfox/urlhaus) drops to 0pts — feed inclusion is not adversary behavior"
  - "Two-pass merge: first build domain->sources map, then dedup — required for correct multi_source flagging before dedup collapses duplicates"
  - "First occurrence wins in dedup (ioc > infra > enriched_infra) — ioc feeds are most authoritative for identity fields"
metrics:
  duration: "~12 minutes"
  completed: "2026-04-12"
  tasks_completed: 2
  tasks_total: 2
  files_created: 2
  files_modified: 0
---

# Phase 04 Plan 01: Pipeline Utils and Merge Script Summary

Behavioral confidence scoring extracted into `pipeline_utils.py` and three-source cache merge implemented in `merge_records.py`, closing the structural gap that blocked Wave 2 from importing shared scoring logic.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Create pipeline_utils.py with shared scoring functions | 4bbb840 | scripts/pipeline_utils.py |
| 2 | Create merge_records.py to combine three source cache files | 1a7f526 | scripts/merge_records.py |

## What Was Built

### pipeline_utils.py

Exports two functions used by all pipeline scripts:

- `confidence_label(score)` — maps 0-100 integer to `confirmed / high / medium / low`
- `rescore_record(record)` — recomputes confidence using behavioral evidence signals

Scoring weights (PIPE-02 compliant):

| Signal | Points | Rationale |
|--------|--------|-----------|
| chain_observed | 40 | Adversary behavior traced end-to-end |
| multi_source | 20 | Cross-feed corroboration |
| payload_family | 15 | Analyst identification of malware family |
| vt_detected | 10 | Community corroboration |
| vt_detection_count >= 5 | 5 | Strong community signal |
| chain_depth >= 3 | 5 | Multi-hop = evasion intent |
| payload_sha256 | 5 | Structural, not behavioral |

Key change from the old `rescore_record` in `fetch_payload_chains.py`:
- SHA-256 dropped from 30pts to 5pts (structural artifact, not behavioral evidence)
- Feed membership dropped to 0pts (being in a feed is not adversary behavior)
- `multi_source` added at 20pts (requires merge step)
- `vt_detected` raised from 5pts to 10pts (community corroboration is behavioral)
- `chain_depth >= 3` added at 5pts (multi-hop = evasion intent)

Result: SHA-256 + domain + feed = 5pts (`low`). chain_observed + multi_source + family + sha256 + VT + deep chain = 100pts (`confirmed`).

### merge_records.py

Three-source merge into `cache/enriched_records.json`:

- Reads `cache/ioc_records.json`, `cache/infra_records.json`, `cache/enriched_infra.json`
- Two-pass dedup: first pass builds domain->sources map, second pass deduplicates
- Sets `multi_source=True` on records whose domain appears in 2+ source files
- First occurrence wins (ioc > infra > enriched_infra priority)
- Handles missing source files gracefully — WARN but continue
- Exits non-zero only if ALL sources are missing or empty
- No API calls — pure I/O merge
- Imports `rescore_record` from `pipeline_utils`

## Verification Results

All five plan verifications passed:

1. `from scripts.pipeline_utils import confidence_label, rescore_record` — exits 0
2. `from merge_records import merge` (with scripts/ on path) — exits 0
3. Structural record (SHA-256 + domain + feed) scores 5 (`low`)
4. Behavioral record (chain + multi_source + family + VT) scores 100 (`confirmed`)
5. Missing source file produces WARN but does not crash

## Deviations from Plan

None — plan executed exactly as written. Both scripts match the exact content specified in the plan.

## Known Stubs

None. Both scripts are fully functional. `merge_records.py` requires the upstream collection scripts to have run first (to populate the cache files), but that is the intended operation model.

## Threat Flags

None. No new network endpoints, auth paths, or trust boundaries introduced. Both scripts perform local file I/O only.

## Self-Check: PASSED

Files exist:
- scripts/pipeline_utils.py: FOUND
- scripts/merge_records.py: FOUND

Commits exist:
- 4bbb840 (pipeline_utils.py): FOUND
- 1a7f526 (merge_records.py): FOUND
