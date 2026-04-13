---
phase: 04-osint-pipeline-fix
plan: "02"
subsystem: scripts/pipeline
tags: [python, pipeline, scoring, refactor, floor-guard]
dependency_graph:
  requires: [pipeline_utils.py, merge_records.py]
  provides: [scoring-consolidation, build-data-floor-guard]
  affects: [scripts/fetch_payload_chains.py, scripts/claude_triage.py, scripts/cluster_campaigns.py, scripts/build_data.py]
tech_stack:
  added: []
  patterns: [single-source-of-truth-scoring, fail-loud-guard]
key_files:
  created: []
  modified:
    - scripts/fetch_payload_chains.py
    - scripts/claude_triage.py
    - scripts/cluster_campaigns.py
    - scripts/build_data.py
decisions:
  - "confidence_label is now defined in exactly one place (pipeline_utils.py); four scripts import it"
  - "rescore_record is defined in exactly one place (pipeline_utils.py); fetch_payload_chains.py imports it"
  - "MIN_RECORD_FLOOR default is 5 — low enough to not block real runs, high enough to catch empty-cache accidents"
  - "--min-records 0 disables the floor guard for dev/test without touching constants"
metrics:
  duration: "~10 minutes"
  completed: "2026-04-12"
  tasks_completed: 2
  tasks_total: 2
  files_created: 0
  files_modified: 4
---

# Phase 04 Plan 02: Scoring Consolidation and Floor Guard Summary

Removed four copies of `confidence_label` and one copy of `rescore_record` from pipeline scripts, replacing all with imports from `pipeline_utils.py`. Added a configurable minimum-record floor guard to `build_data.py` that exits non-zero and suppresses output when too few records pass the confidence threshold.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Replace inline confidence_label and rescore_record with pipeline_utils imports | 3e67438 | scripts/fetch_payload_chains.py, scripts/claude_triage.py, scripts/cluster_campaigns.py, scripts/build_data.py |
| 2 | Add minimum-record floor guard to build_data.py | b779cb3 | scripts/build_data.py |

## What Was Built

### Task 1: Scoring Consolidation (PIPE-02)

Removed all duplicate scoring logic from the four pipeline scripts:

- `fetch_payload_chains.py`: removed inline `confidence_label` (8 lines) and inline `rescore_record` (37 lines); added `from pipeline_utils import confidence_label, rescore_record`
- `claude_triage.py`: removed inline `confidence_label` (8 lines); added `from pipeline_utils import confidence_label`
- `cluster_campaigns.py`: removed inline `confidence_label` (8 lines); added `from pipeline_utils import confidence_label`
- `build_data.py`: removed inline `confidence_label` (8 lines); added `from pipeline_utils import confidence_label`

Total: 83 lines deleted, 8 lines added across 4 files. `confidence_label` now has exactly one definition. `rescore_record` now has exactly one definition.

Note: The old inline `rescore_record` in `fetch_payload_chains.py` used a different scoring model (SHA-256 = 30pts, no multi_source signal). The `pipeline_utils.rescore_record` uses the PIPE-02 behavioral model (chain_observed = 40pts, multi_source = 20pts, SHA-256 = 5pts). This is an intentional behavioral change — the pipeline_utils version is the correct one per the PIPE-02 spec.

### Task 2: Minimum-Record Floor Guard (PIPE-03)

Added to `build_data.py`:

- `MIN_RECORD_FLOOR = 5` constant alongside `CONFIDENCE_THRESHOLD`
- `--min-records` CLI argument (default: `MIN_RECORD_FLOOR`, set to 0 to disable)
- Floor guard block after filtering, before output dict assembly: exits `sys.exit(1)` without writing `_data/masq_infra.json` when `len(filtered) < floor`

Verified behavior:
- Empty `triaged_records.json` with default floor (5): prints `[ERROR]`, exits 1, no output file written
- `--min-records 0`: guard disabled, exits 0, output file written normally
- `--dry-run` still works independently (orthogonal flag)

## Verification Results

All plan verifications passed:

1. `grep -c "from pipeline_utils import"` returns 1 for all four scripts
2. `grep -c "def confidence_label"` returns 0 for all four scripts
3. `grep -c "def rescore_record"` returns 0 for `fetch_payload_chains.py`
4. `grep -c "MIN_RECORD_FLOOR"` returns 3 in `build_data.py`
5. `grep -c "min-records"` returns 2 in `build_data.py`
6. `grep -c "sys.exit(1)"` returns 1 in `build_data.py`
7. Empty cache + `--min-records 5`: exits 1, no output file written
8. Empty cache + `--min-records 0`: exits 0, output file written

## Deviations from Plan

None — plan executed exactly as written.

## Known Stubs

None. All four scripts are fully functional with the shared scoring module.

## Threat Flags

None. No new network endpoints, auth paths, or trust boundaries introduced. The `--min-records 0` bypass is operator-controlled and documented (T-04-05 accepted per plan threat model).

## Self-Check: PASSED

Files modified:
- scripts/fetch_payload_chains.py: FOUND — contains `from pipeline_utils import confidence_label, rescore_record`, no inline definitions
- scripts/claude_triage.py: FOUND — contains `from pipeline_utils import confidence_label`, no inline definition
- scripts/cluster_campaigns.py: FOUND — contains `from pipeline_utils import confidence_label`, no inline definition
- scripts/build_data.py: FOUND — contains `from pipeline_utils import confidence_label`, `MIN_RECORD_FLOOR`, `--min-records`, `sys.exit(1)`

Commits exist:
- 3e67438 (Task 1 — scoring consolidation): FOUND
- b779cb3 (Task 2 — floor guard): FOUND
