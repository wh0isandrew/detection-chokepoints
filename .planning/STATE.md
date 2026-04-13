---
gsd_state_version: 1.0
milestone: v1.0
milestone_name: — Site Quality and Pipeline Integrity
status: executing
last_updated: "2026-04-12T16:45:09.083Z"
progress:
  total_phases: 4
  completed_phases: 2
  total_plans: 6
  completed_plans: 2
  percent: 33
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-04-11)

**Core value:** Chokepoint-focused detections that survive campaigns and tool rotation — the highest-ROI coverage a detection engineer can build.
**Current focus:** Phase 04 — osint-pipeline-fix

---

## Current Phase

Phase 1 of 4: Baseline Cleanup
Status: Executing Phase 01

---

## Key Decisions

| Decision | Rationale |
|----------|-----------|
| Phase 1 is a hard prerequisite for all other phases | Generated files in git corrupt every workstream — `_data/chokepoints.yml`, `_chokepoints/`, and `assets/js/search-index.json` must be untracked before any content or template work begins |
| Phases 2 and 3 can run in parallel after Phase 1 | Writing (Phase 2) and visual design (Phase 3) are independent workstreams once the build is clean |
| Phase 4 can also run in parallel with Phases 2-3 | Pipeline work is independent of site content and templates; start early given API rate limit unpredictability |
| No URL or slug changes in Phase 3 | Visual-only changes to avoid breaking inbound links and GitHub Pages routing |
| `jekyll build --strict` must pass after every template change | Prevents silent regressions from accumulating across Phase 3 changes |
| Streamlit harness is validation-only | Accuracy must be confirmed over multiple daily runs before wiring pipeline output into the site; harness stays local, never shipped |
| Confidence scoring refactor is scoped to Phase 4 | Current scoring rewards structural completeness (has SHA-256) not adversary-behavior evidence — must be separated before publishing labeled records |

---

## Blockers

None

---

## Notes

**From research — carry forward:**

- The Liquid positional index bug (`forloop.parentloop.index == 2`) will produce wrong stage content for any chokepoint where the detection stage isn't literally the second item. Fix is field-based matching. Validate with `jekyll build --strict` after.
- `merge_records.py` is the only structural gap in the pipeline. `claude_triage.py` reads `cache/enriched_records.json` but nothing writes it. Phase 4 starts here.
- The trends page is blank because `_data/masq_infra.json` uses the old schema from `update_masq_infra.py`. The Liquid templates already reference the new schema. Running the corrected pipeline end-to-end should fix it without touching templates.
- `_data/masq_infra.json` is the sole contract boundary between pipeline and site. Pipeline internals can change freely as long as output matches `_data/masq_infra_schema.md`.
- Collection (API keys, local or private CI) is intentionally separate from the public GitHub Pages build (`aggregate.py` + `jekyll build` only, no API keys). This split must stay.
- Writing cleanup is partially done per recent commits. Phase 2 needs a full pass — not just a spot check.

---

## Performance Metrics

| Metric | Value |
|--------|-------|
| Phases defined | 4 |
| v1 requirements | 13 |
| Requirements mapped | 13/13 |
| Plans complete | 0 |
| Phases complete | 0 |

---

*State initialized: 2026-04-11*
*Next action: Run `/gsd-plan-phase 1` to plan Phase 1 — Baseline Cleanup*
