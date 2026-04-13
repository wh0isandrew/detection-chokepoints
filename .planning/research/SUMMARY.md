# Research Summary

## Stack

- Existing stack is correct and stays. The pipeline's bugs are logic and schema-handling issues, not library problems.
- Add `pydantic>=2.7` for a shared `MasqRecord` model with parse-time validation at each source's ingestion boundary — replaces scattered `or {}` / `isinstance` guards.
- Add `pytest>=8.2`, `responses>=0.25`, `respx>=0.21`, `pytest-asyncio>=0.23` for unit-testable pipeline stages with no live API keys.
- Scheduling: one new GitHub Actions workflow YAML (`update-intel.yml` with `on: schedule: cron`) + `stefanzweifel/git-auto-commit-action@v5`. Zero new infrastructure.
- No Celery, no APScheduler, no polars, no marshmallow — all redundant given the GitHub Pages constraint and existing dependencies.

## Table Stakes

- **Copy-to-clipboard on code blocks** — highest-priority UX gap. Sigma rules are the primary deliverable; drag-select breaks YAML indentation. Every modern reference site ships this.
- **Visual differentiation between Sigma maturity tiers** — research and analyst rules currently render at identical visual weight. A left-border accent color per tier reinforces the site's core differentiator with minimal CSS.
- **Consistent data freshness signals on trend pages** — the clickgrab page gets it right (explicit collection window, sample size, generation timestamp). Apply the same pattern to all trend pages.
- **IOK rules visible in nav and index** — one of the site's strongest differentiators is invisible to first-time visitors. Needs a nav entry and index filter chip.
- **Mobile table reflow** — engineers read during incidents on phones; overflow tables break the experience.

## Watch Out For

- **Generated files in git** — confirm `.gitignore` covers `_data/chokepoints.yml`, `_chokepoints/`, and `assets/js/search-index.json` and `git rm --cached` if needed. Must be the first commit. Every other workstream is affected.
- **Silent pipeline failure publishing empty data** — add a minimum-record guard in `build_data.py` (exit non-zero if record count < floor) and run Streamlit validation harness over multiple days before wiring output to the site.
- **Confidence score inflation** — the scoring model awards points for structural completeness (has SHA-256, has domain), not threat certainty. Separate `data_quality` from `confidence` before publishing labeled records to the community.
- **Partial API runs poisoning history** — add `partial_run: true` flag and skip appending partial runs to `masq_infra_history.json`. Treat each of the seven sources as independently optional.
- **Liquid positional index matching** — `forloop.parentloop.index == 2` hardcoding in templates produces wrong output for chokepoints with different stage counts. Replace with field-based matching and validate with `jekyll build --strict` after every template change.

## Architecture Decisions

- **One missing script blocks the full pipeline.** `claude_triage.py` reads `cache/enriched_records.json` but nothing writes it. A `merge_records.py` that merges `ioc_records.json` + `infra_records.json` + `enriched_infra.json` is the only structural gap.
- **Schema mismatch is why the trends page is blank.** The committed `_data/masq_infra.json` uses the old schema from `update_masq_infra.py`. The Liquid templates already reference the new schema. Not a template bug — the pipeline just hasn't produced new output yet.
- **`_data/masq_infra.json` is the sole contract boundary.** Pipeline internals can change as long as output matches `_data/masq_infra_schema.md`. Everything in `cache/` is ephemeral and gitignored.
- **Collection context is separate from build context.** Collection runs locally or in a private CI job with API keys. The public GitHub Pages workflow (`pages.yml`) runs only `aggregate.py` + `jekyll build` — no API keys, no collection. This split is correct and must stay.
- **Domain-centric correlation key is correct.** `sha256(domain + payload_sha256)` as the identity key. Field-level merging (best non-null value per field across source records for the same domain) is a worthwhile improvement over winner-takes-all deduplication.

## Recommended Phase Order

**Phase 1 — Baseline Cleanup** (no content changes)
Confirm `.gitignore` coverage, `git rm --cached` generated files if needed, fix Liquid positional index bug, verify `jekyll build --strict` passes. Prerequisite for everything else.

**Phase 2 — OSINT Pipeline Fix**
Write `merge_records.py`, add Pydantic `MasqRecord` model, fix confidence scoring, add partial-run guard, run full pipeline, validate with Streamlit harness, wire scheduled GitHub Actions workflow. Can run in parallel with Phase 3. Start early — API rate limits make timeline unpredictable.

**Phase 3 — Writing and Content Consistency Pass**
Create prose calibration reference first. Edit all chokepoint and trend pages in fewest sessions possible. Make `WhyCantBypass`/`TheConstant` visually dominant. No template changes. Do before Phase 4 so design wraps stable prose.

**Phase 4 — Visual Design and Navigation/UX Pass**
Copy buttons, maturity tier left-border accents, IOK nav/filter entry, mobile table reflow, inline `<style>` audit and migration to `style.css`. No URL changes, no slug renames. `jekyll build --strict` after every template change.
