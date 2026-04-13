# Roadmap: Detection Chokepoints v1.0

## Milestone: v1.0 — Site Quality and Pipeline Integrity

**Goal:** Deliver a stable, consistent, professionally presented knowledge base with a functioning OSINT data pipeline — no build warnings, clean prose throughout, usable Sigma rule UX, and accurate threat intel data feeding the trends section.
**Success:** `jekyll build --strict` passes clean, all pages read with Tyler's voice, Sigma rules are copy-paste ready with visual tier differentiation, and the OSINT pipeline produces correlated records with honest confidence labels.

---

## Phases

- [ ] **Phase 1: Baseline Cleanup** — Remove generated files from git tracking, fix the Liquid positional index bug, get `jekyll build --strict` to pass clean. Prerequisite for all other phases.
- [ ] **Phase 2: Writing and Content Consistency** — Full prose pass across every page: em dashes removed, sentences tightened, voice consistent, `WhyCantBypass`/`TheConstant` visually dominant.
- [ ] **Phase 3: Site Visual Design and UX** — Copy-to-clipboard on Sigma code blocks, maturity tier left-border accents, mobile table reflow. Template changes only; no URL or slug changes.
- [ ] **Phase 4: OSINT Pipeline Fix** — Write `merge_records.py`, fix confidence scoring, add minimum-record guard in `build_data.py`, validate with Streamlit harness.

---

## Phase Details

### Phase 1: Baseline Cleanup
**Goal:** The build is clean, generated files are out of git, and the Liquid positional index bug is fixed — every other phase starts from a stable foundation.
**Depends on:** Nothing
**Requirements:** BSLN-01, BSLN-02, BSLN-03
**Success criteria:**
- [ ] `_data/chokepoints.yml`, `_chokepoints/`, and `assets/js/search-index.json` are confirmed gitignored and absent from git tracking (verified with `git ls-files`)
- [ ] Chokepoint detail pages render correct content at every stage position — not just the second stage
- [ ] `jekyll build --strict` exits zero with no warnings or errors
**Plans:** 1 plan

Plans:
- [ ] 01-01-PLAN.md — Verify git hygiene, fix positional index bug, fix Liquid syntax error, verify clean strict build

### Phase 2: Writing and Content Consistency
**Goal:** Every public-facing page reads with Tyler's voice — concise, evidence-first, peer-to-peer — and the invariant content (`WhyCantBypass`, `TheConstant`) is the visual anchor on each chokepoint page.
**Depends on:** Phase 1
**Requirements:** WRIT-01, WRIT-02, WRIT-03, WRIT-04
**Success criteria:**
- [ ] No em dashes appear anywhere in rendered page output (chokepoints, trends, docs, layouts)
- [ ] Every sentence carries its own weight — no filler phrases, no throat-clearing intros
- [ ] A first-time reader lands on any chokepoint page and immediately sees the invariant (`WhyCantBypass` / `TheConstant`) without scrolling past tool lists or variant tables
- [ ] Voice is consistent across all chokepoint and trend pages — reads as one author, not a patchwork
**Plans:** 2 plans

Plans:
- [ ] 02-01-PLAN.md — Em dash removal and voice tightening across YAML and trends Markdown content (Wave 1)
- [ ] 02-02-PLAN.md — Add TheConstant to chokepoint detail-page header and remove template em dashes (Wave 2)

### Phase 3: Site Visual Design and UX
**Goal:** Sigma rules are easy to copy and visually differentiated by maturity tier; tables work on mobile; no URL changes introduced.
**Depends on:** Phase 1
**Requirements:** UX-01, UX-02, UX-03
**Success criteria:**
- [ ] Every Sigma rule code block (research, hunt, analyst) has a working copy-to-clipboard button that copies the full rule text
- [ ] Research, hunt, and analyst Sigma blocks are visually distinct via left-border accent color — a reader can identify tier at a glance without reading the label
- [ ] Overflow tables on chokepoint and trend pages reflow cleanly on a 390px viewport with no horizontal scroll bleed
- [ ] `jekyll build --strict` passes clean after every template change introduced in this phase
**Plans:** 1 plan

Plans:
- [ ] 03-01-PLAN.md — Copy button feedback, tier accent left borders, mobile table wrappers

### Phase 4: OSINT Pipeline Fix
**Goal:** The OSINT collection pipeline produces a complete, correlated `enriched_records.json` with confidence labels that reflect adversary-behavior evidence, and `build_data.py` fails loudly rather than silently publishing empty data.
**Depends on:** Phase 1
**Requirements:** PIPE-01, PIPE-02, PIPE-03
**Success criteria:**
- [ ] `merge_records.py` exists, runs without error, and produces `cache/enriched_records.json` from the three source cache files using the shared record schema
- [ ] A record labeled `confirmed` or `high` confidence reflects multi-source corroboration or a confirmed payload chain — not just structural completeness (presence of SHA-256 or domain)
- [ ] `build_data.py` exits non-zero and skips the history append when the assembled record count falls below the configured minimum floor — verified by running with a deliberately sparse cache
**Plans:** 2 plans

Plans:
- [x] 04-01-PLAN.md — Create pipeline_utils.py (shared scoring) and merge_records.py (three-source merge)
- [x] 04-02-PLAN.md — Update four scripts to import shared scoring, add floor guard to build_data.py

---

## Progress

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Baseline Cleanup | 0/1 | Not started | - |
| 2. Writing and Content Consistency | 0/? | Not started | - |
| 3. Site Visual Design and UX | 0/1 | Not started | - |
| 4. OSINT Pipeline Fix | 0/2 | Not started | - |

---

*Roadmap created: 2026-04-11*
*Milestone: v1.0*
*Coverage: 13/13 v1 requirements mapped*
