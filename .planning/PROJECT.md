# Detection Chokepoints

## What This Is

Detection Chokepoints is a detection engineering knowledge base for the security community. It documents invariant prerequisites — the conditions every attacker must satisfy for a technique to work, regardless of tool rotation or variant — and maps them to durable, ROI-focused detection strategies at three Sigma maturity levels. The site is a Jekyll static site, data-driven from YAML, hosted on GitHub Pages.

## Core Value

Chokepoint-focused detections that survive campaigns and tool rotation — the highest-ROI coverage a detection engineer can build.

## Requirements

### Validated

- ✓ Chokepoint YAML data model (invariants, variations, detection tiers, evolution timeline) — existing
- ✓ Sigma rules at three maturity levels (research / hunt / analyst) per chokepoint — existing
- ✓ Jekyll static site with GitHub Pages CI/CD deployment — existing
- ✓ Python aggregate.py pre-build pipeline (YAML → Jekyll data + search index) — existing
- ✓ Client-side Fuse.js fuzzy search — existing
- ✓ IOK rules for phishing/lure page detection — existing
- ✓ Emulation scripts (PowerShell) for lab validation — existing
- ✓ Attack chain documentation (JSON) — existing
- ✓ OSINT collection scripts for threat intelligence — existing
- ✓ Trends section with masquerading software page (partial) — existing

### Active

- [ ] Writing cleanup: remove all em dashes, enforce brevity, match Tyler's voice across all pages
- [ ] Site visual design polish (layout, typography, color, consistency)
- [ ] Site navigation and UX improvements
- [ ] Fix OSINT data pipeline: correct correlation logic across URLhaus, URLScan, and other sources
- [ ] Validate pipeline accuracy over multiple daily runs using Streamlit POC harness
- [ ] Populate masquerading software trends page with accurate, correlated data

### Out of Scope

- Backend or server-side runtime — static site only, no API
- Streamlit app as a shipped product — validation harness only, not part of the site
- New chokepoint categories — content expansion deferred to future milestone
- Contributor workflow/portal — deferred, site is primarily Tyler's reference and portfolio

## Context

- **Brownfield:** Existing codebase with 8+ chokepoint pages, 26+ Sigma rules, 75+ variants. Aggregate.py is the central build pipeline.
- **Trends pipeline:** Scripts in `scripts/` collect OSINT data (URLhaus, URLScan, etc.) but correlation logic is broken. Streamlit app (`kitsune/`) is a POC to test data accuracy over multiple days before wiring it into the site.
- **Writing state:** Em dash removal and style cleanup partially done (recent commits). Needs a full pass across all pages.
- **Target audience:** Security community — detection engineers, threat hunters, SOC analysts seeking durable, high-ROI detection strategies.
- **Deployment:** GitHub Pages via `.github/workflows/pages.yml` — Python pre-build then Jekyll build on push to main.

## Constraints

- **Tech stack:** Jekyll + GitHub Pages — no runtime backend. All data must be static at build time.
- **Data pipeline:** Trends data feeds through aggregate.py before it can appear on the site. Pipeline fixes must preserve the existing YAML schema contract.
- **Streamlit POC:** `kitsune/` app is a local test harness only. Do not ship it or integrate it into the Jekyll site.
- **YAML schema:** `schema/chokepoint-schema.yml` defines valid fields. Site changes must not break existing chokepoint rendering.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Streamlit app is validation-only | Accuracy must be confirmed over multiple daily runs before wiring data into the site | — Pending |
| Writing cleanup before feature work | Consistency and voice matter for community credibility; clean prose reduces cognitive load | — Pending |
| Static site only (no backend) | GitHub Pages hosting, zero infrastructure cost, simple deployment | ✓ Good |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd-transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd-complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-04-11 after initialization*
