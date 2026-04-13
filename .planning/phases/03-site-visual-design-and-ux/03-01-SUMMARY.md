---
phase: 03-site-visual-design-and-ux
plan: "01"
subsystem: frontend-ux
tags: [css, javascript, liquid, mobile, sigma-blocks, copy-button]
dependency_graph:
  requires: []
  provides: [sigma-tier-accents, copy-button-feedback, mobile-table-scroll]
  affects: [_layouts/chokepoint.html, trends/masq-infra.md]
tech_stack:
  added: []
  patterns:
    - CSS modifier classes (.sigma-block--research/hunt/analyst) for tier visual identity
    - classList.add/remove toggling for transient UI feedback states
    - .table-wrapper div wrapping for mobile horizontal scroll on bare tables
key_files:
  created: []
  modified:
    - _layouts/chokepoint.html
    - trends/masq-infra.md
decisions:
  - Use .sigma-btn.copied selector (not .copy-btn.copied) because copy buttons use .sigma-btn class
  - Apply sigma_tier via Liquid | remove: "_sigma_" filter to extract tier name from existing sigma_key variable
  - Hard-code sigma-block--hunt on the hunt-network block since it is explicitly labeled Hunt Level
  - Wrap tables in masq-infra.md preemptively even though page is currently blank (pipeline data not yet available)
  - Leave EarlyDetections (ETW/IOK) and Emulation sigma-block locations without tier accents — they are not tiered Sigma rules
metrics:
  duration: "~20 minutes"
  completed: "2026-04-11"
  tasks_completed: 3
  tasks_total: 3
  files_modified: 2
---

# Phase 03 Plan 01: Copy Button Feedback, Tier Accents, Mobile Tables Summary

CSS copy-button feedback state, three tier accent left-border classes with Liquid wiring at all relevant sigma-block locations, and table-wrapper divs on all 5 bare cg-table elements in masq-infra.md.

## Tasks Completed

| # | Task | Commit | Files |
|---|------|--------|-------|
| 1 | Add copy-button .copied CSS state and tier accent CSS | ce0c0b8 | `_layouts/chokepoint.html` |
| 2 | Wire tier modifier classes into Liquid sigma-block locations | 5c5a39c | `_layouts/chokepoint.html` |
| 3 | Wrap cg-table elements in masq-infra.md with table-wrapper | a878545 | `trends/masq-infra.md` |

## What Was Built

**UX-01 — Copy button feedback (ce0c0b8, 5c5a39c)**

Added `.sigma-btn.copied` CSS rule with `color: var(--medium)` and `border-color: rgba(63,185,80,.4)` to the inline `<style>` block of `chokepoint.html`. Updated `copyCode()` JS to call `btn.classList.add('copied')` on click and `btn.classList.remove('copied')` inside the setTimeout callback. The button now shows both a text change ("Copied!") and a green color change for 1.8 seconds.

**UX-02 — Tier accent left borders (ce0c0b8, 5c5a39c)**

Added three CSS modifier classes to `chokepoint.html`:
- `.sigma-block--research` — 4px blue left border (`var(--link)`)
- `.sigma-block--hunt` — 4px amber left border (`var(--high)`)
- `.sigma-block--analyst` — 4px green left border (`var(--medium)`)

Wired into the template at three of the six sigma-block locations:
1. Accordion detection rules — `{% assign sigma_tier = sigma_key | remove: "_sigma_" %}` then `sigma-block--{{ sigma_tier | default: 'research' }}`
2. Hunt-network hard-coded block — `sigma-block--hunt` (static, confirmed by label text)
3. Research/Hunt/Analyst tabs loop — `sigma-block--{{ level_lower | default: 'research' }}`

Three non-tiered locations (EarlyDetections x2, Emulation block) left unchanged per plan spec.

**UX-03 — Mobile table scroll on trend pages (a878545)**

Wrapped all 5 bare `<table class="cg-table">` elements in `trends/masq-infra.md` with `<div class="table-wrapper">...</div>`. The `.table-wrapper { overflow-x: auto }` rule already exists in `style.css`. Tables will scroll horizontally on narrow (390px) viewports instead of bleeding outside the page body.

## Verification Results

All plan verification checks passed:

```
1. sigma-block--research in chokepoint.html:  1  (PASS)
2. sigma-btn.copied in chokepoint.html:       1  (PASS)
3. classList.add in chokepoint.html:          3  (PASS)
4. sigma-block--{{ in chokepoint.html:        2  (PASS)
5. table-wrapper in masq-infra.md:            5  (PASS)
6. jekyll build --strict:                     exit 0, no warnings (PASS)
```

## Deviations from Plan

None. Plan executed exactly as written.

## Known Stubs

None. All three UX changes are fully wired. The masq-infra.md tables are wrapped preemptively — the page renders blank until the collection pipeline runs, but the wrappers are in place for when data arrives.

## Threat Flags

No new trust boundaries introduced. Changes are CSS modifier classes, a classList toggle in existing client-side JS, and div wrappers in Markdown. No new network endpoints, auth paths, or data flows.

## Self-Check

- [x] `_layouts/chokepoint.html` modified — verified by grep counts above
- [x] `trends/masq-infra.md` modified — verified by grep count (5 table-wrapper)
- [x] Commit ce0c0b8 exists — `git log` confirmed
- [x] Commit 5c5a39c exists — `git log` confirmed
- [x] Commit a878545 exists — `git log` confirmed
- [x] `jekyll build --strict` exits 0 — verified above

## Self-Check: PASSED
