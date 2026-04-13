---
phase: 01-baseline-cleanup
plan: "01"
subsystem: jekyll-build
tags: [gitignore, liquid, chokepoint-layout, sigma-display, build-hygiene]
dependency_graph:
  requires: []
  provides: [clean-strict-build, field-based-detection-routing, generated-files-gitignored]
  affects: [_layouts/chokepoint.html, .gitignore]
tech_stack:
  added: []
  patterns: [field-based-liquid-matching, two-step-liquid-assign]
key_files:
  created: []
  modified:
    - _layouts/chokepoint.html
decisions:
  - "Use field-based tier_lower matching instead of positional forloop.parentloop.index to route detection rules — survives any stage array ordering"
  - "Two-step Liquid assign (emu_lang_raw then emu_lang) to avoid invalid parenthesized filter chain syntax"
metrics:
  duration_minutes: 10
  completed_date: "2026-04-12"
  tasks_completed: 3
  tasks_total: 3
  files_changed: 1
---

# Phase 01 Plan 01: Baseline Cleanup — Gitignore, Layout Bug, Liquid Syntax — Summary

**One-liner:** Fixed positional index bug in chokepoint layout detection routing, invalid Liquid parentheses syntax in emulation block, and confirmed generated files are gitignored — jekyll build --strict exits 0 with no warnings.

---

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Verify gitignore coverage — BSLN-01 | (no change needed) | .gitignore already correct |
| 2 | Fix positional index bug — BSLN-02 | a1b9b4c | _layouts/chokepoint.html |
| 3 | Fix Liquid syntax error and verify strict build — BSLN-03 | 7edd1dd | _layouts/chokepoint.html |

---

## What Was Done

### Task 1 — Gitignore coverage (BSLN-01)

All three generated file paths were already present in `.gitignore` and absent from git tracking:

- `_data/chokepoints.yml`
- `assets/js/search-index.json`
- `_chokepoints/`

`git ls-files` returned empty output for all three. No file changes required.

### Task 2 — Positional index bug fix (BSLN-02)

The detection rule display block in `_layouts/chokepoint.html` used `forloop.parentloop.index == 2` and `forloop.parentloop.index == 3` to decide which Sigma rules to show per stage. This broke silently for any chokepoint where Hunt or Analyst stages were not literally in those array positions.

Replaced all three conditions with field-based matching using `tier_lower` (already assigned as `stage.DetectionTier | downcase`):

- `forloop.parentloop.index == 2 and tier_lower == "hunt"` → `tier_lower == "hunt"`
- `forloop.parentloop.index == 3 and tier_lower == "analyst"` → `tier_lower == "analyst"`

Detection routing now works correctly for any stage ordering.

### Task 3 — Liquid syntax error fix (BSLN-03)

Line 1557 used parentheses to wrap a filter chain inside `append:`, which is invalid Liquid syntax:

```liquid
{% assign emu_lang = "language-" | append: (emu.Language | downcase | default: "plaintext") %}
```

Jekyll emitted a warning for every chokepoint with an emulation block. Fixed with a two-step assign:

```liquid
{% assign emu_lang_raw = emu.Language | downcase | default: "plaintext" %}
{% assign emu_lang = "language-" | append: emu_lang_raw %}
```

`jekyll build --strict` now exits 0 with zero warnings.

---

## Verification Results

| Check | Command | Result |
|-------|---------|--------|
| BSLN-01 | `git ls-files _data/chokepoints.yml "_chokepoints/" assets/js/search-index.json \| wc -l` | 0 |
| BSLN-02 | `grep "forloop.parentloop.index" _layouts/chokepoint.html \| wc -l` | 0 |
| BSLN-03 | `jekyll build --strict 2>&1 \| grep -iE "warning\|error" \| wc -l` | 0 |

---

## Deviations from Plan

None — plan executed exactly as written. Task 1 confirmed existing correct state; Tasks 2 and 3 applied the specified fixes verbatim.

---

## Known Stubs

None.

---

## Threat Flags

None — changes are template logic only. No new network endpoints, auth paths, file access patterns, or schema changes introduced.

---

## Self-Check

**Files modified:**
- `_layouts/chokepoint.html`: exists and contains correct field-based conditions

**Commits:**
- a1b9b4c: fix(01-01): replace positional forloop.parentloop.index with field-based tier matching
- 7edd1dd: fix(01-01): fix invalid Liquid parentheses syntax in emu_lang assignment

## Self-Check: PASSED
