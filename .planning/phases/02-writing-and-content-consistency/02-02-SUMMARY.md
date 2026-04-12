---
phase: 02-writing-and-content-consistency
plan: 02
subsystem: templates
tags: [liquid, jekyll, em-dash, the-constant, invariant, chokepoint-header]
dependency_graph:
  requires: [02-01]
  provides: [the-constant-header-render, clean-template-em-dashes]
  affects: [_layouts/chokepoint.html, _layouts/default.html, jekyll-render]
tech_stack:
  added: []
  patterns: [liquid-if-guard, existing-css-class-reuse]
key_files:
  created: []
  modified:
    - _layouts/chokepoint.html
    - _layouts/default.html
decisions:
  - "Use existing .cp-invariant/.cp-invariant-label CSS classes for TheConstant aside — no new CSS introduced, Phase 3 boundary respected"
  - "Insert TheConstant block after description paragraph and before byline — above-the-fold position without disrupting badge/title hierarchy"
  - "Replace all em dashes in rendered UI chrome with colons (sigma labels, det-meta labels) — consistent with project no-em-dash rule"
  - "Replace Lure section label em dash with colon; Variations intro em dash with period — prose fix, matches Tyler voice"
  - "Replace footer &mdash; with pipe separator — visually equivalent, no em dash"
  - "Leave em dashes in CSS comment (line 492), HTML comment (line 1057), Liquid comment (line 1243) — none render to HTML output"
metrics:
  duration: "~20 minutes"
  completed: "2026-04-11"
  tasks: 2
  files_modified: 2
---

# Phase 2 Plan 2: TheConstant Header Render and Template Em Dash Removal

One-liner: Added TheConstant invariant callout to every chokepoint detail-page header using existing CSS classes, and removed all rendered em dashes from both layout files.

## What Was Done

### Task 1: TheConstant block added to chokepoint detail-page header

Inserted a `{% if cp.TheConstant %}` guarded `<aside class="cp-invariant">` block in `_layouts/chokepoint.html` immediately after the description paragraph and before the byline. Uses the existing `.cp-invariant` and `.cp-invariant-label` CSS classes already present in the stylesheet. All 8 chokepoint YAML files have `TheConstant` at the top level (confirmed by gate check before execution), so the guard is a safety net rather than a conditional path.

Rendered position in detail page header (after edit):
1. Back link + priority badge
2. Page title
3. Tactic/MITRE/difficulty/prevalence badges
4. Description paragraph
5. **THE CONSTANT aside (new)**
6. Byline (author, updated date, source YAML link)

The `awk '/THE CONSTANT/{found=1} /<details/{if(found) print "PASS"; exit}'` check on the rendered `clickfix-techniques/index.html` returned `PASS`, confirming the invariant renders before the first accordion.

Also fixed all em dashes in chokepoint.html:
- 6 `&mdash;` entities in sigma-label UI chrome replaced with colons
- 1 `&mdash;` entity in det-meta-label `Goal` replaced with colon
- 1 raw `—` in section-intro prose (attacker must satisfy) replaced with comma
- 1 raw `—` in Variations section-intro replaced with period
- 1 raw `—` in variant-section-label `Lure` replaced with colon

Remaining raw `—` characters in file (3 total) are all in non-rendering comment blocks (CSS `/* */`, HTML `<!-- -->`, Liquid `{%- comment -%}`) and produce no output in the rendered HTML.

### Task 2: Footer tagline em dash removed from default layout

Replaced `&mdash;` with `|` in the footer tagline in `_layouts/default.html`. Tagline text "community detection engineering resource" preserved. Rendered `_site/index.html` confirms `| community detection engineering resource` in the footer.

## Deviations from Plan

None. Plan executed exactly as written. All acceptance criteria met on first attempt.

## Known Stubs

None. TheConstant is fully authored in all 8 YAML files and renders live data from the YAML source.

## Threat Flags

None. Template changes use existing CSS classes, no new network endpoints, auth paths, or schema changes introduced.

## Self-Check: PASSED

**Files exist:**
- `_layouts/chokepoint.html`: modified
- `_layouts/default.html`: modified

**Commits exist:**
- cfee223: `feat(02-02): add TheConstant invariant block to chokepoint detail-page header`
- 244dbd6: `fix(02-02): remove em dash from footer tagline in default layout`

**Key acceptance criteria verified:**
- `grep -c 'cp.TheConstant' _layouts/chokepoint.html`: 2
- `grep -c 'cp-invariant-label' _layouts/chokepoint.html`: 3
- `grep -c 'THE CONSTANT' _layouts/chokepoint.html`: 1
- `grep -c 'mdash' _layouts/chokepoint.html`: 0
- `grep -c 'mdash' _layouts/default.html`: 0
- `grep -F 'IOK Rule: ' _layouts/chokepoint.html`: 2 matches
- `grep -F 'Sigma Rule: ' _layouts/chokepoint.html`: 5 matches
- `awk` PASS check on rendered clickfix detail page: PASS
- `grep -F 'community detection engineering resource' _site/index.html`: 1 match
- `bundle exec jekyll build --strict`: exits 0, no warnings or errors
