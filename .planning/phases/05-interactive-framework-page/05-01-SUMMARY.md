---
phase: 05-interactive-framework-page
plan: "01"
subsystem: site/framework
tags: [jekyll, framework, d3, liquid, interactive, navigation]
dependency_graph:
  requires: []
  provides: [framework/index.html, updated nav Framework link]
  affects: [_includes/nav.html, framework/index.html]
tech_stack:
  added: [D3 v7 (CDN), framework-graph.js (referenced for Plan 02)]
  patterns: [Liquid graph data generation, Jekyll layout: default, CSS custom properties]
key_files:
  created:
    - framework/index.html
  modified:
    - _includes/nav.html
decisions:
  - Use site CSS custom properties (--accent, --critical, etc.) rather than mockup's hardcoded blue accent
  - Liquid-generated __GRAPH_DATA at build time from site.data.chokepoints, no runtime backend
  - Step 4 card uses critical red styling to distinguish the chokepoint identification step
  - Nav active state uses contains '/framework' pattern, consistent with other nav items
metrics:
  duration: "3 minutes"
  completed: "2026-04-13T20:11:11Z"
  tasks_completed: 2
  files_changed: 2
requirements:
  - FRMK-01
---

# Phase 05 Plan 01: Create Interactive Framework Page Summary

Created the interactive framework page at `framework/index.html` and updated the nav to link to it locally.

## What Was Built

**`framework/index.html`** — Complete Jekyll page using `layout: default` with all 7 content sections from the approved mockup:

1. Hero with subtitle and Red Canary attribution link
2. 6-step interactive cards with click-to-expand SMB lateral movement examples. Step 4 highlighted with critical red border/shadow and "THIS IS THE CHOKEPOINT" badge.
3. Detection maturity model (research/hunt/analyst) with pseudocode blocks and left-border color coding via `--medium`/`--high`/`--critical`
4. Chokepoint vs. tool detection comparison (FRAGILE vs. DURABLE) with code examples
5. Relationship graph container with tactic filter buttons and Liquid-generated `window.__GRAPH_DATA` from `site.data.chokepoints`. D3 v7 CDN loaded, `framework-graph.js` referenced for Plan 02 implementation.
6. Testing section with 4 validation questions (lock, arrows, globe, timer icons)
7. CTA section with links to chokepoints, attack chains, and contribute

**`_includes/nav.html`** — Framework link updated from external GitHub FRAMEWORK.md URL to local `/framework/` with active-state highlighting matching the pattern used by all other nav items.

## Key Decisions

- **CSS custom properties throughout.** The mockup used `--accent: #58a6ff` (blue). The site uses `--accent: #f0883e` (orange). All colors reference site variables. No hardcoded hex from the mockup.
- **`--medium` is green, `--high` is yellow, `--critical` is red** in the site's CSS. The maturity model colors map accordingly: research=green, hunt=yellow, analyst=red. The mockup had a different mapping.
- **Liquid data generation.** Graph data is rendered as inline JSON at build time from `site.data.chokepoints`. No runtime backend required. Static site constraint honored.
- **`framework-graph.js` is referenced but not yet created.** Plan 02 implements the D3 visualization. The script tag is present and the data contract (`window.__GRAPH_DATA`) is established.

## Deviations from Plan

None. Plan executed exactly as written.

## Self-Check

- [x] `framework/index.html` exists
- [x] `_includes/nav.html` updated
- [x] Task 1 commit: 533c6e9
- [x] Task 2 commit: 2feb303
- [x] No em dashes in prose
- [x] All colors via CSS custom properties
- [x] `layout: default` front matter present
- [x] 6 step-cards, 3 maturity-cards, 2 compare-cards, 4 test-cards verified
- [x] `site.data.chokepoints` Liquid iteration present
- [x] `window.__GRAPH_DATA`, D3 v7, and framework-graph.js references present
- [x] Nav active state uses `contains '/framework'` pattern
- [x] External FRAMEWORK.md link removed from nav

## Self-Check: PASSED
