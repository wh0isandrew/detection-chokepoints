---
phase: 05-interactive-framework-page
plan: "02"
subsystem: frontend-js
tags: [d3, force-graph, visualization, framework-page, interactive]
dependency_graph:
  requires:
    - "05-01 (framework/index.html sets window.__GRAPH_DATA and provides #graph-svg, #graph-tooltip, .graph-btn elements)"
  provides:
    - "assets/js/framework-graph.js — D3 force-directed graph visualization"
  affects:
    - "framework/index.html (loads this script after __GRAPH_DATA is set)"
tech_stack:
  added: []
  patterns:
    - "IIFE-wrapped vanilla JS (matches codebase convention from ttp-filter.js)"
    - "D3 v7 force simulation with link, charge, center, and collision forces"
    - "Runtime CSS custom property reading via getComputedStyle for theme-aware colors"
    - "Link deduplication via Set to handle duplicate Liquid output"
key_files:
  created:
    - assets/js/framework-graph.js
  modified: []
decisions:
  - "Used IIFE pattern (not ES modules) consistent with ttp-filter.js and other codebase JS"
  - "Colors read at init via getComputedStyle rather than hardcoded — adapts to light/dark theme"
  - "Link deduplication added at init — Liquid templates may emit duplicate technique-to-tactic links across multiple chokepoints"
  - "Guard clause exits early if window.__GRAPH_DATA or #graph-svg is missing — safe on pages without the graph"
metrics:
  duration: "~10 minutes"
  completed_date: "2026-04-13"
  tasks_completed: 1
  tasks_total: 1
  files_created: 1
  files_modified: 0
---

# Phase 05 Plan 02: D3 Force-Directed Graph Script Summary

D3 v7 IIFE standalone script that reads `window.__GRAPH_DATA` and renders an interactive force-directed graph with tactic/chokepoint/technique nodes, hover tooltips, connection highlighting, tactic filtering, and chokepoint click navigation.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Create assets/js/framework-graph.js with D3 force-directed graph | a7a15cc | assets/js/framework-graph.js (created, 288 lines) |

## What Was Built

`assets/js/framework-graph.js` is a complete standalone D3 v7 visualization script that:

- **Guards** against missing `window.__GRAPH_DATA` or `#graph-svg` container (exits silently)
- **Deduplicates** links at init using a Set of `source|target` keys to handle Liquid template duplication
- **Reads CSS custom properties** at runtime (`--critical`, `--accent`, `--medium`, `--border`, `--text-muted`, `--text-dim`, `--bg-card`) so colors adapt to the site's dark/light theme
- **Renders three node types** with distinct sizes and fill opacities:
  - Tactic (r=22, opacity 0.25, --medium green)
  - Chokepoint (r=16, opacity 0.85, --critical red)
  - Technique (r=10, opacity 0.85, --accent orange)
- **Labels** nodes: tactic uses full name at 11px/600 weight, technique uses MITRE ID at 9px, chokepoint uses name truncated at 20 chars
- **Variation count badge** renders on chokepoint nodes where `vars > 0` (small circle at cx=12, cy=-12)
- **Drag behavior** via d3.drag with alphaTarget 0.3 on start, null fx/fy on end
- **Hover tooltip** shows name, type-specific meta (variations + maturity for chokepoints, MITRE ID for techniques, "Tactic group" for tactics), and positions at offsetX+15/offsetY-10
- **Connection highlighting** dims unrelated nodes to 0.15 fill-opacity and links to 0.07 stroke-opacity; connected nodes get 0.95 fill-opacity and 0.8 stroke-opacity
- **Tactic filter buttons** (`.graph-btn[data-filter]`) show nodes in the selected group plus all connected nodes; "all" resets to full graph; each filter calls `simulation.alpha(0.5).restart()`
- **Chokepoint click** navigates to `d.url` via `window.location.href`
- **Responsive resize** debounced at 250ms updates SVG width, viewBox, and force center, then restarts simulation

## Deviations from Plan

None. Plan executed exactly as written. The mockup reference (framework-mockup.html lines 527-783) provided a solid implementation base that was adapted into a standalone, production-quality IIFE.

## Known Stubs

None. The script is complete and functional. It depends on `window.__GRAPH_DATA` being set by plan 05-01 (framework/index.html). Until that page exists and is loaded, the guard clause exits early — but the script itself has no stubs.

## Threat Flags

None. The script reads build-time static data from `window.__GRAPH_DATA` (no user input modifies graph data) and the node count is bounded by chokepoint YAML entries. Both threat items (T-05-03, T-05-04) were accepted in the plan's threat model.

## Self-Check: PASSED

- `assets/js/framework-graph.js` exists: FOUND
- Commit a7a15cc exists: FOUND (`feat(05-02): create D3 force-directed graph for framework page`)
- Line count 288 >= 150: PASSED
- No hardcoded `#58a6ff`: PASSED
- IIFE wrapper present: PASSED
- All 17 acceptance criteria grep checks: PASSED
