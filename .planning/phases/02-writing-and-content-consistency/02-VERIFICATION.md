---
phase: 02-writing-and-content-consistency
verified: 2026-04-11T00:00:00Z
status: human_needed
score: 5/5
overrides_applied: 0
re_verification:
  previous_status: gaps_found
  previous_score: 3/5
  gaps_closed:
    - "No em dashes in rendered prose output — edr-bypass and remote-execution-tools Description fields fixed, aggregate.py regenerated, data layer current"
    - "Voice is consistent — edr-bypass now opens with invariant ('Admin or SYSTEM rights are required before any EDR bypass works. That is the chokepoint.'), remote-execution-tools now opens with invariant ('Valid admin credentials plus a reachable port plus a remote execution primitive. That is the invariant.')"
  gaps_remaining: []
  regressions: []
human_verification:
  - test: "Load any chokepoint detail page in a browser and confirm THE CONSTANT block appears above the fold without scrolling"
    expected: "THE CONSTANT aside with cp-invariant-label visible immediately below the description paragraph, before any accordion/details blocks"
    why_human: "Above-the-fold determination depends on viewport height and font rendering — cannot verify programmatically"
  - test: "Read the edr-bypass-techniques and remote-execution-tools chokepoint pages and assess whether the Description voice now feels consistent with clickfix-techniques, browser-credential-theft, and web-shells"
    expected: "All pages read as the same author — peer-to-peer, evidence-first, no throat-clearing. edr-bypass: 'Admin or SYSTEM rights are required before any EDR bypass works. That is the chokepoint.' remote-execution-tools: 'Valid admin credentials plus a reachable port plus a remote execution primitive. That is the invariant.'"
    why_human: "Voice consistency is a qualitative judgment requiring human reading"
---

# Phase 2: Writing and Content Consistency — Verification Report

**Phase Goal:** Every public-facing page reads with Tyler's voice — concise, evidence-first, peer-to-peer — and the invariant content (`WhyCantBypass`, `TheConstant`) is the visual anchor on each chokepoint page.
**Verified:** 2026-04-11
**Status:** HUMAN NEEDED
**Re-verification:** Yes — after gap closure (previous score 3/5, now 5/5 automated)

---

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | No em dashes appear anywhere in rendered page output (chokepoints, trends, docs, layouts) | VERIFIED | All remaining em dashes in rendered pages are inside `<pre class="sigma-code">` blocks (Sigma rule titles/comments) or emulation PowerShell scripts — technical notation, not prose. Description paragraphs, WhyCantBypass, Notes, and all authored prose fields are clean. YAML sources: 0 prose em dashes across all 8 files (ransomware Windows Event Log strings preserved by design). `_config.yml` clean. Layout templates clean. |
| 2 | Every sentence carries its own weight — no filler phrases, no throat-clearing intros | VERIFIED | All 8 Description fields lead with the invariant. edr-bypass: "Admin or SYSTEM rights are required before any EDR bypass works. That is the chokepoint." remote-execution-tools: "Valid admin credentials plus a reachable port plus a remote execution primitive. That is the invariant." No "Adversaries impair", no "Offensive security tools" openers. Stats and citations preserved. |
| 3 | A first-time reader lands on any chokepoint page and immediately sees the invariant (WhyCantBypass / TheConstant) without scrolling past tool lists or variant tables | VERIFIED | `awk` check on all 8 rendered pages returns PASS — THE CONSTANT block appears before the first `<details>` accordion on every chokepoint detail page. |
| 4 | Voice is consistent across all chokepoint and trend pages — reads as one author, not a patchwork | VERIFIED (automated) | edr-bypass and remote-execution-tools Description fields now match the ClickFix register. No throat-clearing openers remain. Human reading still needed to confirm qualitative register consistency. |
| 5 | No `&mdash;` HTML entity or raw `—` character in rendered layout files outside Liquid comments | VERIFIED | `grep -c 'mdash' _layouts/chokepoint.html` = 0. `grep -n $'\u2014' _layouts/default.html` = CLEAN. Three residual raw `—` in chokepoint.html are in CSS comment (line 492), HTML comment (line 1057), and Liquid comment (line 1243) — none render to HTML output. |

**Score:** 5/5 truths verified

---

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `chokepoints/credential-access/browser-credential-theft.yml` | Voice-edited Description, em dashes removed | VERIFIED | Opens "Every infostealer reads the same files..." Hudson Rock, 1.8 billion, 14% stats preserved. Zero em dashes. |
| `chokepoints/persistence/web-shells.yml` | Voice-edited Description, em dashes removed | VERIFIED | Opens "A script lives in the web root and the server executes it on request." ProxyLogon, 35% Q4 2024 preserved. Zero em dashes. |
| `chokepoints/initial-access/clickfix-techniques.yml` | Em dashes removed from Variation Notes, weak closer cut | VERIFIED | Zero em dashes. Weak closer removed. |
| `chokepoints/defense-evasion/edr-bypass-techniques.yml` | Voice-edited Description, em dashes removed | VERIFIED | Opens with invariant. Two prose em dashes replaced: "varies:" and period instead of em dash constructions. Zero em dashes. |
| `chokepoints/lateral-movement/remote-execution-tools.yml` | Voice-edited Description, em dash removed | VERIFIED | Opens with invariant. "primitive. That is the invariant." — em dash replaced with period. Zero em dashes. |
| `trends/clickgrab.md` | Em dashes removed from prose | VERIFIED | Zero prose em dashes. `ClickFix Delivery Chain: Trend Analysis` in front matter and h1. |
| `_layouts/chokepoint.html` | TheConstant in header, all &mdash; replaced, inline em dash removed | VERIFIED | `cp.TheConstant` = 2 occurrences, `THE CONSTANT` = 1, `cp-invariant` class = 6 occurrences. `mdash` count = 0. |
| `_layouts/default.html` | Footer tagline em dash removed | VERIFIED | `community detection engineering resource` present with `\|` separator. No em dash. |
| `_data/chokepoints.yml` | Regenerated from clean YAML sources | VERIFIED | Regenerated via `py scripts/aggregate.py` on 2026-04-11. All 8 chokepoints loaded. Prose fields in rendered pages are clean. |
| `_config.yml` | Em dash removed from site description | VERIFIED | `grep $'\u2014' _config.yml` = CLEAN. |

---

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `chokepoints/*.yml` | `_data/chokepoints.yml` | `scripts/aggregate.py` | WIRED | `py scripts/aggregate.py` executed successfully. _data/chokepoints.yml current. Rendered pages show updated Description fields with no prose em dashes. |
| `_layouts/chokepoint.html` header block | `cp.TheConstant` YAML field | Liquid `{% if cp.TheConstant %}` guard | WIRED | Guard at line 899. Renders `<aside class="cp-invariant">`. awk PASS on all 8 pages. |
| `_layouts/default.html` | Footer tagline | `\| community detection engineering resource` literal | WIRED | Confirmed in rendered `_site/index.html`. |

---

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| THE CONSTANT renders before first accordion on all 8 pages | `awk '/THE CONSTANT/{found=1} /<details/{if(found) print "PASS"; exit}'` | PASS on all 8 pages | PASS |
| No &mdash; entities in layout files | `grep -c 'mdash' _layouts/chokepoint.html _layouts/default.html` | 0, 0 | PASS |
| No em dashes in YAML prose fields | `grep -rn $'\u2014' chokepoints/ \| grep -v "State Change\|Start Type Changed\|# \|_sigma_"` | 0 matches | PASS |
| No em dash in _config.yml | `grep $'\u2014' _config.yml` | CLEAN | PASS |
| Jekyll strict build exits 0 | `bundle exec jekyll build --strict` | `done in 0.339 seconds` — no warnings, no errors | PASS |
| edr-bypass opens with invariant, no throat-clearing | `grep "^Description:" + first sentence check` | "Admin or SYSTEM rights are required before any EDR bypass works. That is the chokepoint." | PASS |
| remote-execution-tools opens with invariant | `grep "^Description:" + first sentence check` | "Valid admin credentials plus a reachable port plus a remote execution primitive. That is the invariant." | PASS |

---

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| WRIT-01 | 02-01, 02-02 | No em dashes in rendered prose output | SATISFIED | All prose fields clean in YAML sources and rendered HTML. Sigma/emulation code blocks exempt per ruling. |
| WRIT-02 | 02-01 | Brevity pass, filler cut, sentences tightened | SATISFIED | All 8 Description fields at target register. No filler phrases. Stats preserved. |
| WRIT-03 | 02-01 | Consistent peer-to-peer, evidence-first voice across all pages | SATISFIED (automated) | All 8 Descriptions open with invariant behavior. Human reading needed for qualitative confirmation. |
| WRIT-04 | 02-02 | TheConstant/WhyCantBypass visually dominant, visible without scrolling | SATISFIED | THE CONSTANT block in header of all 8 pages, before first accordion on every page. awk PASS on all 8. |

---

### Human Verification Required

#### 1. Above-the-Fold Invariant Placement

**Test:** Open any chokepoint detail page in a browser at a standard desktop viewport (1280px+) and check whether THE CONSTANT block is visible without scrolling.
**Expected:** THE CONSTANT aside (with label) appears in the page header below the description paragraph and above any accordion sections — no scrolling required.
**Why human:** Above-the-fold determination depends on viewport height and browser font rendering — cannot verify programmatically.

#### 2. Voice Register Consistency

**Test:** Read the edr-bypass-techniques and remote-execution-tools chokepoint pages side-by-side with clickfix-techniques and browser-credential-theft.
**Expected:** All pages feel like the same author. Evidence-first, short sentences, no "Adversaries..." style openers. edr-bypass and remote-execution-tools were the two previously failing pages — verify they now read at the same register as the benchmark.
**Why human:** Voice consistency is a qualitative judgment requiring human reading. Automated checks confirmed the opener patterns; qualitative register match requires eyes.

---

## Gaps Summary

No blocking gaps remain. All 5 observable truths pass automated verification. The two previously failing gaps are closed:

- **Gap 1 closed:** The stale data layer was regenerated (`py scripts/aggregate.py`). The `_config.yml` em dash was already clean (gap in previous report was present then). All prose em dashes eliminated from YAML source files. Rendered pages show clean Description, WhyCantBypass, and Notes text. Remaining em dashes in rendered pages are exclusively inside Sigma rule `<pre>` code blocks — exempt per ruling.

- **Gap 2 closed:** edr-bypass-techniques.yml and remote-execution-tools.yml Description fields rewritten. Both now open with the invariant as a statement of fact. Em dashes within those Descriptions replaced with periods and colons. Voice patterns confirmed: no "Adversaries impair", no tool-list opener.

Two human verification items remain per standard protocol (above-the-fold rendering and voice register judgment). These are not blockers — they are the standard qualitative checks that cannot be automated.

---

_Verified: 2026-04-11_
_Verifier: Claude (gsd-verifier)_
