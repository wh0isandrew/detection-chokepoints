# Phase 3: Site Visual Design and UX — Research

**Researched:** 2026-04-11
**Domain:** Jekyll static site — CSS, vanilla JS, Liquid templates
**Confidence:** HIGH

---

## Summary

Phase 3 is a self-contained visual/UX pass on an existing Jekyll + Tailwind + custom CSS site. The
three requirements — copy buttons, tier-colored left-border accents on Sigma blocks, and mobile table
reflow — are all achievable with CSS additions and minimal JS changes. No new libraries are needed.

The good news: the copy button infrastructure is already 90% there. `copyCode(btn)` exists as an
inline `<script>` at the bottom of `_layouts/chokepoint.html`. Every `Copy` button already calls it.
The function uses `navigator.clipboard.writeText` and reads from `.sigma-code` in the parent
`.sigma-block`. The button text toggles to "Copied!" for 1.8 seconds. The only gap is visual — the
button has no confirmation state styling beyond the text change.

The tier-color work requires adding three modifier classes (`sigma-block--research`,
`sigma-block--hunt`, `sigma-block--analyst`) with a `border-left` accent, then wiring those classes
into the Liquid template at the point where each detection-level panel renders its `.sigma-block`.
The color tokens for all three tiers already exist in the palette (blue `--link`, amber `--high`,
green `--medium`). No new colors needed.

Table reflow is the largest unknown. Trend pages use bare `<table class="cg-table">` elements with
no scroll wrapper. The style for `.cg-table` lives inline in each trend markdown page, not in
`style.css`. Chokepoint pages use `.data-table` inside `.table-wrapper` (which has `overflow-x:
auto`) — those are already correct. The trend page tables need a `<div class="table-wrapper">` wrap
or an equivalent CSS rule applied to `.cg-table`.

**Primary recommendation:** Add three CSS classes + Liquid template wiring for tier accents, verify
copy button state styling exists, and wrap or CSS-fix `.cg-table` elements on trend pages for mobile
overflow. Total surface: `style.css`, `chokepoint.html`, and two trend Markdown files.

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| UX-01 | Copy-to-clipboard button present on all Sigma rule code blocks (research, hunt, analyst tiers) | `copyCode()` function and `Copy` buttons already present in all `.sigma-block` occurrences in `chokepoint.html` — function is complete and correct. Gap is confirmation styling only. |
| UX-02 | Sigma maturity tiers visually distinct via distinct left-border accent color per tier | `.sigma-block` has no tier modifier today. Three new CSS classes needed; tier identity available in Liquid loop variable `level_lower` and in `ed.Layer` for EarlyDetections. |
| UX-03 | Overflow tables reflow cleanly on 390px viewport with no horizontal scroll bleed | `.data-table` tables are already wrapped in `.table-wrapper`. `.cg-table` elements in trend pages have no wrapper — raw `<table>` tags. Fix required on trend pages. |
</phase_requirements>

---

## Project Constraints (from CLAUDE.md)

- Always use `.badge` base class from `style.css` — never create standalone badge styles. [VERIFIED: codebase grep]
- No em dashes in site content. [VERIFIED: CLAUDE.md + memory file]
- Static site only — no backend, no JS libraries beyond what already exists. [VERIFIED: CLAUDE.md]
- `jekyll build --strict` must pass after every template change. [VERIFIED: ROADMAP.md decision log]
- No URL or slug changes in Phase 3. [VERIFIED: ROADMAP.md key decisions]

---

## Standard Stack

### Core (already in use — Phase 3 must stay within this stack)

| Library/Tool | Version | Purpose | Source |
|---|---|---|---|
| Jekyll | per Gemfile | Static site generator | [VERIFIED: _config.yml] |
| Tailwind CSS (CDN) | latest via CDN | Utility classes on Liquid elements | [VERIFIED: default.html line 11] |
| highlight.js | 11.10.0 | Syntax highlighting for YAML/PS blocks | [VERIFIED: chokepoint.html lines 1630-1632] |
| Custom CSS | — | All component styles in `assets/css/style.css` | [VERIFIED: style.css] |
| Vanilla JS | inline `<script>` at bottom of chokepoint.html | Tab switching, copy, scroll-spy | [VERIFIED: chokepoint.html lines 1633-1679] |

### No New Dependencies Needed

Phase 3 requires zero new libraries. `navigator.clipboard.writeText` is supported in all modern
browsers without a polyfill. [ASSUMED — no compatibility table consulted, but this is widely
established for 2024+.]

---

## Architecture Patterns

### Where Code Lives Today

```
_layouts/
  chokepoint.html     # Single-file: all page CSS (inline <style>), Liquid template,
                      #   inline JS — 1679 lines total
  default.html        # Head, nav include, footer, theme-toggle JS
assets/
  css/
    style.css         # Global styles, color tokens, shared component classes
  js/
    search.js         # Search index consumer
    ttp-filter.js     # Index page filter
    (others)          # Trend page charts and table expand/collapse
trends/
  clickgrab.md        # Trend page — has inline <style>, inline <script>, bare <table class="cg-table">
  masq-infra.md       # Trend page — similar structure
```

### Pattern: CSS in chokepoint.html vs style.css

Most component-level CSS for the chokepoint detail page lives in the `<style>` block at the top of
`chokepoint.html` (lines 5–830 approx), not in `style.css`. Global/shared utilities live in
`style.css`. Phase 3 work that is chokepoint-page-specific can go into that inline `<style>` block.
Work that affects trend pages (`.cg-table` scroll fix) should go into `style.css` or into each
trend file's own inline style block.

### Pattern: Sigma Block Structure (verified)

Every Sigma rule renders inside this DOM structure:

```html
<div class="sigma-block">
  <div class="sigma-header">
    <span class="sigma-label">Sigma Rule: Research Level</span>
    <div class="sigma-actions">
      <a class="sigma-btn" ...>GitHub →</a>
      <a class="sigma-btn" ...>Download</a>
      <button class="sigma-btn" onclick="copyCode(this)">Copy</button>
    </div>
  </div>
  <pre class="sigma-code rounded-lg p-4 overflow-x-auto text-[.8rem]">
    <code class="language-yaml">{{ sigma_content | xml_escape }}</code>
  </pre>
</div>
```

`copyCode(btn)` traverses to the nearest `.sigma-block` ancestor, then finds `.sigma-code` within
it. [VERIFIED: chokepoint.html lines 1645-1652]

### Pattern: Tier Identity in Liquid

The detection tab loop (`Research,Hunt,Analyst`) exposes `level_lower` as a string: `"research"`,
`"hunt"`, or `"analyst"`. The EarlyDetections loop does not expose an equivalent — `ed.Layer` is a
descriptive string like `"ETW"` or `"IOK"`, not a maturity tier name. The pre-execution tab renders
all EarlyDetections without tier differentiation, which is correct — pre-execution detections are
not tiered.

For the detection tabs loop (lines 1449-1490), the modifier class can be applied directly:

```liquid
<div class="sigma-block sigma-block--{{ level_lower }}">
```

For the attack chokepoints accordion (lines 1236-1385), `sigma_key` is set to `_sigma_hunt`,
`_sigma_analyst`, or `_sigma_research` depending on `stage.DetectionTier`. The tier string can be
extracted from `sigma_key` for the modifier class.

### Pattern: Color Token Mapping for Tiers

The existing tier badge colors (`mat-research`, `mat-hunt`, `mat-analyst`) use these tokens:

| Tier | Color Token | Hex | Current Use |
|------|-------------|-----|-------------|
| research | `var(--link)` | `#58a6ff` (blue) | `.mat-research`, `.det-badge-research` |
| hunt | `var(--high)` | `#e3b341` (amber) | `.mat-hunt`, `.det-badge-hunt` |
| analyst | `var(--medium)` | `#3fb950` (green) | `.mat-analyst`, `.det-badge-analyst` |

[VERIFIED: chokepoint.html lines 91-93, style.css lines 566-568]

The left-border accent should use these same tokens for visual consistency. The border-left width
used elsewhere in the codebase: sidebar active link uses `2px` (style.css line 312), constant box
uses `4px` (style.css line 860), emulation wrapper header uses `3px` (style.css line 1098). A
`4px` solid left border on `.sigma-block` reads clearly at a glance.

---

## Detailed Findings by Requirement

### UX-01: Copy-to-Clipboard

**Status:** Function exists and works. Styling gap only.

The `copyCode` function (chokepoint.html lines 1645-1652):

```javascript
function copyCode(btn) {
  const code = btn.closest('.sigma-block').querySelector('.sigma-code');
  navigator.clipboard.writeText(code.innerText || code.textContent).then(() => {
    const orig = btn.textContent;
    btn.textContent = 'Copied!';
    setTimeout(() => btn.textContent = orig, 1800);
  });
}
```

This reads from the DOM (`code.innerText`), not from hardcoded content — safe with respect to the
scope boundary (UX-01 reads rule text, does not touch it). [VERIFIED: chokepoint.html]

`style.css` has a stub `.copy-btn` and `.copy-btn.copied` (lines 537-539) that is not currently
wired up. The buttons use `.sigma-btn`, not `.copy-btn`. The `.sigma-btn` class has no `.copied`
state. The planner should add a `.sigma-btn.copied` style (or wire `.copy-btn` classes) so the
confirmation state is visually distinct, not just a text change.

All five locations that render a Copy button use identical markup and the same `copyCode(this)`
call:
- Line 1220 (EarlyDetections in attack chokepoints section)
- Line 1323 (Detection tabs in attack chokepoints section)
- Line 1375 (Hard-coded hunt-network block — ClickFix only)
- Line 1430 (EarlyDetections in detection strategy tabs)
- Line 1482 (Research/Hunt/Analyst tabs in detection strategy)
- Line 1561 (Emulation script block)

No Copy button is missing. The `onclick="copyCode(this)"` pattern is consistently applied.
[VERIFIED: chokepoint.html grep]

**Gap for UX-01:** Visual confirmation state. Add `.sigma-btn.copied` CSS rule. The JS already
sets text to "Copied!" — CSS can reinforce with color change (green border, green text matching
`var(--medium)`).

### UX-02: Tier Left-Border Accents

**Status:** No tier-specific visual differentiation on `.sigma-block` today.

`.sigma-block` in `chokepoint.html` (lines 670-676):

```css
.sigma-block {
  border: 1px solid var(--border);
  border-radius: var(--radius);
  overflow: hidden;
  margin-top: 1rem;
}
```

No left-border accent. No modifier classes. The three new classes to add:

```css
.sigma-block--research { border-left: 4px solid var(--link); }
.sigma-block--hunt     { border-left: 4px solid var(--high); }
.sigma-block--analyst  { border-left: 4px solid var(--medium); }
```

**Liquid wiring locations:**

1. Detection tabs loop (line ~1455): `<div class="sigma-block sigma-block--{{ level_lower }}">`
   — straightforward, `level_lower` is already `"research"`, `"hunt"`, or `"analyst"`.

2. Attack chokepoints accordion (line ~1315): The sigma_key is set conditionally based on
   `stage.DetectionTier`. The tier string needs to be extracted. Pattern:
   ```liquid
   {% assign sigma_tier = sigma_key | remove: "_sigma_" %}
   <div class="sigma-block sigma-block--{{ sigma_tier }}">
   ```

3. EarlyDetections / pre-execution blocks (lines 1207, 1417): These are pre-execution
   (ETW/IOK), not tiered. Leave as plain `.sigma-block` — no tier accent. This is correct
   behavior.

4. Emulation block (line ~1549): This is a script, not a Sigma rule. Leave as plain
   `.sigma-block`. No tier accent.

5. Hunt-network hard-coded block (lines 1369-1378): This is explicitly hunt-level. Use
   `.sigma-block sigma-block--hunt`. [VERIFIED: chokepoint.html line 1371 label text confirms "Hunt
   Level"]

**Risk:** The accordion (attack chokepoints) section uses `forloop.index == 3` for the
hunt-network special case. This is the positional index bug being fixed in Phase 1. Phase 3 should
not attempt to fix that bug — Phase 1 owns it. Phase 3 only adds the modifier class to the
`.sigma-block` div, which is structurally independent of the chokepoint accordion's stage logic.

### UX-03: Mobile Table Reflow

**Status:** Two distinct table patterns exist with different mobile behavior.

**Pattern A — Chokepoint pages (.data-table):** Already wrapped in `.table-wrapper` which has
`overflow-x: auto`. Mobile behavior is correct — horizontal scroll on the table, no bleed.
[VERIFIED: style.css line 438]

**Pattern B — Trend pages (.cg-table):** Raw `<table class="cg-table">` with no wrapper.
The `.cg-table` style lives inline at the top of `clickgrab.md` (line 64) and possibly `masq-infra.md`.
There is no `overflow-x: auto` on `.cg-table` itself. On 390px viewports, wide columns will
overflow the page body.

One table in `clickgrab.md` (line 331) uses `<div style="overflow-x:auto;"><table...>` — but the
others (lines 368, 390, 475, 499, 547) do not. This inconsistency is the root problem.

**Two valid fix approaches:**

Option A — Add `overflow-x: auto` to `.cg-table` in style.css (or in each page's inline style):
```css
.cg-table { overflow-x: auto; }
```
Simpler, but `overflow-x: auto` on `<table>` itself has browser inconsistency — tables don't
scroll themselves, only a block container can scroll. This approach does not work reliably.

Option B — Wrap each bare `<table class="cg-table">` in `<div class="table-wrapper">` in the
markdown files. This is the same pattern chokepoint pages already use and is reliable.
[VERIFIED: style.css line 438 confirms `.table-wrapper { overflow-x: auto }` works]

**Recommendation:** Option B. Wrap each `.cg-table` in trend pages with `.table-wrapper`. The
`masq-infra.md` page is currently blank (trends page renders blank because pipeline data is not
yet available — STATE.md note), so only `clickgrab.md` tables need wrapping for Phase 3. Still
audit `masq-infra.md` for raw table tags.

**Scope note:** Wrapping tables in `<div class="table-wrapper">` is a markup-only change in
Markdown files. It does not alter URLs, slugs, or permalinks. [VERIFIED: _config.yml — no
permalink config for trends pages]

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead |
|---------|-------------|-------------|
| Copy-to-clipboard | Custom clipboard abstraction | `navigator.clipboard.writeText` — already in use |
| Syntax highlighting | Custom highlighter | highlight.js 11.10.0 — already loaded |
| CSS custom properties | Hardcoded hex values | Use `var(--link)`, `var(--high)`, `var(--medium)` — tokens already defined |

**Key insight:** The site has a complete, working color system and JS infrastructure. Phase 3 adds
CSS modifier classes and one Liquid attribute per template location. No new architecture needed.

---

## Common Pitfalls

### Pitfall 1: Adding border-left breaks border-radius rendering

**What goes wrong:** `.sigma-block` has `border: 1px solid var(--border)` and
`border-radius: var(--radius)`. Adding `border-left: 4px solid ...` overrides the left border
width, which can cause the left corners to look slightly off in some browsers when the element
also has `overflow: hidden`.

**Why it happens:** The `overflow: hidden` on `.sigma-block` clips the rounded corners correctly,
but the 4px left border combined with 1px on other sides can look asymmetric.

**How to avoid:** Test visually at 1x and 2x pixel density. If corners look wrong, switch to a
box-shadow approach: `box-shadow: -4px 0 0 var(--link)` — renders the left accent without
touching border geometry.

**Warning signs:** Left corners of `.sigma-block` look squared off or misaligned.

### Pitfall 2: Tier modifier class not applied to all sigma-block locations

**What goes wrong:** Adding the class only in the detection tabs loop but missing the attack
chokepoints accordion or the hunt-network hard-coded block.

**Why it happens:** There are six distinct `sigma-block` render sites in `chokepoint.html`. It is
easy to update the visible tab-panel ones and miss the accordion ones.

**How to avoid:** Grep for `sigma-block` in `chokepoint.html` and verify every occurrence either
has a tier modifier or has a documented reason not to (pre-execution, emulation script).

**Warning signs:** Some Sigma blocks have tier accents, others don't — reader can't tell at a
glance whether it's intentional.

### Pitfall 3: copyCode reads innerText — highlight.js may wrap in spans

**What goes wrong:** `code.innerText` reads the visually rendered text, which may include
highlight.js span elements' text content. This is actually fine — `innerText` collapses spans to
their text nodes.

**Why it's not a problem:** The function uses `innerText || textContent` as fallback. highlight.js
adds `<span>` wrappers for color, but `innerText` still returns plain text. [ASSUMED — no live
test performed, but this is standard DOM behavior.]

**Warning signs if wrong:** Copied text includes HTML tags. If this happens, use
`code.textContent` instead of `code.innerText`.

### Pitfall 4: `.cg-table` overflow fix affects masq-infra.md layout

**What goes wrong:** If the fix is applied as a CSS rule in `style.css` targeting `.cg-table`,
it will affect the masq-infra trend page even though that page is currently blank. If the page
ever renders wide tables without a wrapper, they would still overflow.

**How to avoid:** Fix both pages explicitly. Don't assume one is safe because it's currently blank.

### Pitfall 5: `jekyll build --strict` fails on Liquid syntax in class attribute

**What goes wrong:** `sigma-block--{{ level_lower }}` produces `sigma-block--research`, which
is valid. But if the Liquid variable is nil (e.g., a detection with no `Level` field), it renders
`sigma-block--` — a broken class name that still functions but may trigger a strict warning.

**How to avoid:** Add a Liquid default: `{{ level_lower | default: 'research' }}`.

---

## Code Examples

### Tier Left-Border CSS (add to chokepoint.html inline `<style>`)

```css
/* [VERIFIED pattern — matches existing det-badge color system] */
.sigma-block--research { border-left: 4px solid var(--link); }
.sigma-block--hunt     { border-left: 4px solid var(--high); }
.sigma-block--analyst  { border-left: 4px solid var(--medium); }
```

### Copy Button Confirmed State (add to chokepoint.html inline `<style>` or style.css)

```css
/* Wires into existing copyCode() JS which sets btn.textContent = 'Copied!' */
.sigma-btn.copied {
  color: var(--medium);
  border-color: rgba(63,185,80,.4);
}
```

The JS needs one line added to toggle the class:

```javascript
function copyCode(btn) {
  const code = btn.closest('.sigma-block').querySelector('.sigma-code');
  navigator.clipboard.writeText(code.innerText || code.textContent).then(() => {
    const orig = btn.textContent;
    btn.textContent = 'Copied!';
    btn.classList.add('copied');                          // add this
    setTimeout(() => {
      btn.textContent = orig;
      btn.classList.remove('copied');                    // add this
    }, 1800);
  });
}
```

### Liquid Modifier Class — Detection Tabs Loop

```liquid
<div class="sigma-block sigma-block--{{ level_lower | default: 'research' }}">
```

### Liquid Modifier Class — Attack Chokepoints Accordion

```liquid
{% assign sigma_tier = sigma_key | remove: "_sigma_" %}
<div class="sigma-block sigma-block--{{ sigma_tier | default: 'research' }}">
```

### Table Wrapper for Trend Pages

```html
<!-- Before -->
<table class="cg-table">

<!-- After -->
<div class="table-wrapper">
<table class="cg-table">
...
</table>
</div>
```

`.table-wrapper` is already defined in `style.css` with `overflow-x: auto`. No new CSS needed for
this fix. [VERIFIED: style.css line 438]

---

## Scope Boundary Verification

**No URL changes:** Phase 3 touches `chokepoint.html` (template), `style.css` (CSS), and trend
markdown files (table wrappers). No changes to `_config.yml`, no new layout files, no permalink
modifications. The `permalink: /chokepoints/:name/` config in `_config.yml` is unchanged.
[VERIFIED: _config.yml]

**No content changes:** Copy button reads `code.innerText` from the DOM at click time — it does
not modify or hardcode rule text. Adding CSS modifier classes to `.sigma-block` divs is a
structural-only change, not content.

**No `<link>` tag changes:** `default.html` has one stylesheet link (`assets/css/style.css`) and
one Tailwind CDN link. Both remain untouched. [VERIFIED: default.html]

---

## Environment Availability

Phase 3 is template/CSS/JS changes only. No external services or CLI tools are required beyond
what Phase 1 established (`jekyll build --strict`). This section is SKIPPED — no external
dependencies beyond project's own build stack.

---

## Validation Architecture

**Test framework:** Manual visual testing + `jekyll build --strict`.

No automated test framework is configured for this project. [VERIFIED: no test config files found
in repo root or `assets/`.]

### Phase Requirements to Test Map

| Req ID | Behavior | Test Type | How to Verify |
|--------|----------|-----------|---------------|
| UX-01 | Copy button copies full rule text | Manual | Click Copy on each tier tab; paste into text editor; verify full YAML present |
| UX-01 | Button shows "Copied!" for ~1.8s | Manual | Observe button text after click |
| UX-02 | Research block has blue left border | Manual visual | Load any chokepoint detail page; confirm left border color matches tier badge |
| UX-02 | Hunt block has amber left border | Manual visual | Switch to Hunt tab; compare border color |
| UX-02 | Analyst block has green left border | Manual visual | Switch to Analyst tab |
| UX-03 | Tables scroll on 390px viewport | Manual/DevTools | Chrome DevTools device emulation at 390px; no horizontal bleed on trend pages |
| All | Build stays clean | Automated | `jekyll build --strict` exits 0 |

### Per-Task Build Gate

After every template or CSS change: `jekyll build --strict`. The roadmap decision log explicitly
requires this. [VERIFIED: STATE.md key decisions]

### Wave 0 Gaps

None — no test files to create. Validation is build-clean + manual visual.

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `navigator.clipboard.writeText` works in all modern browsers without polyfill | Standard Stack | Copy silently fails on older browsers; add try/catch fallback |
| A2 | highlight.js `innerText` produces plain text (no HTML artifacts in clipboard) | Pitfall 3 | Copied text contains `<span>` tags; switch to `textContent` |
| A3 | `masq-infra.md` has no currently-rendered table content (page is blank) | UX-03 finding | Tables exist but are overflow-bleed issues in production; audit masq-infra.md before shipping |

---

## Open Questions

1. **Hunt-network hard-coded block (lines 1369-1378)**
   - What we know: It renders a `.sigma-block` with no tier modifier, labeled "Hunt Level (Network)". It is ClickFix-specific.
   - What's unclear: Should it get `.sigma-block--hunt`? The label says yes. But the block is also conditionally rendered only for `forloop.index == 3`, which is the positional bug being fixed in Phase 1.
   - Recommendation: Add `.sigma-block--hunt` to this block in Phase 3, but flag the dependency — if Phase 1's fix changes the condition, Phase 3's edit may need to move.

2. **`masq-infra.md` table audit**
   - What we know: The page currently renders blank because pipeline data is missing (STATE.md).
   - What's unclear: Whether `masq-infra.md` has raw `<table>` elements in the markdown that will reflow poorly once data exists.
   - Recommendation: Read `masq-infra.md` during plan execution and wrap any raw tables preemptively.

---

## Sources

### Primary (HIGH confidence — verified by direct file read)

- `_layouts/chokepoint.html` — Full template read; all sigma-block locations, JS function, CSS classes confirmed
- `assets/css/style.css` — Color tokens, `.sigma-code`, `.table-wrapper`, `.badge`, `.data-table` all verified
- `_layouts/default.html` — JS loading strategy (inline at bottom), no deferred JS files
- `_config.yml` — Permalink config, no URL-affecting changes in scope
- `trends/clickgrab.md` — Table markup: bare `.cg-table`, one existing `overflow-x:auto` wrapper, five without

### Secondary (MEDIUM confidence)

- `style.css` lines 537-539: `.copy-btn.copied` exists but is not wired to actual buttons (uses `.sigma-btn`, not `.copy-btn`)

### Tertiary (LOW confidence / assumed)

- Browser compatibility claim for `navigator.clipboard.writeText` — based on training knowledge, not verified against caniuse.com this session

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — verified by direct file read
- Architecture patterns: HIGH — verified by direct file read
- Pitfalls: MEDIUM — border-left/radius interaction is ASSUMED; all others VERIFIED

**Research date:** 2026-04-11
**Valid until:** 2026-05-11 (stable static site stack; no fast-moving dependencies)
