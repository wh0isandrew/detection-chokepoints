# Phase 2: Writing and Content Consistency — Research

**Researched:** 2026-04-11
**Domain:** Prose editing, Liquid template structure, YAML authored content
**Confidence:** HIGH

---

## Summary

Phase 2 is a content and structure pass, not a visual design pass. The work splits cleanly into two categories: (1) authored prose in YAML source files that needs voice and punctuation fixes, and (2) Liquid template changes needed to move `WhyCantBypass` and `TheConstant` into visually dominant positions on chokepoint detail pages.

The em dash audit found em dashes in YAML source files, trend pages (authored prose), and Liquid layout templates (`&mdash;` entities and raw `—` characters). The `&mdash;` in layout templates (`chokepoint.html`, `default.html`) are in UI chrome — sigma rule labels and the footer tagline — and require template edits. The raw `—` in YAML and Markdown prose files require content edits.

`TheConstant` is the most critical gap: it exists in chokepoint YAML files and renders on the index card view via `_includes/chokepoint-card.html`, but it is **not rendered anywhere on the chokepoint detail page** (`_layouts/chokepoint.html`). A first-time reader landing on a chokepoint detail page never sees `TheConstant`. `WhyCantBypass` does render on detail pages, but only inside collapsible `<details>` stage accordions — it is not visually prominent. The fix for WRIT-04 requires adding `TheConstant` to the page header and surfacing `WhyCantBypass` earlier or more visibly. This is a template restructuring task. Whether it counts as "writing" or "design" is a scope boundary question — see the Scope Boundary section below.

**Primary recommendation:** Split the work into two plans: (1) a content-only plan for em dash removal and voice edits in YAML and Markdown files, and (2) a template-only plan for `TheConstant`/`WhyCantBypass` visibility in `chokepoint.html`. The template plan is structural, not visual-design — it moves existing content, it does not add new CSS or change colors.

---

## Project Constraints (from CLAUDE.md)

- All chokepoint YAML is canonical source of truth. Changes to authored prose fields (`Description`, `Notes`, `WhyCantBypass`, Variation `Notes`) are content edits, not schema changes.
- Voice must be peer-to-peer, evidence-first, conversational-technical. Match Tyler's voice.
- No em dashes per project memory (`feedback_writing_emdash.md`). Use periods/commas instead.
- Remove `AttackerControls`/`AttackerCannotControl` lists — project memory flagged these as bad pattern. (Note: the Liquid template still renders them if present in YAML; verify whether any YAMLs still have these fields populated.)
- Do not break inbound links or slug routes (Phase 3 constraint, but still relevant for any template changes in Phase 2).
- `jekyll build --strict` must pass after every template change.

---

## Em Dash Audit

### YAML Source Files (require content edits, not template edits)

Em dashes appear as raw `—` characters in authored prose fields.

**`chokepoints/initial-access/clickfix-techniques.yml`**
- Line 103: `"troubleshot.sh (note typo in filename — "troubleshot" not "troubleshoot")"` — in Variation `Note` field. Em dash used to introduce a clarification.
- Line 145: `"create urgency — the victim believes"` — in Variation `Notes` field. Em dash used as a conjunction.
- Line 206: `"February–March"` — this is an en dash (`–`) used as a date range separator. Acceptable usage; may not need changing.

**`chokepoints/initial-access/renamed-rmm-tools.yml`**
Multiple lines with `–` as date range separators in timeframe fields (`Jan–Apr`, `2024–2025`, `2023–present`, etc.). These are en dashes in range context — defensible. Review whether Tyler wants these changed to hyphens.

**`chokepoints/defense-evasion/edr-bypass-techniques.yml`**
- Line 131: `"No process termination events —"` — in `Context` field.

**`chokepoints/defense-evasion/ransomware-service-manipulation.yml`**
- Lines 139-140: `"Service State Change — stopped"`, `"Service Start Type Changed — disabled"` — in `LogSources` list items. These appear to be Windows Event Log channel names where the em dash is part of the official event description text. Check whether changing these would make the text inaccurate.

**`chokepoints/lateral-movement/remote-execution-tools.yml`**
- Lines 280, 285, 289, 294, 310: `MITRE ATT&CK — T1021.003`, `SOC Investigation — Event ID 5145` etc. These are in `References` list `Name` fields. The em dash is a separator between source name and document title — consistent with how these were authored. Replace with colon or comma.

### Layout Templates (require template edits)

**`_layouts/chokepoint.html`** (raw `—` characters and `&mdash;` entities):
- Line 1203: `<span class="sigma-label">IOK Rule &mdash; {{ ed.Layer }}</span>` — UI chrome
- Line 1205: `<span class="sigma-label">Sigma Rule &mdash; {{ ed.Layer }}</span>` — UI chrome
- Line 1236: Comment text: `{%- comment -%} Stage 1 only gets EarlyDetections (ETW/IOK) — no sigma rules here` — Liquid comments do not render to HTML. Not a visible issue. Low priority.
- Line 1310: `<span class="sigma-label">Sigma Rule &mdash; {{ det.Level }} Level</span>` — UI chrome
- Line 1364: `<span class="sigma-label">Sigma Rule &mdash; Hunt Level (Network)</span>` — UI chrome
- Line 1400: `<div class="det-meta-label">Goal — {{ ed.Layer }}</div>` — UI chrome
- Line 1413: `<span class="sigma-label">IOK Rule &mdash; {{ ed.Layer }}</span>` — UI chrome
- Line 1415: `<span class="sigma-label">Sigma Rule &mdash; {{ ed.Layer }}</span>` — UI chrome
- Line 1469: `<span class="sigma-label">Sigma Rule &mdash; {{ level }} Level</span>` — UI chrome
- Line 944 (raw `—`): `"invariant condition the attacker must satisfy — regardless of tool"` — inline prose in template
- Line 1062 (raw `—`): `"the list grows; the chokepoint doesn't change."` — no em dash here, just a semicolon. OK.

**`_layouts/default.html`**:
- Line 32: `&mdash; community detection engineering resource` — footer tagline

**`_layouts/attack-chain.html`**:
- No em dashes found in authored prose. The line at 36 uses "must" for emphasis, not an em dash.

### Trends and Docs Pages (require content edits)

**`trends/masq-infra.md`** (authored prose in `<p>` blocks):
- Line 4 (front matter `description`): `"— the domains that served malicious binaries"` — em dash in meta description
- Line 257: `"— chain coverage is"` — in methodology note
- Line 417: `"— shared favicon hash, shared IP address"` — in campaign section prose
- Lines 486, 487, 488, 559, 561, 565, 570: These are `| default: "—"` Liquid filters — they render a literal em dash as an empty-cell placeholder in tables. This is a display/UI decision, not prose. Tyler needs to decide whether placeholder dashes should stay (they're conventional in data tables) or be replaced with `N/A` or similar.

**`trends/index.md`**:
- Line 184: `"Chokepoints stay stable — but the techniques"` — prose
- Lines 201, 211: em dashes in pillar description prose
- Lines 385, 413: em dashes in callout prose

**`trends/clickgrab.md`**:
- Line 3 (front matter `title`): `"ClickFix Delivery Chain — Trend Analysis"` — page title
- Line 158 (`<h1>`): same title rendered in HTML
- Line 196: `"Every ClickFix variant — ClickFix, FileFix, TerminalFix, InstallFix — follows"` — two em dashes used as parenthetical
- Line 240: `"— the Nov 2025 surge was driven by"` — prose
- Line 249: `"— and why that rotation actually validates"` — prose
- Line 257 (two instances): em dashes in callout prose

**Summary count by location:**
| File | Em dash instances | Fix type |
|------|-------------------|----------|
| YAML source files | ~12 raw `—`, multiple `–` date ranges | Content edit |
| `_layouts/chokepoint.html` | ~8 `&mdash;` entities + 1 raw `—` prose | Template edit |
| `_layouts/default.html` | 1 `&mdash;` entity | Template edit |
| `trends/masq-infra.md` | 3 prose + 5 table placeholders | Content edit (prose); decision needed (placeholders) |
| `trends/index.md` | ~5 prose | Content edit |
| `trends/clickgrab.md` | ~7 prose + 1 title | Content edit |
| `docs/` files | Multiple `—` in project-internal docs | Internal docs — not public-facing, likely out of scope |
| `STATE.md` | `milestone_name: — Site Quality` | Internal planning file, not public-facing |

**Docs verdict:** `docs/LEARNED.md`, `docs/CHALLENGES.md`, `docs/project-knowledge.md` are internal project documentation, not public-facing pages. The requirement says "every page" but these aren't rendered to the site. Confirm scope with Tyler — most likely out of scope.

---

## WhyCantBypass / TheConstant Current Display

### `TheConstant` — Not Rendered on Detail Pages

`TheConstant` is defined in YAML at the top-level of each chokepoint file (e.g., `TheConstant: Browser download → renamed signed binary execution → persistent RMM C2 connection`).

It renders in **one place only**: `_includes/chokepoint-card.html` (the index listing card view), truncated to 80 characters with a "THE CONSTANT" label.

It does **not appear anywhere** in `_layouts/chokepoint.html` (the detail page). A reader clicking into a chokepoint detail page sees the name, description, tactic/MITRE badges, then scrolls directly into the "Attack Chokepoints" section (per-stage accordion). The chokepoint's one-line invariant summary is never surfaced.

**Fix required:** Add `TheConstant` to the chokepoint detail page header (the `<header>` block around line 874 in `chokepoint.html`), between the description paragraph and the byline. This is a template edit, not a content edit.

Not all YAML files have `TheConstant` populated at the top level. The field appears to exist on: `renamed-rmm-tools.yml`, `remote-execution-tools.yml`, `web-shells.yml`. Check each file for presence of the top-level `TheConstant` field vs. the per-stage `TheConstant` inside `EvolutionTimeline` entries (these are different). The top-level field is what the card and detail page should display.

**YAML files to verify for top-level `TheConstant`:**
- `clickfix-techniques.yml` — not found at top level during audit (only inside `EvolutionTimeline` via `byosi-scripting-interpreters.yml` search results — this was cross-contamination). Needs verification.
- `ransomware-service-manipulation.yml` — not found at top level.
- `edr-bypass-techniques.yml` — not found at top level.
- `browser-credential-theft.yml` — not found at top level.

If the field is absent from a YAML file, adding the template render block will silently produce no output (Liquid's `{% if cp.TheConstant %}` guard). But WRIT-04 requires the field to be *visually dominant* — so any YAML that lacks a top-level `TheConstant` needs the field authored as part of this phase.

### `WhyCantBypass` — Rendered, But Buried

`WhyCantBypass` is rendered in `chokepoint.html` at approximately line 997-1001, inside each `<details class="chokepoint-item">` accordion body. The render order within each stage accordion is:

1. Prerequisites (first stage only)
2. Input row
3. Chokepoint row (the invariant)
4. Observable row
5. **`WhyCantBypass` callout** (`.cp-why-unavoidable` with `.cp-why-label` "Why unavoidable")
6. Log sources, detection tier, Sigma links

The `WhyCantBypass` content is visually styled — red-tinted `.cp-why-unavoidable` box with a monospace "WHY UNAVOIDABLE" label. It is not hidden. However:

- It is inside a collapsible `<details>` element
- Only the first stage is open by default (`{% if forloop.first %}open{% endif %}`)
- The first stage does appear open on page load, so its `WhyCantBypass` is visible without user interaction

The problem: a first-time reader sees the page header (name, description, badges) and then lands at the "Attack Chokepoints" section header. The first stage accordion is open, showing Input → Chokepoint → Observable → WhyCantBypass in sequence. But `TheConstant` (the one-line invariant for the entire technique) is not above this section at all.

**Page content order for a first-time reader (current state):**

1. Breadcrumb + priority badge
2. Page title (`cp.Name`)
3. Tactic/MITRE/difficulty/prevalence badges
4. `cp.Description` paragraph (can be 100+ words)
5. Byline (author, updated date, source YAML link)
6. "Attack Chokepoints" heading
7. Intro text: "Each stage is an invariant condition..." (only if `AttackerControls`/`AttackerCannotControl` absent)
8. Stage 1 accordion (open) → Input → Chokepoint → Observable → WhyCantBypass
9. Connector pill (→ next stage)
10. Stage 2 accordion (closed)
11. ...
12. "Variations" section heading
13. Variant accordions (all closed)

The invariant isn't visible until a reader reaches step 8. The `Description` field (step 4) is where the invariant is most likely to be stated in prose form, but it's written as a multi-sentence paragraph, not a highlighted callout.

**Fix required for WRIT-04:** Insert `TheConstant` as a styled callout immediately below or adjacent to `cp.Description` in the `<header>` block. This brings the invariant to the top of every detail page without requiring the reader to find it inside an accordion.

---

## File Inventory — Public-Facing Authored Prose

Files that contain authored prose text that renders to the public site:

### Chokepoint YAML Files (content edits affect rendered output via `aggregate.py` + Jekyll build)
- `chokepoints/initial-access/clickfix-techniques.yml`
- `chokepoints/initial-access/renamed-rmm-tools.yml`
- `chokepoints/defense-evasion/ransomware-service-manipulation.yml`
- `chokepoints/defense-evasion/byosi-scripting-interpreters.yml`
- `chokepoints/defense-evasion/edr-bypass-techniques.yml`
- `chokepoints/persistence/web-shells.yml`
- `chokepoints/credential-access/browser-credential-theft.yml`
- `chokepoints/lateral-movement/remote-execution-tools.yml`

**Prose fields per YAML file** (fields with authored free-text that renders publicly):
- `Description` — top-level, renders in page header and card truncated
- `Variations[].Notes` — renders in variant accordion body
- `Variations[].NotesShort` — check if rendered; may only be for internal use
- `Chokepoints[].WhyCantBypass` — renders in stage accordion
- `Chokepoints[].Invariant` — renders as "Chokepoint" row in stage accordion
- `References[].Name` — renders in references section (contains em dashes)
- `TheConstant` — top-level; currently only renders on index card, not detail page

### Trends Pages (Markdown/HTML hybrid)
- `trends/clickgrab.md` — full authored analysis page
- `trends/masq-infra.md` — data-driven page with authored prose sections
- `trends/index.md` — trends landing page with authored section descriptions

### Layouts with Inline Authored Copy
- `_layouts/chokepoint.html` — contains inline prose in Liquid template (e.g., line 944: "Each stage is an invariant condition...", line 918: "Applying the chokepoint framework to...")
- `_layouts/attack-chain.html` — contains inline prose (lines 36, 118)
- `_layouts/default.html` — footer tagline

### Not Public-Facing (out of scope)
- `docs/LEARNED.md`, `docs/CHALLENGES.md`, `docs/project-knowledge.md` — internal project notes, not rendered to site
- `.planning/` files — planning infrastructure only
- `STATE.md`, `CLAUDE.md`, `FRAMEWORK.md`, `CONTRIBUTING.md` — repository documentation, not Jekyll pages

---

## Voice Audit — Specific Violations

Sampled from three YAML files. Quoted violations with diagnosis.

### `chokepoints/credential-access/browser-credential-theft.yml`

**`Description` field (lines 17-25):**
> "Infostealers systematically harvest credentials, cookies, and autofill data from browser credential databases. This is the single invariant behavior across all stealer families regardless of obfuscation or bypass technique. Hudson Rock tracks 30+ million infected computers; 1.8 billion credentials were stolen in 2025 alone, with enterprise credentials present in 14% of infections (up from 6% in early 2024)."

Issues:
- "systematically harvest" — throat-clearing adverb. Just "harvest."
- "This is the single invariant behavior" — redundant opener. The description should lead with the invariant, not announce it.
- The third sentence is a run-on stat dump. The numbers are valuable but the framing adds no weight.

Suggested rewrite direction: Open with the invariant as a statement of fact. Then give the scale numbers. Then name the families.

**`Variations[LummaC2].Notes` field:**
> "The dominant infostealer MaaS of 2024-2025, representing 51% of all dark web credential logs at peak. Delivered primarily via ClickFix (517% surge in 2025 ClickFix attacks) and malvertising."

This is clean. Evidence-first, no filler. Good example of the target voice.

### `chokepoints/persistence/web-shells.yml`

**`Description` field (lines 17-25):**
> "Adversaries plant web-accessible scripts (web shells) on compromised servers to maintain persistent command execution via HTTP/HTTPS. Web shells are deployed in virtually every major web-facing compromise, appearing in 35% of Q4 2024 IR incidents (Cisco Talos) and serving as the primary persistence mechanism in ProxyLogon, ProxyShell, MOVEit, Barracuda ESG, and Ivanti zero-day campaigns."

Issues:
- "Adversaries plant" — passive-ish construction with an impersonal subject. Could lead with the invariant instead.
- "web-accessible scripts (web shells)" — parenthetical definition is redundant given the page title.
- "to maintain persistent command execution" — wordy. "for persistent command execution" or just drop "persistent."
- The sentence that starts "Despite diversity..." (line 20) is strong but long. The parenthetical `(polyglot files, fileless IIS modules, steganography)` is a good detail but buries the key claim.

### `chokepoints/initial-access/clickfix-techniques.yml`

**`Description` field (lines 11-18):**
> "User pastes a malicious command from their clipboard into a Run dialog, terminal, or Explorer address bar. The lure page writes to the clipboard via JavaScript and the user does the rest. No attachment, no exploit, no macro. The clipboard is the delivery mechanism and the scripting interpreter spawn is the chokepoint."

This is strong Tyler voice. Short sentences, evidence-first, no filler. The "No attachment, no exploit, no macro" triplet works well. This is the target register.

> "APT28, MuddyWater, and Kimsuky adopted ClickFix for espionage in late 2024. This is not just commodity crimeware anymore."

"This is not just commodity crimeware anymore" — weak closer. The actor list already makes the point. The sentence adds nothing and is slightly dramatic. Cut it or replace with a specific impact statement.

### `trends/clickgrab.md` (lines 196, 249, 257)

> "Every ClickFix variant — ClickFix, FileFix, TerminalFix, InstallFix — follows these five stages."

The em dash parenthetical is the violation here. Fix: "Every ClickFix variant (ClickFix, FileFix, TerminalFix, InstallFix) follows these five stages." Or restructure.

> "The network fetch was the unavoidable action. This chart shows how adversaries rotated their download method as defenders tuned IWR/IEX-specific detections — and why that rotation actually validates the chokepoint approach."

Strong prose except the em dash. Easy fix: period after "detections." New sentence: "That rotation validates the chokepoint approach."

> "Dec 2025 pivot — your IWR detections worked. IWR/IEX drops sharply as WebClient and Curl surge in the same month. That's not coincidence — that's adversaries responding to detection pressure."

Two em dashes. "That's not coincidence — that's adversaries" is a rhetorical structure that works conversationally but has an em dash. Fix: "That's not coincidence. That's adversaries responding to detection pressure." Both sentences now punch independently, which is stronger.

---

## Template vs. Source Distinction

| Fix | Where | File |
|-----|-------|------|
| Em dashes in prose description/notes | YAML source files | 8 chokepoint YAMLs |
| Em dashes in Liquid prose string literals | Template file | `_layouts/chokepoint.html` line 944 |
| `&mdash;` in sigma rule label UI chrome | Template file | `_layouts/chokepoint.html` (8 instances) |
| `&mdash;` in footer | Template file | `_layouts/default.html` |
| Em dashes in trends prose | Markdown files | `trends/clickgrab.md`, `trends/index.md`, `trends/masq-infra.md` |
| `TheConstant` not shown on detail pages | Template file | `_layouts/chokepoint.html` |
| `TheConstant` absent from some YAMLs | YAML source files | Verify per-file; author field if missing |
| `WhyCantBypass` visibility | Template file (restructure) | `_layouts/chokepoint.html` |
| Voice/brevity pass | YAML source files | `Description`, `Notes`, `WhyCantBypass` fields |
| Filler closers | YAML source files | e.g., clickfix-techniques.yml `Description` |

---

## Scope Boundary — Writing vs. Design

The WRIT-04 requirement ("WhyCantBypass / TheConstant fields visually dominant") has an inherent template-edit component. Moving or adding content on the detail page requires editing `chokepoint.html`. This is structural, not visual design. The distinction:

- **Phase 2 scope (writing/structure):** Reorder existing content sections, add `TheConstant` callout using *existing* CSS classes (`.cp-invariant`, `.cp-invariant-label` already exist in the stylesheet). No new CSS. No color changes.
- **Phase 3 scope (visual design):** New CSS, new visual components, copy-to-clipboard JS, left-border accents, mobile reflow.

The existing stylesheet already has `.cp-invariant` and `.cp-invariant-label` classes (lines 148-166 of `chokepoint.html`) described as "Legacy invariant box (fallback for pages without new fields)." Using these existing classes for `TheConstant` in the header is pure Phase 2 work. If new visual treatment is desired, that belongs in Phase 3.

**Decision for planner:** WRIT-04 template work (adding `TheConstant` to detail page header using existing `.cp-invariant` style) is in Phase 2 scope. Any new visual treatment for prominence is Phase 3 scope.

---

## Architecture Patterns

### YAML → Site Data Flow
Content edits in chokepoint YAML files require `aggregate.py` to regenerate `_data/chokepoints.yml` before changes appear in the Jekyll build. This is a Phase 1 concern (generated files out of git) that Phase 2 depends on.

Workflow for any YAML content edit:
1. Edit `chokepoints/<tactic>/<name>.yml`
2. Run `python scripts/aggregate.py` (or equivalent build step)
3. Run `jekyll build --strict` to verify no warnings

### Template Edit Validation
Any `chokepoint.html` edit must be followed by `jekyll build --strict` to catch Liquid syntax errors. The Phase 1 research noted a pre-existing Liquid positional index bug — Phase 2 template edits should not interact with that bug (it's in the detection strategy section, Phase 2 changes target the header/overview section).

---

## Common Pitfalls

### Pitfall 1: Em Dash in Table Placeholder vs. Em Dash in Prose
**What goes wrong:** Blanket-replacing all `—` characters hits Liquid `| default: "—"` filters in masq-infra.md, breaking the table rendering (cells would show empty or "N/A" instead of a consistent placeholder dash).
**Why it happens:** The same character serves two purposes: prose punctuation (bad) and table empty-cell marker (conventional).
**How to avoid:** Replace prose em dashes explicitly by line. Do not use a global find-replace on `—`.
**Warning signs:** After replacement, `jekyll build --strict` output shows broken table cells or Liquid errors.

### Pitfall 2: `TheConstant` at Top Level vs. Inside `EvolutionTimeline`
**What goes wrong:** Grepping for `TheConstant:` in YAML finds entries inside `EvolutionTimeline` list items, not the top-level field the template needs.
**Why it happens:** The field name is reused at both levels of the schema (top-level invariant vs. per-event invariant in EvolutionTimeline).
**How to avoid:** Check for `TheConstant:` at the root indentation level (no leading spaces) in each YAML file. The top-level field should have zero indentation.
**Warning signs:** Template renders "THE CONSTANT" label but blank value, or renders the wrong text.

### Pitfall 3: Voice Edits Breaking YAML Syntax
**What goes wrong:** Editing a multi-line YAML string (block scalar or quoted scalar) introduces a quote character that breaks YAML parsing. The `aggregate.py` script fails silently or Jekyll reports a data load error.
**Why it happens:** Many `Notes` fields use single-quote YAML scalar syntax. A single quote inside the value must be escaped as `''` (doubled). An apostrophe added during prose editing breaks the parse.
**How to avoid:** After any YAML edit, validate with `python -c "import yaml; yaml.safe_load(open('chokepoints/...')"` or run aggregate.py and check for parse errors before committing.
**Warning signs:** `aggregate.py` exits with a YAML parse exception; `_data/chokepoints.yml` is empty or shorter than expected.

### Pitfall 4: Removing Em Dashes from Windows Event Log Descriptions
**What goes wrong:** The `LogSources` fields in `ransomware-service-manipulation.yml` contain strings like `"Windows System Event ID 7036 (Service State Change — stopped)"`. The em dash is part of the Windows event channel's official description text. Replacing it makes the description inaccurate.
**How to avoid:** Leave em dashes in LogSources entries where they quote official Windows Event Log channel names. Only remove em dashes from free-form authored prose.

---

## Open Questions

1. **Table placeholder dashes in masq-infra.md**
   - What we know: `| default: "—"` Liquid filters produce em dashes in table cells as "no data" placeholders.
   - What's unclear: Whether Tyler considers these in scope for WRIT-01. They're conventional data-table notation, not prose punctuation.
   - Recommendation: Leave table placeholder dashes. Scope WRIT-01 to prose/sentence-level em dashes only.

2. **`TheConstant` missing from some YAML files**
   - What we know: `clickfix-techniques.yml`, `ransomware-service-manipulation.yml`, `edr-bypass-techniques.yml`, `browser-credential-theft.yml` may lack a top-level `TheConstant` field.
   - What's unclear: Whether authoring these fields is in Phase 2 scope (it is required for WRIT-04 to fully deliver) or whether the template change alone satisfies WRIT-04 for the files that already have the field.
   - Recommendation: Author the field in all YAML files that lack it. One line per chokepoint. This is the most important writing task in the phase.

3. **`AttackerControls` / `AttackerCannotControl` still in template**
   - What we know: `chokepoint.html` lines 917-942 still render these fields if present in YAML. Project memory says to remove these lists.
   - What's unclear: Whether any YAML files still have these fields populated, and whether removing the template block is Phase 2 or Phase 3 scope.
   - Recommendation: Grep for `AttackerControls:` in YAML files. If none are populated, the template block renders nothing and can be cleaned up as part of Phase 2 template work with no risk.

4. **Internal docs em dash scope**
   - What we know: `docs/LEARNED.md`, `docs/CHALLENGES.md`, `docs/project-knowledge.md` contain many em dashes.
   - What's unclear: Whether WRIT-01 ("every page") includes these internal files or only public-facing rendered pages.
   - Recommendation: Exclude internal docs. The requirement says "chokepoints, trends, docs, layouts" in the REQUIREMENTS.md text — "docs" likely refers to the `docs/` pages if any are Jekyll-rendered. Verify whether any `docs/*.md` files have Jekyll front matter and are rendered to the site.

---

## Validation Architecture

Phase 2 has no automated test framework. The validation approach is manual inspection and build verification.

### Per-task validation
- After any YAML edit: `python scripts/aggregate.py && jekyll build --strict`
- After any template edit: `jekyll build --strict`
- Voice check: Read the edited prose aloud. If it sounds like a press release or a vendor white paper, rewrite.

### Phase gate
- `jekyll build --strict` passes with zero warnings
- Manual review: visit each edited chokepoint detail page and verify `TheConstant` visible in header
- Manual review: search rendered output for `—` and `–` in prose contexts (not code blocks, not table cells)
- Manual review: voice consistency — all Description fields should read at the same register

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `docs/*.md` files are not Jekyll-rendered pages | File Inventory | If they are rendered, em dashes in docs/ are in scope for WRIT-01 |
| A2 | `.cp-invariant` CSS class is sufficient for TheConstant callout styling (no new CSS needed) | Scope Boundary | If existing style is insufficient, Phase 3 CSS work is required before WRIT-04 can be marked done |
| A3 | `AttackerControls`/`AttackerCannotControl` fields are not populated in any current YAML | Open Questions | If populated, template cleanup risks removing displayed content |
| A4 | En dashes (`–`) in date range contexts (`2024–2025`, `Jan–Apr`) are acceptable | Em Dash Audit | Tyler may want all en dashes normalized to hyphens; preference not explicitly documented |
| A5 | `TheConstant` is absent from top level in `clickfix-techniques.yml`, `ransomware-service-manipulation.yml`, `edr-bypass-techniques.yml`, `browser-credential-theft.yml` | WhyCantBypass/TheConstant | If present at unusual indentation, authoring the field would duplicate it |

---

## Sources

### Primary (HIGH confidence)
- Direct file reads: `_layouts/chokepoint.html`, `_includes/chokepoint-card.html`, all 8 chokepoint YAML files, `trends/clickgrab.md`, `trends/masq-infra.md`, `trends/index.md`, `_layouts/default.html` — all findings based on direct inspection of current file state
- `CLAUDE.md` — project constraints and voice guidelines
- `.planning/REQUIREMENTS.md` — requirement definitions for WRIT-01 through WRIT-04

### Secondary (MEDIUM confidence)
- `docs/project-knowledge.md` — project architecture context
- Memory files (`user_writing_style.md`, `feedback_writing_emdash.md`, `feedback_badge_reuse.md`) — referenced via system-reminder context

### Tertiary (LOW confidence)
- None. All findings in this research were verified by direct file inspection.

---

**Research date:** 2026-04-11
**Valid until:** Stable — no external dependencies. Valid until files are changed.
