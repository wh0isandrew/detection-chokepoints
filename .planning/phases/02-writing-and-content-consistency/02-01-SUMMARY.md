---
phase: 02-writing-and-content-consistency
plan: 01
subsystem: content
tags: [em-dash, voice, yaml, markdown, description-fields]
dependency_graph:
  requires: []
  provides: [clean-prose-yaml, voice-consistent-descriptions]
  affects: [_data/chokepoints.yml, jekyll-render]
tech_stack:
  added: []
  patterns: [yaml-quoted-scalars, short-sentence-prose]
key_files:
  created: []
  modified:
    - chokepoints/initial-access/clickfix-techniques.yml
    - chokepoints/defense-evasion/edr-bypass-techniques.yml
    - chokepoints/lateral-movement/remote-execution-tools.yml
    - chokepoints/defense-evasion/ransomware-service-manipulation.yml
    - chokepoints/credential-access/browser-credential-theft.yml
    - chokepoints/persistence/web-shells.yml
    - chokepoints/initial-access/renamed-rmm-tools.yml
    - chokepoints/defense-evasion/byosi-scripting-interpreters.yml
    - trends/clickgrab.md
    - trends/index.md
    - trends/masq-infra.md
decisions:
  - "Preserve Liquid `{% else %}—{% endif %}` constructs in clickgrab.md as equivalent to `| default: \"—\"` table-cell placeholders — same function, different syntax"
  - "Fix em dashes in Invocation code block comments despite not being rendered prose — consistency across file and zero-em-dash acceptance criteria"
  - "Replace all References[].Name em dash separators with colons and quote the YAML scalar — colons in unquoted YAML scalars cause ScannerError"
  - "ransomware-service-manipulation.yml Windows Event Log strings preserved: Service State Change — stopped and Service Start Type Changed — disabled are official channel description text (Pitfall 4)"
metrics:
  duration: "~45 minutes"
  completed: "2026-04-11"
  tasks: 2
  files_modified: 11
---

# Phase 2 Plan 1: Em Dash Removal and Description Voice Tightening

One-liner: Removed all prose em dashes from 8 chokepoint YAMLs and 3 trends Markdown files; rewrote 5 Description fields to match ClickFix's evidence-first, short-sentence register.

## What Was Done

### Task 1: Em Dash Removal

Removed prose em dashes from every targeted file. The plan specified the highest-value targets; execution extended to all em dashes found in the listed files to satisfy the acceptance criteria.

**YAML files:**
- `clickfix-techniques.yml`: Fixed 10 em dashes across Notes, Detections Description, and References Name fields. Cut the weak closer "This is not just commodity crimeware anymore." from the Description. Quoted all References Name YAML scalars that contained colons.
- `edr-bypass-techniques.yml`: Fixed 7 em dashes in Context field and Variation/References Name fields.
- `remote-execution-tools.yml`: Fixed 5 em dashes in References Name fields.
- `ransomware-service-manipulation.yml`: Fixed em dash in Qilin Invocation code comment. Preserved the 2 Windows Event Log quoted strings (`Service State Change — stopped`, `Service Start Type Changed — disabled`) per Pitfall 4.
- `browser-credential-theft.yml`: Fixed em dashes in 2 Invocation code comments and 5 References Name fields.
- `web-shells.yml`: Fixed em dashes in 6 Invocation code comments, 1 detection logic string, and 5 References Name fields.
- `renamed-rmm-tools.yml`: Fixed em dashes in 2 Invocation code comments, 12 Sources list items, and 4 References Name fields.
- `byosi-scripting-interpreters.yml`: Fixed 7 em dashes in Variation Name and References Name fields.

**Markdown files:**
- `trends/clickgrab.md`: Fixed 15+ em dashes in front matter title, h1, h2 headings, and prose paragraphs. Preserved 3 `{% else %}—{% endif %}` Liquid table-cell placeholders.
- `trends/index.md`: Fixed 5 em dashes in front matter description, hero paragraph, pillar descriptions, and card copy.
- `trends/masq-infra.md`: Fixed 5 em dashes in front matter description, methodology text, chains section, and campaigns section prose. Preserved 7 Liquid `| default: "—"` table placeholder instances.

**Rule 1 deviation — YAML quoting fix:** Converting em dash separators to colons in YAML Name fields without quoting causes `ScannerError: mapping values are not allowed here`. All converted Name fields were quoted with single quotes. Apostrophes inside single-quoted YAML strings were doubled per YAML spec.

### Task 2: Description Voice Tightening

Rewrote 5 Description fields to match the ClickFix register (evidence-first, short sentences, no throat-clearing openers).

| File | Before (opener) | After (opener) |
|------|----------------|----------------|
| `browser-credential-theft.yml` | "Infostealers systematically harvest..." | "Every infostealer reads the same files..." |
| `web-shells.yml` | "Adversaries plant web-accessible scripts..." | "A script lives in the web root and the server executes it on request." |
| `renamed-rmm-tools.yml` | "Legitimate remote management and monitoring (RMM) tools are renamed..." | "A legitimately signed RMM binary is renamed, delivered via browser download, and executed by the user." |
| `byosi-scripting-interpreters.yml` | "Adversaries bring legitimate, vendor-signed scripting interpreters..." | "A vendor-signed interpreter binary...runs attacker-controlled scripts." |
| `ransomware-service-manipulation.yml` | "Before encrypting files, ransomware operators stop and delete..." | "Before encrypting files, ransomware stops and deletes..." |

All stats and citations preserved in every rewrite. No em dashes introduced.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] YAML ScannerError from unquoted Name fields with colons**
- **Found during:** Task 1, YAML validation after em dash substitution
- **Issue:** Replacing ` — ` with `: ` in References/Variation Name fields produced unquoted YAML scalars containing colons, causing `yaml.scanner.ScannerError: mapping values are not allowed here`
- **Fix:** Wrapped all affected Name values in single quotes; doubled internal apostrophes per YAML spec
- **Files modified:** All 8 YAML files
- **Commit:** 02d545e

**2. [Rule 2 - Scope extension] Em dash removal extended beyond plan-specified files**
- **Found during:** Task 1, em dash grep across all 8 YAML files listed in frontmatter
- **Issue:** `web-shells.yml` and `renamed-rmm-tools.yml` were listed in the plan's `files_modified` frontmatter and the overall verification criteria, but not in Task 1's `<files>` list. Both contained em dashes.
- **Fix:** Fixed all em dashes in both files to satisfy the phase-level verification criteria (`grep -rn $'\u2014' chokepoints/` returns only Windows EL preserved lines)
- **Files modified:** `chokepoints/persistence/web-shells.yml`, `chokepoints/initial-access/renamed-rmm-tools.yml`
- **Commit:** 7f76a68

## Known Stubs

None. All Description fields are fully authored. No placeholder text introduced.

## Threat Flags

None. This plan made no changes that introduce new network endpoints, auth paths, file access patterns, or schema changes.

## Self-Check: PASSED

**Commits exist:**
- 02d545e: `refactor(02-01): remove prose em dashes from YAML and Markdown files`
- 7f76a68: `refactor(02-01): voice tighten Description fields and remove remaining em dashes`

**Key acceptance criteria verified:**
- All 8 YAML files parse via `yaml.safe_load` with UTF-8 encoding
- `clickfix-techniques.yml`, `edr-bypass-techniques.yml`, `remote-execution-tools.yml`: 0 em dashes
- `ransomware-service-manipulation.yml`: 2 remaining em dashes (Windows Event Log preserved strings only)
- `browser-credential-theft.yml`, `web-shells.yml`, `renamed-rmm-tools.yml`, `byosi-scripting-interpreters.yml`: 0 em dashes
- `trends/clickgrab.md`: 0 prose em dashes; 3 Liquid `{% else %}—{% endif %}` table placeholders preserved
- `trends/index.md`: 0 em dashes
- `trends/masq-infra.md`: 0 prose em dashes; 7 Liquid `| default: "—"` table placeholders preserved
- `grep -F 'not just commodity crimeware' clickfix-techniques.yml`: 0 matches
- `grep -F 'ClickFix Delivery Chain: Trend Analysis' trends/clickgrab.md`: 2 matches (front matter + h1)
- `grep -F 'systematically harvest' browser-credential-theft.yml`: 0 matches
- `grep -F 'Hudson Rock' browser-credential-theft.yml`: 4 matches (stat preserved)
- `grep -F '1.8 billion' browser-credential-theft.yml`: 2 matches (stat preserved)
- `grep -F 'Adversaries plant web-accessible' web-shells.yml`: 0 matches
- `grep -F 'ProxyLogon' web-shells.yml`: 2 matches (campaign list preserved)
- `grep -F '35% of Q4 2024' web-shells.yml`: 1 match (stat preserved)
- All 8 YAML files have top-level `TheConstant` field (plan_checker_note conditional not triggered)
