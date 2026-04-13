# Conventions — detection-chokepoints

## Chokepoint YAML

- **File naming:** `chokepoints/<tactic>/<technique-name>.yml` — hyphenated, lowercase, descriptive
- **Tactic directory names** match MITRE canonical: `initial-access`, `defense-evasion`, `persistence`, `credential-access`, `lateral-movement`, etc.
- **Id field:** UUIDv4, generated at entry creation, never changed
- **MITRE IDs:** Sub-technique IDs required where available (`T1059.001` not `T1059`)
- **DetectionPriority:** `CRITICAL | HIGH | MEDIUM | LOW` — always uppercase
- **ThreatPrevalence:** `VERY HIGH | HIGH | MEDIUM | LOW | EMERGING` — always uppercase
- **DetectionDifficulty:** `LOW | MEDIUM | HIGH` — always uppercase
- **Variation.Status:** `Active | Emerging | Declining | Legacy` — Title case
- **LastUpdated:** ISO 8601 date string: `"2025-01-15"`
- **Author:** `"@iimp0ster"` — Twitter/X handle format

## TheConstant Field Convention

Each chokepoint YAML should have a `TheConstant` field — a single sentence summarizing the invariant in plain language. This is the chokepoint in one line: "What the attacker MUST do, regardless of tool."

## Sigma Rules

- **Directory:** `sigma-rules/<chokepoint-slug>/`
- **Files:** `research.yml`, `hunt.yml`, `analyst.yml` (all three required; `hunt-network.yml` optional for network-layer variants)
- **IDs:** UUIDv4 in `id:` field
- **Tags:** Must include `attack.tXXXX` sub-technique IDs and `detection.maturity.<level>`
- **Required fields:** `title`, `id`, `status`, `description`, `references`, `author`, `date`, `tags`, `logsource`, `detection`, `falsepositives`, `level`
- **Filter block:** Always include a `filter_legit_software` condition block even if empty
- **Reference analyst rule:** `sigma-rules/clickfix/analyst.yml`

## IOK Rules

- **Directory:** `iok-rules/<chokepoint>/<name>.yml`
- **Format:** Sigma-based, targeting web proxy or phish.report
- **Matchers:** `html`, `js`, `dom`, `requests`, `headers`
- **Reference:** `iok-rules/clickfix/clickfix-lure.yml`

## YAML Field Name Casing

All YAML fields use **PascalCase**: `Name`, `Id`, `MitreIds`, `DetectionPriority`, `Variations`, `Chokepoints`, `EvolutionTimeline`, `EarlyDetections`, `OsintSources`, etc.

Computed fields added by `aggregate.py` use **`_snake_case`** prefix: `_tactic`, `_slug`, `_sigma_research`, `_emulation_content`. These are never added manually.

## Writing Style (CLAUDE.md guidance)

- Conversational-technical tone — peer-to-peer, not documentation-voice
- Evidence-first: lead with the observable behavior, not the tool name
- Use periods and commas instead of em dashes
- Invariants framed as: "what MUST be true regardless of tool rotation"
- Avoid AttackerControls/AttackerCannotControl lists (deprecated pattern)
- EvolutionTimeline entries must include `DetectionImpact` — call out if new log source needed

## Sigma Rule Maturity Model

| Level | Purpose | FP Rate | Tags |
|-------|---------|---------|------|
| research | Baseline visibility, understand behavior | High | `detection.maturity.research` |
| hunt | Refined, noise reduced | Medium | `detection.maturity.hunt` |
| analyst | Production SOC alerting | Low | `detection.maturity.analyst` |

Never skip levels. Research establishes the behavioral baseline for tuning.

## SigmaRef Paths

Paths in chokepoint YAML always use forward slashes and are relative to repo root:
`"sigma-rules/clickfix/research.yml"` — not `"./sigma-rules/..."` or Windows-style paths.

## KnownBypasses (deprecated)

Field is preserved in schema for data integrity but **do not add new entries**. Not rendered in current layout.
