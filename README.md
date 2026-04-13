# Detection Chokepoints

> **TTPs evolve. Chokepoints don't.**

---

## The Military Analogy

In 480 BC, 300 Spartans held the pass at Thermopylae against a Persian army of hundreds of thousands. The narrow coastal pass stripped the Persians of their numerical advantage. To advance, they *had* to traverse it. Every attacker, every time.

During the Cold War, NATO planners identified the Fulda Gap as the likely invasion route for Warsaw Pact armor into Western Germany. The geography forced any large armored force through a handful of passable corridors. Defend those corridors and you neutralize the mass.

**Detection engineering has the same opportunity.** No matter how many ransomware families, RMM tools, or clipboard-attack variants emerge, every attacker must traverse certain chokepoints — conditions that *must* be met for the technique to work. Detect the chokepoint, and you detect all current and future variations that require it.

---

## Why Chokepoints?

| Traditional Detection | Chokepoint Detection |
|----------------------|---------------------|
| Detects a specific tool or hash | Detects the requirement the tool must satisfy |
| Breaks when the tool is renamed or replaced | Survives tool rotation, obfuscation, and variation |
| Narrow coverage (one threat family) | Broad coverage (all families sharing the chokepoint) |
| Requires constant signature updates | Durable. New tools hit the same chokepoints. |
| High long-term maintenance cost | Low long-term maintenance cost |

**This isn't theory.** Kaspersky's analysis of eight major ransomware groups, including Conti, LockBit 2.0, BlackCat, and five others, found that all eight share the same core kill chain. External Remote Services, Command and Scripting Interpreter, WMI, and LSASS credential dumping appear across every single group, regardless of variant, affiliate, or toolset. Shadow copy deletion and service stopping appear in 7-8 of 8. The tools rotate. The requirements do not.

**Time = Money.** Dwell time has compressed from weeks to hours as Initial Access Brokers sell pre-authenticated environments to ransomware operators. There's no time to chase every new tool signature. Chokepoints let you strangle threats at the conditions they *cannot avoid*.

```
Time to Ransom (TTR) Compression:
  2020: ~21 days average
  2022: ~7 days average
  2024: ~2 days average
  2025: <24 hours median     ← Mandiant M-Trends 2025
```

---

## The Framework

Every chokepoint is built around three questions:

```
┌─────────────────┬──────────────────────┬──────────────────────────────┐
│      Scope      │      Variations      │        Prerequisites         │
├─────────────────┼──────────────────────┼──────────────────────────────┤
│ Which tactic(s) │ What tools/methods   │ What MUST be true for this   │
│ and technique   │ exploit this         │ to succeed — regardless of   │
│ does this cover?│ chokepoint today?    │ tool choice?                 │
└─────────────────┴──────────────────────┴──────────────────────────────┘
```

The **prerequisites** are the chokepoint. The scope keeps the work bounded. The variations column validates that your detection survives tool rotation. Full methodology in [FRAMEWORK.md](FRAMEWORK.md).

---

## Detection Maturity Model

Chokepoint detections are built iteratively at three levels. Don't skip ahead.

| Level | Goal | False Positive Rate | Use Case |
|-------|------|-------------------|----------|
| **Research** | Visibility, baseline understanding | High | Threat research, log source validation |
| **Hunt** | Refined coverage, noise reduction | Medium | Proactive hunting, campaign detection |
| **Analyst** | Production alerting, low FP | Low | SOC alerting, automated IR response |

Start broad. The research rule tells you what's in your environment. The hunt rule tells you what's interesting. The analyst rule tells your SOC what to respond to. The research rule is the foundation — without it, you can't tune intelligently.

---

## Chokepoint Index

`†` = empirically confirmed across 8/8 major ransomware groups (Kaspersky 2022)

| Chokepoint | Tactic | Priority | Prevalence | Difficulty |
|------------|--------|----------|------------|------------|
| [ClickFix Techniques](chokepoints/initial-access/clickfix-techniques.yml) | Initial Access | HIGH | HIGH | LOW |
| [Renamed RMM Tools](chokepoints/initial-access/renamed-rmm-tools.yml) | Initial Access / C2 | HIGH | HIGH | MEDIUM |
| [Remote Execution Tools](chokepoints/lateral-movement/remote-execution-tools.yml) `†` | Lateral Movement | HIGH | HIGH | MEDIUM |
| [Ransomware Service Manipulation](chokepoints/defense-evasion/ransomware-service-manipulation.yml) `†` | Defense Evasion / Impact | CRITICAL | HIGH | LOW |
| [Browser Credential Theft](chokepoints/credential-access/browser-credential-theft.yml) `†` | Credential Access | CRITICAL | HIGH | MEDIUM |
| [EDR Bypass Techniques](chokepoints/defense-evasion/edr-bypass-techniques.yml) `†` | Defense Evasion | CRITICAL | HIGH | HIGH |
| [Web Shell Persistence](chokepoints/persistence/web-shells.yml) | Persistence / Initial Access | CRITICAL | HIGH | MEDIUM |

---

## Repository Structure

```
detection-chokepoints/
├── chokepoints/                    # Canonical YAML entries — one file per chokepoint
│   ├── initial-access/
│   ├── lateral-movement/
│   ├── defense-evasion/
│   ├── credential-access/
│   └── persistence/
├── sigma-rules/                    # Detection rules at 3 maturity levels
│   └── <chokepoint>/
│       ├── research.yml
│       ├── hunt.yml
│       └── analyst.yml
├── iok-rules/                      # Indicator of Knowledge rules for lure/phishing page detection
├── emulation/                      # PowerShell scripts to validate detections in a lab
├── attack-chains/                  # Full kill chain documentation (ransomware, infostealers)
├── intel/                          # Free intelligence resources tied to specific chokepoints
├── trends/                         # Threat trend analyses and chokepoint evolution tracking
├── templates/                      # Templates for contributors
│   ├── chokepoint-template.yml     # Canonical YAML template
│   ├── quick-add.md                # Fast template for adding a new variant
│   ├── evolution-tracker.md        # Template for tracking technique shifts over time
│   └── EXAMPLE-WORKFLOW.md        # Complete worked example: adding Impacket RDP shadowing
└── schema/
    └── chokepoint-schema.yml       # All valid fields and values
```

---

## How to Use This Repository

### For Threat Hunters
1. Browse [chokepoints/](chokepoints/) by tactic
2. Grab the sigma rule at your target maturity level from [sigma-rules/](sigma-rules/)
3. Check [intel/](intel/) for free intelligence resources tied to specific chokepoints
4. Review [trends/](trends/) for live data analysis and current threat landscape

### For Detection Engineers
1. Use the Research rule to baseline behavior in your environment
2. Tune the Hunt rule against your baseline to reduce false positives
3. Deploy the Analyst rule to production once the false positive rate is acceptable
4. Validate rules with the PowerShell emulation scripts in [emulation/](emulation/)

### For Phishing and Lure Detection
Check [iok-rules/](iok-rules/) for Indicator of Knowledge rules targeting lure page behaviors. IOK rules detect the invariant page-side behaviors regardless of visual design or obfuscation.

---

## How to Contribute

This is a community resource for detection engineers, threat hunters, and incident responders. You don't need to submit a complete chokepoint page to contribute. Every empty field on an existing page is an open contribution. Pick what you can fill in.

### What this project is

Contributions must be grounded in **chokepoints** — the prerequisites that attackers *cannot bypass* regardless of tool choice. This is not an IOC feed or a signature database. The goal is invariant conditions and durable detections.

**Ask yourself before submitting:** "If the attacker switches tools tomorrow, does this detection still fire?" If yes, it's a chokepoint. If no, it may be a useful IOC, but it's not a chokepoint entry.

---

### Ways to Contribute

#### New Chokepoint Page

A technique or attack requirement not yet documented in the repo.

Start with `templates/chokepoint-template.yml` and fill in the `AttackerControls` and `AttackerCannotControl` fields **before** writing any detection stages. If you can't clearly list what the attacker cannot control, the chokepoint hasn't been properly identified yet.

**Minimum requirements:**
- Complete YAML entry with all required metadata fields (see `schema/chokepoint-schema.yml`)
- `Prerequisites`, `AttackerControls`, `AttackerCannotControl` filled in
- At least Research and Hunt level Sigma rules
- At least one source reference (MITRE, threat report, research blog)

Full field reference: [CONTRIBUTING.md](CONTRIBUTING.md). Worked example: [templates/EXAMPLE-WORKFLOW.md](templates/EXAMPLE-WORKFLOW.md).

---

#### Sigma Detection Rules

Rules at any of the three maturity levels targeting an existing chokepoint. If a chokepoint page exists but the Sigma rules are missing or thin, that's an open contribution.

Rules live at `sigma-rules/<chokepoint-name>/research.yml`, `hunt.yml`, `analyst.yml`.

Required Sigma fields: `title`, `id` (UUIDv4, different from the chokepoint ID), `status`, `description`, `references`, `author`, `date`, `tags`, `logsource`, `detection`, `falsepositives`, `level`.

Tags must include `attack.<tactic>`, `attack.t<technique-id>`, and `detection.maturity.<level>`.

| Maturity | Sigma level | Notes |
|----------|-------------|-------|
| Research | `informational` | High FP expected. For baselining, not alerting. |
| Hunt | `low` or `medium` | Reduced noise. For active hunting. |
| Analyst | `high` or `critical` | SOC-deployable. Minimal FPs. |

Always include a `falsepositives` field. If you genuinely cannot identify false positive scenarios, say that explicitly with a note explaining why.

---

#### New Variation on an Existing Chokepoint

A new tool, malware family, or delivery method that exploits an existing chokepoint. This is the most common contribution. When a new variant hits threat reports, it's usually a variation on an existing invariant, not a new chokepoint.

**What to add:**
- An entry in the `Variations:` list in the relevant YAML file
- An `EvolutionTimeline:` entry with a `DetectionImpact` field explaining whether existing detections cover the new variant or whether a rule update is needed
- `CHANGELOG.md` update

Use `templates/quick-add.md` for the fast path. See [templates/EXAMPLE-WORKFLOW.md](templates/EXAMPLE-WORKFLOW.md) for a complete walkthrough.

**Defang all IOCs.** Payload examples must be sourced from the `SourceURL` article, not fabricated.

---

#### Log Samples

Real or realistic log events for the `RawLogs:` field in a chokepoint YAML, or as `TruePositive:` examples inside a chokepoint stage. These help detection engineers understand what a hit actually looks like in telemetry before they tune their rules.

A good log sample includes the event ID, the key field values that trigger the detection, and a `KeySignal` line explaining which fields confirm it as a true positive.

---

#### Emulation Scripts

PowerShell scripts that simulate chokepoint behavior in a controlled lab environment. These let detection engineers validate that their Sigma rules fire before deploying to production.

Scripts live at `emulation/<chokepoint>/emulate.ps1`.

**Requirements:**
- `SafetyNotes` block at the top. Lab use only, isolated VM only.
- Maps to an Atomic Red Team technique ID via `AtomicRef`
- Outbound connections point to benign destinations (`example.com`)

---

#### IOK Rules

Sigma-based rules for detecting lure and phishing pages at the web proxy or phish.report layer. IOK rules target the invariant page-side behaviors — clipboard seeding, execution prompts, obfuscated JavaScript patterns.

Rules live at `iok-rules/<chokepoint>/<name>.yml`. Use `html`, `js`, `dom`, `requests`, and `headers` matchers. Reference example: `iok-rules/clickfix/clickfix-lure.yml`.

Link new IOK rules from the relevant chokepoint YAML under `EarlyDetections:`.

---

#### OSINT Queries

Platform-specific queries for the `OsintSources:` field in a chokepoint YAML. Supported platforms include URLScan, Shodan, Censys, FOFA, Hunt.io, Validin, and VirusTotal Intelligence.

Every query needs a `Notes` field explaining **why** this query has cross-variant resilience, not just what it matches. A query that fires on a specific domain is an IOC. A query that fires on infrastructure patterns shared across variants is an OSINT chokepoint pivot.

---

#### Evolution Timeline Entries

Date-stamped entries in `EvolutionTimeline:` documenting how a technique has changed. These belong in the relevant chokepoint YAML.

Each entry needs a `DetectionImpact` field. If the existing Sigma rules still cover the new variant, say so explicitly. If a new log source or parent process constraint is needed, call it out. The goal is to make the timeline useful for detection engineers trying to understand whether their current rules are still valid.

---

#### Partial Contributions

You don't need to fill in a whole chokepoint page at once. Any of the following are valid standalone PRs:

- A single missing Sigma rule (research, hunt, or analyst level)
- OSINT queries for a platform that isn't covered yet
- Log samples for a stage that has empty `RawLogs`
- An `EmulationScript:` entry for a chokepoint that doesn't have one
- A `TruePositive:` log example for an existing chokepoint stage
- An `EvolutionTimeline:` entry for a recently reported variant
- A `BypassNote:` documenting a known evasion path

If you see an empty field and you have data to fill it in, that's enough reason to open a PR.

---

### What Not to Submit

| Don't submit | Why |
|-------------|-----|
| Raw IP/domain/hash lists | These are IOCs, not chokepoints |
| Detection for a single tool by name | Reframe around the chokepoint the tool exploits |
| Fabricated payload examples | Variation payload commands must be sourced from the cited `SourceURL` |
| Rules without a `falsepositives` field | Understanding FP scenarios is part of the quality bar |
| MITRE IDs not in the current ATT&CK framework | Verify at attack.mitre.org before submitting |

---

### PR Process

1. Fork the repository
2. Create a branch named `<your-handle>/<chokepoint-name>` (e.g., `jsmith/browser-cred-theft`)
3. Use `templates/chokepoint-template.yml` as a starting point for new pages
4. Fill in `AttackerControls` and `AttackerCannotControl` before writing stages
5. Update `CHANGELOG.md`
6. Submit a PR with the checklist from [CONTRIBUTING.md](CONTRIBUTING.md) completed

For questions, open a GitHub Issue with the `question` label and reference the relevant chokepoint file.

---

## Key Reference Files

| File | Purpose |
|------|---------|
| [FRAMEWORK.md](FRAMEWORK.md) | Full methodology for identifying chokepoints |
| [CONTRIBUTING.md](CONTRIBUTING.md) | PR checklist and complete field reference |
| [schema/chokepoint-schema.yml](schema/chokepoint-schema.yml) | All valid fields and values for chokepoint YAML |
| [templates/chokepoint-template.yml](templates/chokepoint-template.yml) | Blank YAML template for new entries |
| [templates/EXAMPLE-WORKFLOW.md](templates/EXAMPLE-WORKFLOW.md) | End-to-end worked example: adding Impacket RDP shadowing |
| [chokepoints/initial-access/clickfix-techniques.yml](chokepoints/initial-access/clickfix-techniques.yml) | Most complete chokepoint entry. Use as reference. |
| [sigma-rules/clickfix/analyst.yml](sigma-rules/clickfix/analyst.yml) | Reference analyst-level Sigma rule |

---

## Resources

| Resource | Description |
|----------|-------------|
| [MITRE ATT&CK](https://attack.mitre.org/) | Technique taxonomy used for all chokepoint mappings |
| [Sigma Specification](https://github.com/SigmaHQ/sigma-specification) | Rule format used across all detection levels |
| [Mandiant M-Trends](https://www.mandiant.com/m-trends) | Source for TTR compression statistics |
| [Kaspersky — Common TTPs of Modern Ransomware](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2022/06/23093553/Common-TTPs-of-the-modern-ransomware_low-res.pdf) | Cross-group TTP analysis across 8 ransomware families |
| [Red Canary — The Why, What, and How of Threat Research](https://redcanary.com/blog/threat-detection/threat-research-questions/) | Research methodology behind the Scope/Variations/Prerequisites framework |
| [Huntress ClickFix Analysis](https://huntress.com/blog/dont-sweat-clickfix-techniques) | In-the-wild ClickFix variant breakdown |

---

> *"Detection is a game of economics. Make it expensive for attackers to avoid your detections."*
