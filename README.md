# Detection Chokepoints

> **TTPs evolve. Chokepoints don't.**

---

## The Military Analogy

In 480 BC, 300 Spartans held the pass at Thermopylae against a Persian army of hundreds
of thousands. The narrow coastal pass — a chokepoint — stripped the Persians of their
numerical advantage. To advance, they *had* to traverse it. Every attacker, every time.

During the Cold War, NATO planners identified the Fulda Gap as the likely invasion route
for Warsaw Pact armor into Western Germany. The geography forced any large armored force
through a handful of passable corridors. Defend those corridors and you neutralize the
mass.

**Detection engineering has the same opportunity.** No matter how many ransomware
families, RMM tools, or clipboard-attack variants emerge, every attacker must traverse
certain chokepoints — conditions that *must* be met for the technique to work. Detect
the chokepoint, and you detect all current and future variations that require it.

---

## Why Chokepoints?

| Traditional Detection | Chokepoint Detection |
|----------------------|---------------------|
| Detects a specific tool or hash | Detects the requirement the tool must satisfy |
| Breaks when the tool is renamed or replaced | Survives tool rotation, obfuscation, and variation |
| Narrow coverage (one threat family) | Broad coverage (all families sharing the chokepoint) |
| Requires constant signature updates | Durable — new tools hit the same chokepoints |
| High long-term maintenance cost | Low long-term maintenance cost |

**This isn't theory.** Kaspersky's analysis of eight major ransomware groups — Conti, Pysa,
Clop, Hive, LockBit 2.0, RagnarLocker, BlackByte, and BlackCat — found that all eight share
the same core kill chain. External Remote Services, Command & Scripting Interpreter, WMI,
and LSASS credential dumping appear across every single group, regardless of variant,
affiliate, or toolset. Shadow copy deletion and service stopping appear in 7–8 of 8. The
tools rotate; the requirements do not.

**Time = Money.** Dwell time has compressed from weeks to hours as Initial Access
Brokers (IABs) sell pre-authenticated environments to ransomware operators. There's no
time to chase every new tool signature. Chokepoints let you strangle threats at the
conditions they *cannot avoid*.

---

## The Framework

Matt Graeber's research framework describes a three-step process for building durable
detection: **(1) define and scope the technique** — what is the invariant core at a
technical level? **(2) identify variations** — what inputs can an attacker control to evade
naive detections? **(3) validate coverage** — does your detection fire on the invariant
regardless of the variation chosen?

Every chokepoint in this repository is built around those three questions:

```
┌─────────────────┬──────────────────────┬──────────────────────────────┐
│      Scope      │      Variations      │        Prerequisites         │
├─────────────────┼──────────────────────┼──────────────────────────────┤
│ Which tactic(s) │ What tools/methods   │ What MUST be true for this   │
│ and technique   │ exploit this         │ to succeed — regardless of   │
│ does this cover?│ chokepoint today?    │ tool choice?                 │
└─────────────────┴──────────────────────┴──────────────────────────────┘
```

The **prerequisites** are the chokepoint. The scope keeps the work bounded. The variations
column is what you use to validate that your detection survives tool rotation. As Jeffrey Snover
put it: *"to ship is to choose"* — a chokepoint with solid coverage of the invariant beats
a perfect detection that never ships.

---

## Detection Maturity Model

Chokepoint detections are built iteratively at three levels:

| Level | Goal | False Positive Rate | Use Case |
|-------|------|-------------------|----------|
| **Research** | Visibility, baseline understanding | High | Threat research, log source validation |
| **Hunt** | Refined coverage, noise reduction | Medium | Proactive hunting, campaign detection |
| **Analyst** | Production alerting, low FP | Low | SOC alerting, automated IR response |

Start broad. The research rule tells you what's in your environment. The hunt rule
tells you what's interesting. The analyst rule tells your SOC what to respond to.

---

## Why Now?

The RaaS ecosystem has changed the economics of detection:

```
Time to Ransom (TTR) Compression:
  2020: ~21 days average
  2022: ~7 days average
  2024: ~2 days average
  2025: <24 hours median     ← Mandiant M-Trends 2025
```

**Why so fast?** Initial Access Brokers (IABs). Infostealers harvest credentials and
session tokens at scale. IABs sell pre-mapped enterprise environments to ransomware
operators — complete with domain admin creds, VPN access, and network maps. Ransomware
groups skip the initial access and reconnaissance phases entirely.

At the same time, new ransomware families now appear at a rate of at least one per month.
Each new family is a new tool built on the same underlying kill chain. The Kaspersky 2022
report documented this directly: *"the core techniques remain the same throughout the
cyber kill chain. The attack patterns thus revealed are not accidental, because this class
of attack requires the hackers to go through certain stages."* Requires — that is the word
that matters. You cannot encrypt a domain without credential access. You cannot move
laterally without execution. You cannot avoid service manipulation before encryption.

Detection now requires fewer chances. Chokepoints are how you maximize each one.

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
├── chokepoints/                    # Canonical YAML entries (one file per chokepoint)
│   ├── initial-access/
│   │   ├── clickfix-techniques.yml
│   │   └── renamed-rmm-tools.yml
│   ├── lateral-movement/
│   │   └── remote-execution-tools.yml
│   ├── defense-evasion/
│   │   ├── ransomware-service-manipulation.yml
│   │   └── edr-bypass-techniques.yml
│   ├── credential-access/
│   │   └── browser-credential-theft.yml
│   └── persistence/
│       └── web-shells.yml
├── sigma-rules/                    # Detection rules at 3 maturity levels
│   ├── clickfix/
│   │   ├── research.yml
│   │   ├── hunt.yml
│   │   └── analyst.yml
│   ├── renamed-rmm/
│   ├── remote-execution/
│   ├── ransomware-service/
│   ├── browser-credential-theft/
│   ├── edr-bypass/
│   └── web-shells/
├── iok-rules/                      # Indicator of Knowledge rules for lure/phishing page detection
│   └── clickfix/
│       └── clickfix-lure.yml
├── emulation/                      # PowerShell scripts to validate detections against each chokepoint
│   ├── clickfix-techniques/
│   ├── renamed-rmm-tools/
│   ├── remote-execution-tools/
│   ├── ransomware-service-manipulation/
│   ├── browser-credential-theft/
│   ├── edr-bypass-techniques/
│   └── web-shells/
├── attack-chains/                  # Full kill chain documentation
│   ├── ransomware.md
│   └── infostealers.md
├── intel/                          # Free intelligence resources
│   └── clickgrab.md
├── trends/                         # Threat trend analyses and chokepoint shifts
│   ├── index.md                    # Trends landing page
│   ├── clickgrab.md                # Live ClickFix delivery chain analysis (20K+ sites)
│   ├── 2025-q1.md
│   └── chokepoint-shifts.md
├── templates/                      # Templates for contributors
│   ├── chokepoint-template.yml     # Canonical YAML template
│   ├── chokepoint-template.md      # Human-readable template
│   ├── quick-add.md                # Fast template for adding new variants
│   ├── evolution-tracker.md        # Template for tracking evolution over time
│   └── EXAMPLE-WORKFLOW.md        # Complete example: adding Impacket RDP shadowing
└── schema/
    └── chokepoint-schema.yml       # Field definitions and valid values
```

---

## How to Use This Repository

### For Threat Hunters
1. Browse [chokepoints/](chokepoints/) by tactic
2. Grab the sigma rule at your target maturity level from [sigma-rules/](sigma-rules/)
3. Check [intel/clickgrab.md](intel/clickgrab.md) for free ClickFix payload IOCs
4. Review [trends/](trends/) for live data analysis and current threat landscape

### For Detection Engineers
1. Use the Research rule to baseline behavior in your environment
2. Tune the Hunt rule against your baseline to reduce false positives
3. Deploy the Analyst rule to production once false positive rate is acceptable
4. Validate rules with the PowerShell emulation scripts in [emulation/](emulation/)
5. Log updates to your sigma rules in `CHANGELOG.md`

### For Phishing/Lure Detection
1. Check [iok-rules/](iok-rules/) for Indicator of Knowledge rules targeting lure page behaviors
2. IOK rules detect the invariant page-side behaviors (e.g. clipboard seeding + execution instruction) regardless of visual design or obfuscation

### For Tracking Threat Evolution
1. When a new tool variant emerges: use [templates/quick-add.md](templates/quick-add.md)
2. When a new technique emerges: use [templates/chokepoint-template.yml](templates/chokepoint-template.yml)
3. Document evolution over time with [templates/evolution-tracker.md](templates/evolution-tracker.md)
4. For a complete example, see [templates/EXAMPLE-WORKFLOW.md](templates/EXAMPLE-WORKFLOW.md)

---

## How to Contribute

This is a community resource for detection engineers, threat hunters, and incident
responders. Contributions should focus on **chokepoints** — the invariant requirements
attackers cannot bypass — not specific IOCs or tool signatures.

**Good contributions:**
- New chokepoint entries with all three detection maturity levels
- New variations on existing chokepoints (with evolution timeline entries)
- Improved sigma rules with lower false positive rates
- Free intel resources tied to specific chokepoints

**Not a fit:**
- Raw IOC dumps (IPs, domains, hashes) without detection logic
- Tool-specific signatures without chokepoint framing
- Vendor-specific content without broader applicability

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full process, schema requirements,
and PR checklist.

---

## Resources

| Resource | Description |
|----------|-------------|
| [MITRE ATT&CK](https://attack.mitre.org/) | Technique taxonomy used for all chokepoint mappings |
| [Sigma Specification](https://github.com/SigmaHQ/sigma-specification) | Rule format used across all detection levels |
| [ClickGrab (ClickFix intel)](https://mhaggis.github.io/ClickGrab/) | Live crawl data feeding the ClickFix trends analysis |
| [Mandiant M-Trends](https://www.mandiant.com/m-trends) | Source for TTR compression statistics in this README |
| [Kaspersky — Common TTPs of Modern Ransomware](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2022/06/23093553/Common-TTPs-of-the-modern-ransomware_low-res.pdf) | Cross-group TTP analysis across 8 ransomware families — empirical foundation for the chokepoint approach |
| [Red Canary — The Why, What, and How of Threat Research](https://redcanary.com/blog/threat-detection/threat-research-questions/) | Research methodology behind the Scope/Variations/Prerequisites framework |
| [Huntress ClickFix Analysis](https://huntress.com/blog/dont-sweat-clickfix-techniques) | In-the-wild ClickFix variant breakdown |

---

## Framework Reference

For the full chokepoint identification methodology — how to decide what is and isn't
a chokepoint, when to create a new entry vs. add a variation, and how to build
detection iterations — see [FRAMEWORK.md](FRAMEWORK.md).

---

> *"Detection is a game of economics. Make it expensive for attackers to avoid your detections."*
