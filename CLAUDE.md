# CLAUDE.md — Detection Chokepoints

This file provides context for AI-assisted work in this repository.

---

## Project Purpose

Detection Chokepoints is a detection engineering knowledge base built around the concept of **invariant prerequisites** — the conditions every attacker must satisfy for a technique to work, regardless of tool rotation, obfuscation, or variant. The goal is durable detection coverage that survives adversary evolution.

All detections are anchored to a chokepoint entry that defines the invariant, documents known variations, and maps to three detection maturity levels.

---

## Repository Structure

```
chokepoints/          # Canonical YAML entries — one file per chokepoint, organized by tactic
sigma-rules/          # Sigma rules at three maturity levels (research / hunt / analyst)
iok-rules/            # Indicator of Knowledge rules for lure/phishing page detection
emulation/            # PowerShell scripts for validating detections in a lab environment
attack-chains/        # Full kill chain documentation (ransomware, infostealers)
intel/                # Free intelligence resources tied to specific chokepoints
trends/               # Threat trend analyses and chokepoint evolution tracking
templates/            # Templates for contributors (chokepoint YAML, quick-add, evolution tracker)
schema/               # Field definitions and valid values for chokepoint entries
scripts/              # Python/shell scripts for data ingestion, enrichment, and automation
```

---

## Core Conventions

### Chokepoint YAML (`chokepoints/<tactic>/<name>.yml`)

The canonical source of truth. Key fields:

- `Name`, `Id` (UUIDv4), `MitreIds`, `Tactics`, `Techniques`
- `DetectionPriority`: CRITICAL | HIGH | MEDIUM | LOW
- `ThreatPrevalence`: VERY HIGH | HIGH | MEDIUM | LOW | EMERGING
- `DetectionDifficulty`: LOW | MEDIUM | HIGH
- `Variations`: list of named tool/technique variants with `FirstSeen`, `Status`, `VariantId`
- `Chokepoints`: per-stage detection chain — `Stage`, `Invariant`, `WhyCantBypass`, `LogSources`, `DetectionTier`, `SigmaRef`
- `EvolutionTimeline`: dated events tracking how the technique has changed
- `Detections`: detection logic summary at each maturity level with `SigmaRule` path references
- `EarlyDetections`: pre-execution detection layers (ETW, IOK)
- `Prerequisites`, `KnownBypasses`, `RelatedChokepoints`
- `OsintSources`: platform-specific queries for URLScan, Shodan, VirusTotal, etc.
- `RawLogs`: sample log entries for each Sysmon event ID covered
- `EmulationScript`: path and safety notes for the paired emulation script
- `TheConstant`: one-line summary of the invariant (the chokepoint in plain language)

Full schema: `schema/chokepoint-schema.yml`

### Sigma Rules (`sigma-rules/<chokepoint>/<level>.yml`)

Three files per chokepoint — `research.yml`, `hunt.yml`, `analyst.yml` — with increasing precision.

| Level | Purpose | FP Rate |
|-------|---------|---------|
| research | Baseline visibility, understand behavior | High |
| hunt | Refined coverage, noise reduced | Medium |
| analyst | Production SOC alerting | Low |

Required Sigma fields: `title`, `id` (UUIDv4), `status`, `description`, `references`, `author`, `date`, `tags`, `logsource`, `detection`, `falsepositives`, `level`

Tags must include relevant `attack.tXXXX` MITRE IDs and `detection.maturity.<level>`.

### IOK Rules (`iok-rules/<chokepoint>/<name>.yml`)

Sigma-based rules for phishing/lure page detection via web proxy or phish.report. Use `html`, `js`, `dom`, `requests`, and `headers` matchers. See `iok-rules/clickfix/clickfix-lure.yml` as the reference example.

### Emulation Scripts (`emulation/<chokepoint>/emulate.ps1`)

PowerShell scripts that simulate the chokepoint behavior in a controlled lab. Always include safety notes — these must only run in an isolated VM. Each script maps to an Atomic Red Team technique ID via `AtomicRef`.

---

## Detection Maturity Model

Start with **research** (broad, noisy) → tune to **hunt** → harden to **analyst** (production alerting).

Do not skip levels. The research rule establishes the behavioral baseline. Without it you cannot tune intelligently.

---

## Author Context

- **Author:** Tyler ([@iimp0ster](https://twitter.com/iimp0ster))
- **Role:** Detection Engineer / Malware Analyst / Threat Researcher
- **Primary detection format:** Sigma
- **Secondary:** YARA (learning)
- **OSINT platforms in use:** URLScan, Shodan, Censys, FOFA, Hunt.io, Validin

---

## AI Assistance Guidelines

When helping with this repo:

1. **Chokepoint entries** — Focus on the invariant (what MUST be true), not the tool. A chokepoint that fires on Mimikatz but not on pypykatz is not a chokepoint.

2. **Sigma rules** — Follow the maturity model. Research rules use broad `CommandLine` contains logic. Analyst rules add parent process constraints, encoding patterns, and filters for known-good software. Always include a `filter_legit_software` condition block even if empty.

3. **MITRE mapping** — Use sub-technique IDs where available (e.g., `T1059.001` not just `T1059`). Cross-check against `schema/chokepoint-schema.yml` for valid tactic names.

4. **Variations vs. new chokepoints** — A new tool that exploits the same invariant is a variation. A fundamentally different prerequisite set is a new chokepoint. When in doubt, add a variation entry before creating a new YAML file.

5. **EvolutionTimeline entries** — Include `DetectionImpact` explicitly. If the existing detection logic still covers the new variant, say so. If a new parent process or log source is required, call it out.

6. **OSINT queries** — Always include a `Notes` field explaining why the query has cross-variant resilience, not just what it matches.

7. **Emulation scripts** — Must include `SafetyNotes`. Outbound connections in emulation scripts should point to benign destinations (e.g., `example.com`).

8. **Keep it durable over precise.** A detection that survives tool rotation at medium confidence is more valuable than a perfect detection that breaks when the attacker renames a binary.

---

## Key Reference Files

| File | Purpose |
|------|---------|
| `schema/chokepoint-schema.yml` | All valid fields and values for chokepoint YAML |
| `FRAMEWORK.md` | Full methodology — when to create a chokepoint vs. add a variation |
| `CONTRIBUTING.md` | PR checklist and contribution standards |
| `templates/chokepoint-template.yml` | Blank YAML template |
| `templates/EXAMPLE-WORKFLOW.md` | End-to-end worked example |
| `chokepoints/initial-access/clickfix-techniques.yml` | Most complete chokepoint entry — use as reference |
| `sigma-rules/clickfix/analyst.yml` | Reference analyst-level Sigma rule |
