# Challenges — Detection Chokepoints

Known blockers, incomplete work, and open questions.

---

## Unfinished Content

### Missing source: BlackSanta EDR Killer
- Only variant across all 8 pages without a SourceURL (75th of 75)
- Notes say "Likely uses BYOVD or kernel callback removal" — speculative
- No public technical analysis found as of April 2026
- Consider changing Status from Active to Emerging until confirmed

### Payloads not traceable to source articles
- Some variant payloads are representative examples, not directly extracted from cited sources
- AuKill "startkey" CLI argument — not mentioned in the Sophos article
- POORTRY cert names ("bopsoft", "Evangel Technology", "FEI XIAO") — not in the Burnt Cigar 2 article
- Huntress blog does NOT name JackFix/GlitchFix/ConsentFix — those names may originate elsewhere

### FileFix source URL
- mrd0x.com returns ECONNREFUSED intermittently
- The FileFix article may need a mirror or archive.org reference as backup

## Structural Gaps

### Ransomware analyst Sigma rule is too narrow
- Only detects `sc.exe` + `SophosFileScanner` — single service, single tool
- Should detect bulk service stop/delete across multiple service families
- YAML description says "5+ services in 10 minutes" but rule doesn't implement this

### Remote Execution analyst Sigma rule oversells scope
- Title says "Network Logon + IPC$ + Suspicious Service" correlation
- Rule only detects EID 7045 (service install) — no logon or IPC$ correlation
- Comment acknowledges "IPC$ correlation must be done at SIEM/pipeline level"

### Stage-to-Sigma mapping inconsistencies
- Some pages have DetectionTier labels that don't match the SigmaRef pointed to
- The stage-grouped template logic uses hardcoded stage index matching (forloop.parentloop.index == 2)
- This breaks for chokepoints with different numbers of stages or different tier assignments

### Web Shells hunt rule title mismatch
- Title was fixed but description still mentions "script file creation in web-accessible directories"
- The rule has no file creation detection (EID 11) — only process spawning

## Design Decisions to Revisit

### Convergence heatmap data is hardcoded HTML
- The ransomware heatmap on the attack chains page is pure HTML table
- Should be data-driven from YAML so actors/techniques can be updated without editing HTML
- Same pattern needed for future infostealer and AiTM convergence maps

### IOK rules not integrated into variant cards
- The ClickFix task plan includes IOK detection snippets per variant
- Template supports it (IokRule field) but no variant-level IOK content exists yet
- Phase 4 of the original implementation plan — lowest priority

### Cross-page detection gaps
- EDR Bypass: no detection for SafeMode boot bypass in Sigma rules (bcdedit safeboot)
- Browser Theft: analyst rule mixes multiple logsource categories (file_event + process_creation)
- BYOSI: hunt/analyst rules missing coverage for Tcl, R, Dart, Nim, Crystal interpreters
