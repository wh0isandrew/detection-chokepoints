# Learned — Detection Chokepoints

Hard-won lessons from building and maintaining this project. Check here before
making changes to avoid repeating past mistakes.

---

## Sigma Rules

- `|contains|any` is NOT valid Sigma syntax. Lists under `|contains` are already implicitly OR'd.
- `|re:` regex modifier is NOT standard Sigma. Use `|contains` with SIEM-side guidance for regex patterns.
- `|not|contains` and `|not|endswith` are NOT valid. Move negations to a `filter_` block in the condition.
- Every rule must have a `filter_legit_software` block, even if empty (placeholder for env tuning).
- UUIDs must be valid hex only (0-9, a-f). Third group must start with `4` (UUIDv4).
- Keep descriptions to 1-3 sentences. The surrounding chokepoint page provides context.
- Sigma rule titles must match what the rule actually detects. Don't claim correlation that only happens at SIEM layer.

## Sysmon Event IDs

- EID 10 (ProcessAccess) — TargetImage is always a **process**, never a file path. Don't use it for file access detection.
- EID 11 (FileCreate) — Use this for detecting file access/copy operations (e.g., stealer copying Login Data).
- EID 6 (DriverLoaded) — Only fires if Sysmon is installed and configured. Not a universal invariant.
- EID 7036 (Service State Change) — Logs service start/stop, NOT service deletion. Deletion is registry-based.

## Chokepoint Invariants

- Invariants must hold across ALL listed variants. If IronNetInjector doesn't write to disk, "must write binary to disk" is not an invariant — broaden to "must introduce runtime."
- EDR bypass spans kernel (BYOVD) AND userland (unhooking, ETW patching, WFP). Stage 2 must cover both paths.
- Web shells include file-based (PHP/ASPX), module-based (IIS DLLs), and injection-based (SSTI). "Must write file" doesn't hold for all three.
- "Logged by Sysmon" is a deployment dependency, not an absolute invariant. Note the caveat.

## MITRE ATT&CK

- T1204.003 is "Malicious Image" (container/VM images), NOT image files. ClickFix should use T1204.004.
- T1218 is system binary proxy execution (mshta, rundll32). BYOSI interpreters are vendor-signed but NOT system binaries — T1218 is a mismap.
- Always cross-check: MitreIds in YAML should match tags in Sigma rules. Mismatches confuse users.

## URLs and Sources

- Sophos migrated from `news.sophos.com` to `www.sophos.com`. Old URLs return 301. Use the new domain.
- CISA advisory URLs return 403 to bots but work in browsers. They're valid — don't replace them.
- Europol URLs go stale. The Operation Magnus site (`operation-magnus.com`) is more reliable than the Europol press release.
- URLScan queries: no wildcards (`*`) or parenthesized OR groups for anonymous users. Use exact matches only.
- mrd0x.com goes down intermittently (ECONNREFUSED). The FileFix article may need a mirror reference.

## Variant Data

- CVE-2023-36204 is a Windows Audio Service vuln, NOT a Zemana driver CVE. Don't attribute it to Terminator.
- POORTRY/STONESTOP FirstSeen is 2022-Q4 (Mandiant), not 2024-Q1. The 2024 date was the EDR wiper evolution.
- Hell's Gate was published June 2020, not 2018.
- AnyDesk breach disclosure was February 2024 (public), not January. Breach itself was late Dec 2023 / early Jan 2024.
- Valid Status values: Active, Emerging, Declining, Legacy. Not "Inactive", "Defunct", "Archived", "Severely Disrupted".
- CrackMapExec binary was `crackmapexec` or `cme`, NOT `nxc`. NetExec uses `nxc`.

## Site / Jekyll

- `_data/chokepoints.yml`, `search-index.json`, and `_chokepoints/` are gitignored. CI regenerates them.
- Always run `py scripts/aggregate.py` after editing YAML or Sigma files.
- The aggregate script key: `_sigma_hunt-network` — Liquid can't use hyphens in property access. Use `cp["_sigma_hunt-network"]` bracket notation.
- Liquid `{% elsif %}` requires a preceding `{% if %}`. Removing an `if` block but leaving its `elsif` causes a syntax error.
- GitHub Pages CI only triggers on pushes to `main`. Branch deployments don't update the live site.

## OSINT Pivots

- Hudson Rock and HIBP are not useful for finding samples in the wild. Remove from OSINT sections.
- URLScan filename queries with exact names (e.g., `filename:MicrosoftTeams.msi`) work for anonymous users.
- Renamed RMM URLScan queries should target masquerade filenames, not legitimate tool names.
- Include notes telling users they can swap query terms for seasonal campaigns.
