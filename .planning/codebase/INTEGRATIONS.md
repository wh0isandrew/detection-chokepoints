# Integrations — detection-chokepoints

## GitHub Pages

- **What:** Hosting for the static site
- **How:** `.github/workflows/pages.yml` runs pre-build + Jekyll and deploys `_site/` to GitHub Pages on push to `main`
- **URL:** `https://iimp0ster.github.io/detection-chokepoints`
- **Config:** `_config.yml` sets `baseurl: "/detection-chokepoints"` and `url: "https://iimp0ster.github.io"`

## MITRE ATT&CK

- **What:** Technique and tactic taxonomy — all chokepoint IDs, names, and mappings follow ATT&CK
- **How:** Referenced in `MitreIds[]`, `Tactics[]`, Sigma `tags: attack.tXXXX`
- **Not automated:** No API integration; IDs are maintained manually in YAML

## Sigma (SigmaHQ)

- **What:** Detection rule format for all rules in `sigma-rules/`
- **How:** Rules follow the Sigma specification; rendered as code blocks in the chokepoint layout
- **Tooling:** `sigma-cli` used manually for validation (not in CI)
- **References in YAML:** `SigmaRule:` paths point to files in `sigma-rules/`

## IOK / phish.report

- **What:** Indicator of Knowledge rule format for phishing lure detection
- **How:** Rules in `iok-rules/` use the IOK/Sigma hybrid format targeting `html`, `js`, `dom`, `requests`, `headers` matchers
- **Runtime:** Rules intended for use with phish.report or a compatible web proxy
- **Reference rule:** `iok-rules/clickfix/clickfix-lure.yml`

## Fuse.js

- **What:** Client-side fuzzy search
- **How:** `scripts/aggregate.py` writes `assets/js/search-index.json`; `assets/js/search.js` loads it and initializes Fuse
- **Bundled:** `assets/js/fuse.min.js` committed directly (no npm at runtime)

## Threat Intel Scripts (external services)

These scripts in `scripts/` connect to external services but are run manually, not part of the site build:

| Script | External Service |
|--------|-----------------|
| `collect_ioc_feeds.py` | IOC feed sources (configured in `sources.yml`) |
| `collect_infra_hunts.py` | Infrastructure hunt platforms |
| `enrich_infra.py` | Infrastructure enrichment APIs |
| `ha_lookup.py` | HybridAnalysis / any.run |
| `sandbox_submit.py` | Sandbox platform |
| `fetch_payload_chains.py` | URLScan, VirusTotal, etc. |
| `claude_triage.py` | Claude API (Anthropic) |
| `update_masq_infra.py` | Masquerading infra tracking |

## OSINT Platforms Referenced in Chokepoints

YAML entries include `OsintSources[]` with queries for:
- **URLScan** — page/domain searches
- **Shodan** — infrastructure fingerprinting
- **Censys** — certificate/banner searches
- **VirusTotal** — file/URL reputation
- **FOFA**, **Hunt.io**, **Validin** — specialized threat intel
