# Stack — detection-chokepoints

Jekyll static site with a Python pre-build data layer. Content lives in YAML; a Python script (`scripts/aggregate.py`) reads it and generates the Jekyll data files before build. The site is hosted on GitHub Pages. Client-side search is powered by Fuse.js. No backend at runtime — everything is static HTML.

## Site Framework

- **Jekyll** (Ruby) — static site generator
- **GitHub Pages** — hosting (`.github/workflows/pages.yml`)
- **Liquid** — templating language for `_layouts/` and `_includes/`
- **kramdown** — Markdown processor with GFM input
- **rouge** — syntax highlighting
- **jekyll-seo-tag** — SEO plugin

## Pre-Build Data Layer (Python)

- **Python 3** — `scripts/aggregate.py` is the build entry point
- **PyYAML** — reads `chokepoints/**/*.yml` and sigma rule files
- **json** (stdlib) — writes `assets/js/search-index.json`

## Frontend

- **Fuse.js** — client-side fuzzy search (`assets/js/fuse.min.js`)
- **Vanilla JS** — `assets/js/search.js`, no frontend framework
- **CSS** — custom styles, badge system, dark theme

## Threat Intel Scripts (`scripts/`)

Secondary tooling, not part of the Jekyll build:
- `collect_ioc_feeds.py`, `collect_infra_hunts.py` — IOC/infra data collection
- `enrich_infra.py`, `update_masq_infra.py` — infrastructure enrichment
- `sandbox_submit.py`, `ha_lookup.py`, `fetch_payload_chains.py` — sandbox integration
- `claude_triage.py` — Claude API-based triage
- `ingest_clickgrab.py`, `analyze_clickgrab.py`, `cluster_campaigns.py` — campaign analysis
- `update_ttps.py`, `append_history.py` — TTP tracking
- `sources.yml` — data source configuration

## Content Formats

- **Chokepoint YAML** — `chokepoints/<tactic>/<name>.yml` (canonical entries)
- **Sigma YAML** — `sigma-rules/<chokepoint>/{research,hunt,analyst}.yml`
- **IOK YAML** — `iok-rules/<chokepoint>/<name>.yml` (phishing lure detection)
- **Attack chains** — `attack-chains/*.json`
- **Emulation scripts** — `emulation/<chokepoint>/emulate.ps1` (PowerShell)

## Ruby / Gem Dependencies

- `Gemfile` / `Gemfile.lock` — Jekyll and plugins
- `vendor/` — bundled gems (gitignored but present on build)

## Node

- `package.json` — single dependency: `js-yaml ^4.1.1` (used by scripts, not Jekyll build)
