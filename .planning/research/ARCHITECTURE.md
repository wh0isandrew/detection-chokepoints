# Architecture Research

## Component Map

The OSINT collection pipeline is a separate offline process that runs before the Jekyll build and deposits static data files Jekyll can render. There are two distinct runtime contexts: the **collection context** (runs locally or in a scheduled CI job with API keys) and the **build context** (runs in GitHub Actions, no API keys, reads only committed files).

### Existing Components (brownfield)

```
COLLECTION CONTEXT (local / scheduled CI)
────────────────────────────────────────────────────────────────────────
[Source APIs]
  MalwareBazaar · ThreatFox · URLhaus
  Shodan · URLScan · Validin · VirusTotal · IPinfo
  ClickGrab GitHub repo (LFS-backed nightly reports)

[Stage 1 — Collection]
  scripts/collect_ioc_feeds.py      → cache/ioc_records.json
  scripts/collect_infra_hunts.py    → cache/infra_records.json
  scripts/ingest_clickgrab.py       → cache/clickgrab_raw.json

[Stage 2 — Enrichment]
  scripts/enrich_infra.py           → cache/enriched_infra.json
                                       cache/dns_cache.json
                                       cache/vt_cache.json
  (reads clickgrab_raw.json, enriches hostnames via IPinfo + VT)

[Stage 3 — Merge / Normalize]
  (MISSING — broken gap between enriched_infra.json and unified record schema)
  scripts/update_masq_infra.py      (monolithic legacy script; overlaps Stages 1–3;
                                     currently the source of _data/masq_infra.json
                                     but uses a different schema than build_data.py expects)

[Stage 4 — AI Triage]
  scripts/claude_triage.py          reads cache/enriched_records.json
                                    writes cache/triaged_records.json

[Stage 5 — Campaign Clustering]
  scripts/cluster_campaigns.py      reads cache/triaged_records.json
                                    writes cache/campaigns.json
                                           cache/low_confidence_campaigns.json

[Stage 6 — Data Assembly]
  scripts/build_data.py             reads cache/triaged_records.json
                                           cache/campaigns.json
                                           _data/masq_infra_history.json
                                    writes _data/masq_infra.json
                                           _data/masq_infra_history.json (append)

BUILD CONTEXT (GitHub Actions — no API keys)
────────────────────────────────────────────────────────────────────────
[Pre-build]
  scripts/aggregate.py              reads chokepoints/**/*.yml
                                           sigma-rules/**/*.yml
                                    writes _data/chokepoints.yml
                                           _chokepoints/<slug>.md
                                           assets/js/search-index.json

[Jekyll build]
  jekyll build                      reads _data/masq_infra.json  ← committed static file
                                          _data/chokepoints.yml
                                    writes _site/

[Deploy]
  GitHub Pages                      serves _site/
```

### The Broken Correlation Gap

The current `_data/masq_infra.json` (written by the legacy `update_masq_infra.py`) uses a different top-level shape than what `build_data.py` now produces. The legacy file has `stats`, `hosting_providers`, and flat arrays. The new schema (documented in `_data/masq_infra_schema.md`) has `meta`, `records`, `campaigns`, `payload_summary`, `infrastructure_summary`, and `weekly_summary`. The Liquid templates in `trends/masq-infra.md` are written for the new schema. The trends page renders empty sections because of this mismatch.

**The specific gap:** `enrich_infra.py` writes `cache/enriched_infra.json`, but `claude_triage.py` reads `cache/enriched_records.json`. These are not the same file. A normalization step that merges `ioc_records.json` + `infra_records.json` + `enriched_infra.json` into `cache/enriched_records.json` using the unified record schema is missing. This is the one missing script that would wire the full pipeline together.

---

## Data Flow

### Unified Record Schema (the correlation key)

Every record is normalized to one schema via `make_record()` in `collect_ioc_feeds.py`. The identity key is `sha256(domain + payload_sha256)`. Cross-source correlation happens at the deduplication step using this ID: if MalwareBazaar and ThreatFox both surface the same domain+payload, the highest-confidence record wins.

The correlation model is domain-centric, not URL-centric. Different sources report different URL paths on the same domain. The domain is the stable infrastructure unit.

```
Source signal types and their correlation potential:

MalwareBazaar     sha256 (confirmed) + delivery URL → domain
ThreatFox         family + domain or URL → domain
URLhaus           URL → domain, optional sha256 from url_info
Shodan            IP + favicon hash → domain (if hostname in response)
URLScan           domain + UUID + optional sha256 from scan results
Validin pDNS      domain → historical IPs; IP → co-hosted domains
VirusTotal        domain → detection count (enrichment only, not source)

Hard correlation signals (used for campaign clustering):
  shared_payload        same sha256 across 2+ domains
  shared_favicon        same favicon mmh3 hash across 2+ domains
  shared_ip             same IP within 30-day window
  shared_cert_pattern   self-signed cert on disposable TLD
```

### Data Flow Diagram

```
MalwareBazaar
ThreatFox         ──→  collect_ioc_feeds.py    ──→  cache/ioc_records.json    ──┐
URLhaus                                                                          │
                                                                                 ▼
Shodan                                                              [merge.py — MISSING]
URLScan           ──→  collect_infra_hunts.py  ──→  cache/infra_records.json  ──→  cache/enriched_records.json
Validin                                                                          ▲
                                                                                 │
ClickGrab GitHub  ──→  ingest_clickgrab.py  ──→  cache/clickgrab_raw.json       │
                              │                                                  │
                              └──→  enrich_infra.py  ──→  cache/enriched_infra.json ──┘

         cache/enriched_records.json
                  │
                  ▼
         claude_triage.py  ──→  cache/triaged_records.json
                  │
                  ▼
         cluster_campaigns.py  ──→  cache/campaigns.json
                  │
                  ▼
         build_data.py  ──→  _data/masq_infra.json  (committed to repo)
                              _data/masq_infra_history.json (committed to repo)
                  │
                  ▼  (git commit + push)
         GitHub Actions: aggregate.py + jekyll build
                  │
                  ▼
               _site/  ──→  GitHub Pages
```

### Incremental Update Strategy (no database)

The pipeline uses layered file caches under `cache/` (gitignored) to avoid re-fetching:

- `cache/dns_cache.json` — hostname-to-IP resolutions. Append-only.
- `cache/vt_cache.json` — domain/IP VT responses. Stale-but-acceptable for weekly cadence.
- `cache/pipeline_run.json` — run log with per-stage timestamps. Can skip stages that ran successfully in the last N hours.

Historical persistence is handled by `_data/masq_infra_history.json`, committed to the repo. Each pipeline run appends a weekly summary entry keyed by ISO week date. The `records` array in `masq_infra.json` is a point-in-time snapshot of the most recent 30-day window — overwritten each run, not appended.

---

## Build Order

### Ordered Stage Dependencies

```
Stage 1a  collect_ioc_feeds.py       no local deps; requires MB/TF/URLhaus API keys
Stage 1b  collect_infra_hunts.py     reads ioc_records.json for Validin seed; run after 1a
Stage 1c  ingest_clickgrab.py        no local deps; requires GitHub token; can run in parallel

Stage 2   enrich_infra.py            reads clickgrab_raw.json; requires IPinfo + VT keys

Stage 2b  [merge_records.py — NEW]   reads ioc_records.json + infra_records.json +
                                     enriched_infra.json
                                     writes cache/enriched_records.json
                                     no API keys required

Stage 3   claude_triage.py           reads enriched_records.json; requires Anthropic API key

Stage 4   cluster_campaigns.py       reads triaged_records.json; optional Anthropic key

Stage 5   build_data.py              reads triaged_records.json + campaigns.json +
                                     masq_infra_history.json; no API keys required

Stage 6   append_history.py          appends weekly snapshot to masq_infra_history.json

Stage 7   git commit + push          _data/masq_infra.json + _data/masq_infra_history.json

Stage 8   GitHub Actions trigger     aggregate.py → jekyll build → Pages deploy
```

### Correct Execution Sequence

```bash
python scripts/collect_ioc_feeds.py
python scripts/collect_infra_hunts.py        # reads ioc_records.json
python scripts/ingest_clickgrab.py           # independent; can overlap above
python scripts/enrich_infra.py               # reads clickgrab_raw.json
python scripts/merge_records.py              # NEW: writes enriched_records.json
python scripts/claude_triage.py
python scripts/cluster_campaigns.py
python scripts/build_data.py
python scripts/append_history.py             # appends to masq_infra_history.json
git add _data/masq_infra.json _data/masq_infra_history.json
git commit -m "data: weekly masq-infra pipeline run YYYY-WW"
git push
```

---

## Key Findings

**Finding 1: Schema mismatch is the immediate blocker.** The committed `_data/masq_infra.json` uses the old schema from `update_masq_infra.py`. The Liquid templates reference the new schema (`meta.record_count`, `records`, `campaigns`, `payload_summary`, `infrastructure_summary`). Until `build_data.py` runs and its output is committed, the trends page will always show empty sections.

**Finding 2: One missing script wires the full pipeline.** `claude_triage.py` reads `cache/enriched_records.json`. Nothing writes this file. A `merge_records.py` script that merges `ioc_records.json` + `infra_records.json` + `enriched_infra.json` into a unified `enriched_records.json` is the only structural gap.

**Finding 3: Domain-centric correlation key is the right model.** The `sha256(domain + payload_sha256)` identity key is correct. Field-level merging (best non-null value per field across source records for the same domain) would enrich records further without a separate pass.

**Finding 4: `_data/masq_infra.json` is the sole contract boundary.** Everything in `cache/` is ephemeral and gitignored. The pipeline can be redesigned as long as it produces valid output matching `_data/masq_infra_schema.md`.

**Finding 5: `update_masq_infra.py` should be retired** once the new pipeline produces verified output. Do not delete until `build_data.py` has run successfully and validated.

**Finding 6: History file must not be overwritten.** `_data/masq_infra_history.json` is read by both `build_data.py` and Jekyll templates. `append_history.py` must run after `build_data.py` and before the git commit.

**Finding 7: No API keys in the public CI workflow — must stay that way.** The `pages.yml` workflow runs only `aggregate.py` and `jekyll build`. All collection happens out-of-band via a private workflow or local run.
