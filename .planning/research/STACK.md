# Stack Research

## Context

This is a brownfield project. The existing stack (Jekyll + Python pre-build pipeline) is not changing. These recommendations cover only the three new workstreams:

1. OSINT data correlation pipeline (fix + extend)
2. Scheduled collection producing static JSON for Jekyll
3. Testability and reproducibility of pipeline results

---

## Recommended Stack

### Data Correlation / Normalization

| Component | Choice | Version | Rationale |
|-----------|--------|---------|-----------|
| Schema validation | `pydantic` v2 | `>=2.7` | Validates records at ingestion boundary. Each source maps into a shared `MasqRecord` model. Field coercion, None-safety, and schema enforcement happen once, centrally, before any joining logic runs. Replaces the scattered `or {}`, `or []`, `isinstance` guards duplicated across `collect_ioc_feeds.py` and `collect_infra_hunts.py`. |
| Data joining / merging | `pandas` | `>=2.2` (already in requirements) | `DataFrame.merge()` on `domain` key handles cross-source correlation. `json_normalize()` is useful for flattening nested URLScan result structures before mapping to schema. Already installed. |
| Domain extraction | `tldextract` | `>=5.0` (already in requirements) | Already in use and correct. PSL-aware registered domain extraction. No change. |

**Why Pydantic over plain dataclasses:** The pipeline's bug surface is `KeyError`, `AttributeError`, and silent `None` propagation when API response shapes change. Pydantic v2 catches this at parse time with a clear error, not a silent wrong confidence score three records later.

**Why not marshmallow:** Extra dependency, no benefit over Pydantic v2 here. Pydantic is faster (Rust core), better IDE support, community standard.

---

### HTTP Clients (existing choices are correct, no changes)

| Component | Choice | Version | Rationale |
|-----------|--------|---------|-----------|
| Sync HTTP (feed collectors) | `requests` | `>=2.31` | URLhaus, MalwareBazaar, ThreatFox are sequential POST/GET. `requests` is appropriate. No change. |
| Async HTTP (enrichment) | `httpx` | `>=0.27` | `enrich_infra.py` already uses `httpx.AsyncClient` correctly for concurrent IPinfo/VT enrichment. No change. |

---

### Scheduling (static JSON production for Jekyll)

| Component | Choice | Version | Rationale |
|-----------|--------|---------|-----------|
| Scheduler | GitHub Actions `on: schedule` cron | N/A | Already used for Pages deploy. Add a separate `update-intel.yml` with `cron: '0 6 * * *'`. Runs collection scripts, writes `_data/masq_infra.json`, commits, triggers Pages build. Zero new infrastructure. |
| Auto-commit action | `stefanzweifel/git-auto-commit-action` | `@v5` | Standard action for committing changed files from a scheduled workflow. Manual `git config/add/push` steps are fragile. |
| Secrets | GitHub repository secrets | N/A | `MB_API_KEY`, `URLSCAN_API_KEY`, etc. as `${{ secrets.NAME }}` env vars. Already correct approach for GitHub Pages. |

**Why not Celery/APScheduler/VPS cron:** All require a running process or broker. Incompatible with zero-infrastructure GitHub Pages constraint.

---

### Testing / Reproducibility

| Component | Choice | Version | Rationale |
|-----------|--------|---------|-----------|
| Test framework | `pytest` | `>=8.2` | Standard. Fixtures handle both unit and integration scenarios cleanly. |
| HTTP mocking (requests) | `responses` (getsentry) | `>=0.25` | Intercepts `requests` transport layer. `@responses.activate` plus `responses.add(method, url, json={...})` is the lowest-friction way to replay fixture API responses for the feed collectors. |
| HTTP mocking (httpx) | `respx` | `>=0.21` | Intercepts `httpx` calls including async clients. Required for testing `enrich_infra.py`. Works with `pytest-asyncio`. |
| Async test support | `pytest-asyncio` | `>=0.23` | Required to `await` coroutines in pytest. |
| Fixture data strategy | JSON files in `tests/fixtures/` | N/A | Capture one real API response per source per scenario, store as `.json` files, load in pytest fixtures. Tests run with no network access. |

**Reproducibility approach:** The pipeline's correlation logic has no tests. The fix path is:
1. Extract each collector into a pure function: `collect_urlhaus(api_key) -> list[MasqRecord]`
2. Mock the HTTP layer in tests using `responses` / `respx`
3. Test deduplication logic separately with controlled inputs
4. Test the correlation join (`ioc_records + infra_records -> masq_infra.json`) end-to-end with fixture data

---

## What NOT To Use

| What | Why Not |
|------|---------|
| `marshmallow` | Redundant with Pydantic v2. Slower, more boilerplate. |
| `celery` / `rq` | Requires a broker and persistent worker. Incompatible with GitHub Pages. |
| `APScheduler` | Requires a running process. GitHub Actions cron is the right primitive. |
| `great_expectations` | Overengineering for a pipeline producing one JSON file per day. |
| `polars` | No reason to add a second dataframe library. Pandas (already installed) is sufficient. |
| `unittest.mock.patch` for HTTP | Brittle. Transport-layer mocking with `responses`/`respx` is more durable. |
| Streamlit in CI or site build | Validation harness only per PROJECT.md. Not part of the site. |

---

## Key Findings

**The existing tooling is mostly right.** `requests`, `httpx`, `tldextract`, `pandas`, and `python-dotenv` are correct choices already in `requirements.txt`. The correlation bugs are logic bugs and schema handling issues, not library problems.

**The real gap is schema enforcement at ingestion boundaries.** Both collector scripts duplicate `make_record`, `score_record`, `classify_family`, and `extract_domain`. When an API returns an unexpected shape, silent `None` values propagate into confidence scores without raising an error. Pydantic v2 with a single shared `MasqRecord` model fixes this.

**Scheduling is trivially solved with GitHub Actions.** One new workflow YAML file, no new runtime dependencies.

**Testability requires extracting pure functions and mocking at the transport layer.** Current scripts mix collection, normalization, and file I/O in `main()`. Splitting into pure functions makes them unit-testable without external API calls.

**New dependencies to add to `requirements.txt`:** `pydantic>=2.7`, `responses>=0.25`, `respx>=0.21`, `pytest>=8.2`, `pytest-asyncio>=0.23`.

---

## Confidence Levels

| Area | Level | Reason |
|------|-------|--------|
| Existing stack (keep as-is) | HIGH | Read from actual code |
| Pydantic v2 for schema normalization | HIGH | Official docs current; community standard |
| `responses` / `respx` for test mocking | HIGH | Official docs verified; actively maintained |
| GitHub Actions schedule + auto-commit | HIGH | Official GitHub docs; widely used pattern |
| `stefanzweifel/git-auto-commit-action` | MEDIUM | Community action, widely adopted but not GitHub-official |
