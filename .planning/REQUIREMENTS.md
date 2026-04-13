# Requirements: Detection Chokepoints v1.0

**Defined:** 2026-04-11
**Core Value:** Chokepoint-focused detections that survive campaigns and tool rotation — the highest-ROI coverage a detection engineer can build.

## v1 Requirements

### Baseline (BSLN)

- [ ] **BSLN-01**: Generated files (`_data/chokepoints.yml`, `_chokepoints/`, `assets/js/search-index.json`) are confirmed gitignored; removed from git tracking if previously committed
- [ ] **BSLN-02**: Liquid positional index bug (`forloop.parentloop.index == 2`) replaced with field-based matching
- [ ] **BSLN-03**: `jekyll build --strict` passes clean with zero warnings

### Writing (WRIT)

- [ ] **WRIT-01**: All em dashes removed from every page (chokepoints, trends, docs, layouts)
- [ ] **WRIT-02**: Brevity pass applied across all pages — filler cut, sentences tightened to minimum required words
- [ ] **WRIT-03**: Consistent peer-to-peer, evidence-first voice across all chokepoint and trend pages
- [ ] **WRIT-04**: `WhyCantBypass` / `TheConstant` fields visually dominant on chokepoint detail pages

### Site UX (UX)

- [ ] **UX-01**: Copy-to-clipboard button present on all Sigma rule code blocks (research, hunt, analyst tiers)
- [ ] **UX-02**: Sigma maturity tiers visually differentiated via distinct left-border accent color per tier (research / hunt / analyst)
- [ ] **UX-03**: Overflow tables reflow cleanly on mobile viewports

### OSINT Pipeline (PIPE)

- [ ] **PIPE-01**: `scripts/merge_records.py` written and merges `cache/ioc_records.json` + `cache/infra_records.json` + `cache/enriched_infra.json` into `cache/enriched_records.json` using the shared record schema
- [ ] **PIPE-02**: Confidence scoring separated from data quality — `confirmed`/`high` labels reflect adversary-behavior evidence (multi-source corroboration, confirmed payload chain), not structural completeness (has SHA-256, has domain)
- [ ] **PIPE-03**: `build_data.py` exits non-zero and skips history append when assembled record count falls below configurable minimum floor

## v2 Requirements

### Site UX

- **UX-V2-01**: IOK rules surfaced in site navigation and index filter chips
- **UX-V2-02**: Index tactic grouping for scalability beyond 20 chokepoints
- **UX-V2-03**: Framework/methodology hosted as on-site page (instead of raw GitHub markdown link)

### OSINT Pipeline

- **PIPE-V2-01**: Weekly GitHub Actions workflow automates pipeline collection and commits updated `_data/masq_infra.json`
- **PIPE-V2-02**: Streamlit validation harness replaced by scheduled CI job once accuracy is confirmed over multiple runs

## Out of Scope

| Feature | Reason |
|---------|--------|
| Vendor-specific SIEM rule translations | N rules × M vendors matrix is unsustainable for a solo project; pySigma backends handle this |
| Actor attribution tables | MITRE ATT&CK and Malpedia do this better with more resources; ages badly |
| AI-generated Sigma rules | Site value is curated, human-reviewed detections with explicit FP reasoning |
| User accounts / saved rules | Requires backend; static-only is an explicit architectural constraint |
| Community comments or discussion threads | Moderation overhead with no backend infrastructure |
| Interactive ATT&CK matrix widget | ATT&CK Navigator already exists and does this better |
| Streamlit app as shipped product | Validation harness only; not part of the site |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| BSLN-01 | Phase 1 | Pending |
| BSLN-02 | Phase 1 | Pending |
| BSLN-03 | Phase 1 | Pending |
| WRIT-01 | Phase 2 | Pending |
| WRIT-02 | Phase 2 | Pending |
| WRIT-03 | Phase 2 | Pending |
| WRIT-04 | Phase 2 | Pending |
| UX-01 | Phase 3 | Pending |
| UX-02 | Phase 3 | Pending |
| UX-03 | Phase 3 | Pending |
| PIPE-01 | Phase 4 | Pending |
| PIPE-02 | Phase 4 | Pending |
| PIPE-03 | Phase 4 | Pending |

**Coverage:**
- v1 requirements: 13 total
- Mapped to phases: 13
- Unmapped: 0 ✓

---
*Requirements defined: 2026-04-11*
*Last updated: 2026-04-11 after initial definition*
