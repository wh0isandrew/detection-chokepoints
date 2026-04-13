# Features Research

## Context

The design language is already at parity with what the target audience (detection engineers, threat hunters) expects from reference tools. This milestone closes specific gaps and extends existing patterns — it is not a rebuild.

**What the site already has:**
- GitHub-style dark theme with strong color system (`#0d1117` background, `#f0883e` orange accent)
- Light/dark toggle persisted via `localStorage`
- Sticky top nav with active-state highlighting
- In-page anchor sub-nav (`.page-anchors`) on chokepoint pages
- Filter chips by tactic and priority on the index
- Fuse.js client-side fuzzy search
- Three-tier Sigma maturity model with color-coded badges
- Stable permalinks at `/chokepoints/<slug>/`
- Visible timestamps on trends cards

---

## Table Stakes

Features users expect. Missing any of these makes the site feel incomplete.

| Feature | Why Expected | Complexity | Current State |
|---------|--------------|------------|---------------|
| Copy-to-clipboard on code blocks | Sigma rules are the primary deliverable. Users expect one-click copy (set by GitHub, GitLab, every modern docs site). Drag-select copy on YAML breaks indentation. | Low | **MISSING — highest priority gap** |
| Mobile-readable layout | Engineers read during incidents on phones; cards and tables must reflow | Low-Medium | Partial — nav is mobile-aware but some tables may overflow |
| Syntax-highlighted code blocks | Unformatted YAML rule content is nearly unreadable; standard on any code-heavy reference site | Low | Present but needs verification across all maturity levels |
| Visible data freshness on trend pages | Stale trend data is worse than no data — it misleads. Users must see collection window and generation date, not just "recent" | Low | Pattern exists on clickgrab page; needs consistent application |
| Stable, shareable deep links | Engineers share chokepoint links in Slack, PRs, and blog posts. Broken links destroy trust | Low | Exists — `/chokepoints/<slug>/` and anchor IDs |
| MITRE T-IDs visible on index cards | Engineers scan for T-numbers first. Must be visible at the card level, not only on detail pages | Low | Exists |
| Readable long-form pages on desktop | Chokepoint detail pages are long. Typographic rhythm, line length, and section spacing determine whether someone reads or skips | Medium | Exists but section spacing is uneven across pages |

---

## Differentiators

What makes this site worth bookmarking instead of using the sigma/main GitHub repo.

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| Detection invariant framing | Reframes detection from "detect this tool" to "detect this prerequisite" — rare in community resources. The "WhyCantBypass" field is the intellectual core. | Low (content exists) | Exists in YAML + rendered pages. The invariant should be visually dominant, not equal weight to other fields. |
| Three-tier Sigma maturity progression | No other free resource walks through noisy-to-production tuning. The site's strongest differentiator from a plain rule repo. | Medium | Exists. Needs visual differentiation — research and analyst rules currently render with the same container weight. |
| Variations table with status badges | Shows tool rotation as variant entries, not separate chokepoints. Teaches the "same prerequisite" mindset. No community equivalent. | Low | Exists — Active/Emerging/Archived status badges. |
| Evolution timeline with DetectionImpact | Shows defenders what changed and whether existing coverage still holds. Rare in community resources. | Low | Exists in YAML, rendering quality varies by page. |
| Trend pages with data provenance | URLScan/URLhaus/crawl data with explicit collection methodology, date range, and sample size. Turns "ransomware delivery is changing" into a citable data point. | High (pipeline) | Partial — clickgrab is done. masq-infra blocked on pipeline accuracy. |
| IOK rules for pre-execution detection | Pre-execution detection layer is nearly absent from community Sigma resources. | Medium | Exists in site data but not prominently surfaced in nav or index. |
| Emulation scripts linked from detection pages | Closes the loop: Sigma rule + "here is how to fire it in a lab." Uncommon in community resources. | Low | Exists — emulation_content embedded inline. |
| Attack chains linking multiple chokepoints | Full kill-chain view (ransomware, infostealer) is more actionable than isolated technique entries. | Medium | Exists — attack-chains section. |
| Source attribution per variant | Every variant cites a real incident report or vendor analysis. No hypothetical examples. | Low | Exists — `SourceURL` per variant. |

---

## Anti-Features

Things to deliberately not build.

| Anti-Feature | Why Avoid | What to Do Instead |
|--------------|-----------|-------------------|
| Vendor-specific SIEM translations | Maintaining Splunk/Elastic/Sentinel-converted rules creates an N rules × M vendors matrix one person cannot sustain. | Link to pySigma converter docs from the Sigma section; add a one-liner convert command to CONTRIBUTING.md. |
| Actor attribution tables | MITRE ATT&CK, Malpedia, and vendor threat intel teams do this better with more resources. Ages badly. | Link to MITRE group pages from relevant chokepoints where actor overlap is relevant. |
| CVE / vulnerability tracking | Not the site's domain. Post-exploitation detection is in scope; exploit tracking competes with NVD. | Narrow to "what the attacker does after the exploit" — already the site's focus. |
| News/blog section | Irregular posts make the site look abandoned. | Treat trend pages as the update mechanism, not freeform blog posts. |
| User accounts / saved rules | Requires backend. Explicit architectural constraint against it. | Provide copy buttons and GitHub links — the user's own SIEM is the persistence layer. |
| AI-generated Sigma rules | The site's value is curated, human-reviewed, analyst-tuned detections with explicit FP reasoning. AI rules erode this. | Keep rules hand-authored with visible false-positive rationale per rule. |
| Interactive ATT&CK matrix widget | ATT&CK Navigator already exists and does this better. Adds heavy JS dependency with no net value. | Link to the Navigator; consider exporting a coverage-layer JSON from aggregate.py as a download. |
| Community comments or discussion threads | Moderation overhead with no backend infrastructure. | Use GitHub Issues as the community channel; link from relevant chokepoint pages. |

---

## Key Findings

**Copy buttons are the single highest-priority gap.** Sigma rules are the primary deliverable. Users who cannot copy in one click will drag-select, get broken YAML indentation, and blame the rule. Every modern reference site ships copy buttons. Low complexity, high daily friction reduction.

**Visual differentiation between maturity levels needs work.** Research and analyst Sigma rules currently render with identical visual weight. The maturity model is the site's core differentiator — the visual rendering should reinforce the semantic distinction. A left-border accent color per tier (in addition to the badge) accomplishes this with minimal CSS.

**The trends trust-signal pattern is established but not complete.** The clickgrab page does it right: explicit collection window (dates), sample size, methodology box, and a generation timestamp. Masq-infra is a stub. Apply the same pattern once data is ready.

**IOK rules are invisible to first-time visitors.** Pre-execution detection layer is one of the site's strongest differentiators but the index has no IOK filter and the nav has no IOK entry. Surface IOK as a filterable category on the index.

**Navigation works now; plan for 20+ chokepoints.** Flat index with filter chips is functional at 8 entries. At 20+, tactic grouping in the index will reduce scroll fatigue. Inform how the index template is structured now.

**Framework lives off-site.** FRAMEWORK.md links to a raw GitHub markdown file. Hosting the methodology as a first-class on-site page would reduce the "you left the site" jarring effect and improve discoverability.
