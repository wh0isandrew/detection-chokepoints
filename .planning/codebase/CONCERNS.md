# Concerns — detection-chokepoints

## Schema Not Machine-Enforced

`schema/chokepoint-schema.yml` is documentation only. Nothing prevents a contributor from omitting required fields (`Id`, `MitreIds`, `Chokepoints`), using wrong enum values for `DetectionPriority`, or adding `KnownBypasses` entries that the layout no longer renders. Drift between schema docs and actual YAML content is undetected until the page looks wrong.

## Missing Sigma Rules

Several chokepoints have incomplete rule sets:
- `sigma-rules/remote-execution/` — missing `analyst.yml`
- Some chokepoints may be missing the `hunt-network.yml` variant where applicable

The layout renders whatever is present; there's no build warning for missing maturity levels.

## Generated Files Committed

`_chokepoints/`, `_data/chokepoints.yml`, and `assets/js/search-index.json` are generated at build time by `aggregate.py`. If they're committed (as appears to be the case for `_site/` being partially present), they can diverge from the source YAML without anyone noticing until the next build. The canonical rule: these files should never be manually edited, but there's no git hook enforcing this.

## attack-chains/webdav.json Untracked

`attack-chains/webdav.json` appears in git status as untracked — work in progress that hasn't been committed. The attack chain format/template needs to be established before it becomes a pattern.

## No Sigma Validation in CI

CI only checks that `aggregate.py` runs without error and Jekyll builds. A syntactically valid but logically broken Sigma rule (wrong field names, invalid condition syntax, missing required tags) will build fine and only be caught by a human reviewer or `sigma-cli` run manually.

## `KnownBypasses` Dead Field

The field is preserved in `schema/chokepoint-schema.yml` for data integrity but the layout no longer renders it. Existing entries have `KnownBypasses` data that silently goes nowhere. If the data is valuable it needs a new rendering location; if not, entries should be cleaned up and the field removed from schema.

## Threat Intel Scripts Undocumented

The `scripts/` directory contains ~14 Python scripts for threat intel collection, enrichment, and analysis. Most have no README or docstring explaining their dependencies, API keys required, or intended workflow. `sources.yml` configures feed sources but its format is undocumented.

## `app/` Directory Purpose Unknown

A top-level `app/` directory exists but its purpose wasn't established from the visible file tree. Could be a separate web application, tooling, or leftover artifact.

## `preview.html` Untracked

`preview.html` is listed as untracked in git status. If it's a useful local development tool it should be committed (or added to `.gitignore` if intentionally local-only).

## No Contribution Automation

The contribution workflow (new chokepoint → YAML + Sigma rules + emulation script + PR) is documented in `CONTRIBUTING.md` and `templates/`, but entirely manual. There's no scaffolding script to generate a correctly structured new entry from a template.

## `_site/` Scope

The build output in `_site/` may be partially committed. Static site output typically shouldn't be committed when GitHub Actions handles deployment, as it creates misleading diffs and inflates repo size.
