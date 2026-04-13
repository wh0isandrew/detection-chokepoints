# Testing — detection-chokepoints

## Current State

No automated test suite. No CI test step beyond Jekyll build success. Testing is manual.

## What the Build Validates

Running `python scripts/aggregate.py && jekyll build` catches:
- YAML parse errors in chokepoints or sigma rules (PyYAML will error)
- Missing referenced sigma/emulation files (aggregate.py prints warnings to stderr)
- Broken Liquid template syntax (Jekyll errors on build)
- Missing required front matter fields that templates depend on

The GitHub Actions workflow (`pages.yml`) fails the deploy if either script errors — this is the only automated quality gate today.

## Manual Validation Approaches

### Local build
```bash
bundle exec jekyll serve
# Open http://localhost:4000/detection-chokepoints/
```

### Pre-build data check
```bash
python scripts/aggregate.py
# Check stderr for warnings about missing files
# Check _data/chokepoints.yml for expected entry count
```

### Sigma rule linting
```bash
# Using sigma-cli (not currently integrated into CI)
sigma check sigma-rules/**/*.yml
```

### YAML schema validation
No automated schema validation against `schema/chokepoint-schema.yml` — it's documentation-only, not machine-enforced.

## Testing Gaps

- No schema validation enforced at build or commit time
- No Sigma rule quality checks (syntax, required fields, tag format) in CI
- No visual regression testing for layout changes
- No broken-link checking in generated `_site/`
- No test that verifies SigmaRef paths in chokepoint YAML resolve to real files
- `aggregate.py` warnings go to stderr but don't fail the build — a missing emulation script is silent in CI output

## Recommended Improvements

- Add `sigma check` or `sigma-cli validate` step to CI
- Add Python script to validate required YAML fields against schema (especially `Id`, `MitreIds`, `Chokepoints` presence)
- Validate that all `SigmaRule` paths in `Detections[]` and `EarlyDetections[]` resolve to real files (extend aggregate.py warnings to CI failures)
- Add `htmlproofer` to Jekyll CI step for link validation
