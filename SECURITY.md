# Security Policy

## Reporting a vulnerability

If you find a security issue in this repository — the site, the build/automation
pipeline, or anything that could let a third party tamper with published content —
please report it privately rather than opening a public issue.

- Preferred: open a [GitHub private security advisory](https://github.com/iimp0ster/detection-chokepoints/security/advisories/new).
- Alternatively, DM [@iimp0ster](https://twitter.com/iimp0ster).

Please include what you found, where, and how to reproduce it. I'll acknowledge
within a few days and keep you posted on the fix.

## Scope

In scope:

- Cross-site scripting or content injection via contributed chokepoint YAML,
  Sigma rules, IOK rules, or trend data rendered on the live site.
- Supply-chain exposure in GitHub Actions workflows or site dependencies.
- Any path that allows unauthorized modification of `main` or the deployed site.

Out of scope:

- The detection content itself. Sigma rules, command-line examples, emulation
  scripts, and IOCs are **intentional, public threat-intelligence artifacts** —
  reporting that the repo "contains attack commands" is not a vulnerability.
- The MagicSword affiliate link and other public configuration.

## Contributions

This is a community resource. Contributions arrive by pull request and are
reviewed before merge. Detection logic, prose, and metadata from contributed
files are HTML-escaped at render time; if you find a field that reaches the DOM
unescaped, that is in scope above.
