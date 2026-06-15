#!/usr/bin/env python3
"""
ingest_carson_domains.py
Fetch Carson Williams' (cdup07) ClickFix domain gist and cache the normalised
domain set for the trends generator.

ROLE (see docs/DECISIONS.md #011): Carson's gist is a domains-ONLY feed — bare
hostnames, one per line, refreshed daily (~3.3k domains). It carries no command
lines (his richer ClickGrab fork froze 2025-10-09), so it cannot feed the
behavioural cradle/evasion stats — those are all MHaggis. Carson's value is
breadth: a landscape count (meta.total_domains) and corroboration of staging
domains MHaggis also observed.

HYGIENE: the full domain list stays in gitignored cache only. analyze_clickgrab.py
commits the COUNT and the corroboration count to clickgrab_trends.yml, never the
list itself.

Source: https://api.github.com/gists/9f563dfb78a06fad5db794f33ba93a3f
Output: cache/clickgrab/carson_domains.json  {count, updated, source, domains[]}
"""

import ipaddress
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

REPO_ROOT  = Path(__file__).parent.parent
OUT_PATH   = REPO_ROOT / "cache" / "clickgrab" / "carson_domains.json"

GIST_ID   = "9f563dfb78a06fad5db794f33ba93a3f"
GIST_API  = f"https://api.github.com/gists/{GIST_ID}"
GIST_FILE = "clickfix_domains.txt"

HEADERS = {"User-Agent": "detection-chokepoints/clickgrab-ingest",
           "Accept": "application/vnd.github+json"}

# A host line: a domain (labels + alpha TLD) OR a bare IPv4. We keep www. and
# IPs so the count stays faithful to "how many hosts Carson tracks" (a landscape
# stat that should trend with his list). www-stripping happens only at join time
# in the generator, where it's needed to match defanged staging domains.
RE_DOMAIN = re.compile(r"^(?:[a-z0-9_-]+\.)+[a-z]{2,}$")


def _is_ipv4(s: str) -> bool:
    """True only for a well-formed IPv4 — rejects 999.999.999.999 etc. that a loose
    \\d{1,3} regex would admit, so junk can't inflate the landscape count."""
    try:
        ipaddress.IPv4Address(s)
        return True
    except ValueError:
        return False


def normalise(line: str) -> str:
    """Lowercase, strip scheme/path/port/comments and a trailing dot. Keep www.
    and IPs. Returns '' to drop blanks/comments/invalid hosts."""
    s = line.strip().lower()
    if not s or s.startswith("#"):
        return ""
    s = re.sub(r"^https?://", "", s)            # tolerate a stray scheme
    s = s.split("/", 1)[0].split(":", 1)[0]     # drop any path / port
    s = s.rstrip(".")
    return s if (RE_DOMAIN.match(s) or _is_ipv4(s)) else ""


def main() -> None:
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        resp = requests.get(GIST_API, headers=HEADERS, timeout=30)
        resp.raise_for_status()
        gist = resp.json()
    except requests.RequestException as exc:
        print(f"ERROR fetching gist: {exc}", file=sys.stderr)
        sys.exit(1)

    files = gist.get("files", {})
    finfo = files.get(GIST_FILE) or next(iter(files.values()), None)
    if not finfo:
        print("ERROR: gist has no files", file=sys.stderr)
        sys.exit(1)

    # The gist API inlines file content unless it exceeds ~1 MB (this file is
    # ~64 KB, so 'truncated' is False); fall back to raw_url just in case — with
    # the same status/timeout guards, so a 5xx error page can't become the data.
    content = finfo.get("content")
    if finfo.get("truncated") or content is None:
        try:
            r = requests.get(finfo["raw_url"], headers=HEADERS, timeout=30)
            r.raise_for_status()
            content = r.text
        except requests.RequestException as exc:
            print(f"ERROR fetching gist raw content: {exc}", file=sys.stderr)
            sys.exit(1)

    raw_lines = content.splitlines()
    domains = sorted({d for d in (normalise(ln) for ln in raw_lines) if d})

    # Guard against a transient/empty upstream clobbering the cache with count~0,
    # which analyze_clickgrab would then publish as total_domains. Refuse to
    # overwrite a healthy cache with an implausibly small result; keep the last good.
    prior = None
    if OUT_PATH.exists():
        try:
            prior = json.loads(OUT_PATH.read_text(encoding="utf-8")).get("count")
        except Exception:
            prior = None
    if len(domains) == 0 or (isinstance(prior, int) and prior > 0 and len(domains) < prior * 0.5):
        print(f"ERROR: refusing to overwrite cache — {len(domains)} domains is implausibly low "
              f"vs prior {prior} (likely a transient/empty upstream). Keeping last good cache.",
              file=sys.stderr)
        sys.exit(1)

    # Atomic write: a crash mid-write must not leave truncated JSON the generator
    # would then json.load.
    tmp = OUT_PATH.with_name(OUT_PATH.name + ".tmp")
    tmp.write_text(json.dumps({
        "count":   len(domains),
        "updated": gist.get("updated_at"),
        "description": gist.get("description"),
        "source":  f"https://gist.github.com/cdup07/{GIST_ID}",
        "fetched_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "domains": domains,
    }, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, OUT_PATH)

    dropped = len(raw_lines) - len(domains)
    print(f"Carson gist: {len(raw_lines)} lines -> {len(domains)} unique domains "
          f"({dropped} blank/dupe/invalid dropped)")
    print(f"Updated: {gist.get('updated_at')}  | written: {OUT_PATH}")


if __name__ == "__main__":
    main()
