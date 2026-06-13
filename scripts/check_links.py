#!/usr/bin/env python3
"""Audit external URLs referenced in chokepoint YAML entries.

Run: `python scripts/check_links.py`
Reports three buckets so genuine link-rot is separated from noise:
  BROKEN  - 404/410/5xx/DNS failure: a real dead citation, fix it.
  BLOCKED - 401/403/429: bot/auth/rate-limit. The page is usually fine; these
            are query/search URLs (Censys, Graph API) or sites that block
            non-browser clients. Verify manually, don't auto-edit.
  OK      - 2xx/3xx.

This is advisory, NOT a CI gate: external links flake (BLOCKED proves it), so
failing a PR on them would be too noisy. The schema validator is the hard gate;
this is a periodic maintenance sweep. Exit code is always 0.

Note: placeholder/example URLs inside detection logic (e.g. http://target/...)
and live API endpoints (graph.microsoft.com, login.microsoftonline.com) will
appear as BROKEN/BLOCKED — they are technique illustrations, not citations.
"""
from __future__ import annotations

import re
import socket
import ssl
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
URL_RE = re.compile(r"https?://[^\s\"'<>)\]}]+")
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      "Accept": "*/*"}
_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE


def collect() -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for f in sorted((REPO / "chokepoints").glob("*/*.yml")):
        for i, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            for m in URL_RE.finditer(line):
                url = m.group(0).rstrip(".,;")
                found.setdefault(url, []).append(f"{f.relative_to(REPO).as_posix()}:{i}")
    return found


def check(url: str):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=UA),
                                    timeout=15, context=_ctx) as r:
            return url, r.status
    except urllib.error.HTTPError as e:
        return url, e.code
    except (urllib.error.URLError, socket.timeout, ssl.SSLError, ConnectionError):
        return url, "ERR"
    except Exception:
        return url, "ERR"


def bucket(status) -> str:
    if isinstance(status, int) and 200 <= status < 400:
        return "OK"
    if status in (401, 403, 429):
        return "BLOCKED"
    return "BROKEN"


def main() -> int:
    found = collect()
    results: dict[str, object] = {}
    with ThreadPoolExecutor(max_workers=12) as ex:
        for url, status in ex.map(check, found):
            results[url] = status

    broken = sorted(u for u in found if bucket(results[u]) == "BROKEN")
    blocked = sorted(u for u in found if bucket(results[u]) == "BLOCKED")
    ok = [u for u in found if bucket(results[u]) == "OK"]

    print(f"{len(found)} unique URLs  |  OK {len(ok)}  BLOCKED {len(blocked)}  BROKEN {len(broken)}\n")
    print("=== BROKEN (review — real dead citations, excluding example/API URLs) ===")
    for u in broken:
        print(f"  [{results[u]}] {u}")
        for loc in found[u]:
            print(f"        @ {loc}")
    print("\n=== BLOCKED (bot/auth/ratelimit — usually fine) ===")
    for u in blocked:
        print(f"  [{results[u]}] {u}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
