#!/usr/bin/env python3
"""
analyze_clickgrab.py
Merge new ClickGrab nightly days into _data/clickgrab_trends.yml.

DESIGN (see docs/DECISIONS.md #011) — baseline + append, never regenerate:
  The committed _data/clickgrab_trends.yml (Apr 2025 .. May 2026) is a FROZEN
  historical baseline. The rich generator that produced it was never committed
  and the pre-Oct-2025 nightly reports are LFS-budget-locked, so that history
  cannot be re-derived. This script therefore only APPENDS days that are newer
  than the file's current max daily date, recomputing aggregate totals as
  baseline + new-day deltas. It never recomputes the historical sections.

  Idempotency invariant: "new days" = cached days with date strictly greater
  than max(daily.date) in the current file. Because each run appends and the
  file is committed, the max date advances and the next run only adds genuinely
  new days — re-running is a no-op, so totals never double-count.

WHAT IT UPDATES (counts / time-series only — statistics, no IOCs committed):
  meta.{total_reports,total_sites_crawled,total_malicious,date_range,generated,
        total_domains,carson_*}
  daily[]            append one entry per new day (full cradle schema)
  cradles_total      += new-day deltas
  evasion_totals     += new-day deltas
  monthly[]          extend boundary month + append new months

WHAT IT PRESERVES VERBATIM (curated / enriched / contains defanged payloads):
  payload_examples   curated, defanged — example refresh is a manual step
  domain_monthly     historical per-domain classification (not re-derivable)
  staging_domains    ASN/geo enrichment is a separate LOCAL step (#001)

INPUT:  cache/clickgrab/days/<YYYY-MM-DD>.json   (written by ingest_clickgrab.py)
        cache/clickgrab/carson_domains.json       (optional, ingest_carson_domains.py)
OUTPUT: _data/clickgrab_trends.yml                 (round-tripped via PyYAML)

Usage:
  python scripts/analyze_clickgrab.py
"""

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import yaml

REPO_ROOT  = Path(__file__).parent.parent
DAYS_DIR   = REPO_ROOT / "cache" / "clickgrab" / "days"
CARSON_CACHE = REPO_ROOT / "cache" / "clickgrab" / "carson_domains.json"
TRENDS_YML = REPO_ROOT / "_data" / "clickgrab_trends.yml"

# ---------------------------------------------------------------------------
# Detection — shared with the chokepoint Sigma logic; we classify each site by
# the invariant behaviour in its clipboard/PowerShell command, not the lure.
# ---------------------------------------------------------------------------

RE = {
    "iex":        re.compile(r"\biex\b|Invoke-Expression", re.I),
    "iwr":        re.compile(r"\biwr\b|Invoke-WebRequest", re.I),
    "irm":        re.compile(r"\birm\b|Invoke-RestMethod", re.I),
    "webclient":  re.compile(r"WebClient|DownloadString|DownloadFile", re.I),
    "curl":       re.compile(r"\bcurl\b", re.I),
    "msiexec":    re.compile(r"\bmsiexec\b", re.I),
    "vbs_wscript":re.compile(r"WinHttp\.WinHttpRequest|\bWScript\b|CreateObject\(", re.I),
    "hex_xor":    re.compile(r"-bxor", re.I),
    "self_delete":re.compile(r"\bdel\s|Remove-Item\b", re.I),
    "start_sleep":re.compile(r"Start-Sleep\b|-sleep\s", re.I),
    "hidden":     re.compile(r"-w\s+h(idden)?\b|-WindowStyle\s+Hidden\b", re.I),
    "enc":        re.compile(r"FromBase64String|-enc(odedcommand)?\b", re.I),
    "url":        re.compile(r"https?://|hxxps?://", re.I),
}
# Mixed-case PowerShell: any casing that isn't the three "normal" forms.
RE_PS_ANY = re.compile(r"p[oO][wW][eE][rR][sS][hH][eE][lL][lL]")
CDN_PATTERNS = re.compile(r"cdn[-.]|\.wixstatic\.com|irp\.cdn-website\.com", re.I)


def extract_ps_text(record: dict) -> str:
    """Concatenate every command-bearing field into one searchable string."""
    parts = []
    for field in ("PowerShellCommands", "ClipboardCommands", "HighRiskCommands",
                  "EncodedPowerShell", "SuspiciousCommands"):
        v = record.get(field)
        if isinstance(v, str):
            parts.append(v)
        elif isinstance(v, list):
            parts.extend(str(x) for x in v if x)
    b64 = record.get("Base64Strings")
    if isinstance(b64, dict):
        parts.append(str(b64.get("Decoded") or b64.get("decoded") or ""))
    elif isinstance(b64, list):
        for it in b64:
            if isinstance(it, dict):
                parts.append(str(it.get("Decoded") or it.get("decoded") or ""))
    return " ".join(parts)


def download_urls(record: dict) -> list:
    urls = []
    dls = record.get("PowerShellDownloads") or []
    if isinstance(dls, dict):
        dls = [dls]
    for dl in dls:
        if isinstance(dl, dict):
            u = dl.get("URL") or dl.get("url")
            if u:
                urls.append(u)
    return urls


def has_command(record: dict) -> bool:
    """True if the site carries an actual clipboard/PowerShell command or download —
    the real attack artifact, distinct from a lure page that merely scored > 0."""
    return bool(record.get("PowerShellCommands") or record.get("ClipboardCommands")
                or record.get("PowerShellDownloads") or record.get("HighRiskCommands"))


def is_malicious(record: dict) -> bool:
    """Upstream's own Verdict is authoritative; a page carrying an actual command or
    download is malicious regardless. Bare ThreatScore > 0 is deliberately NOT used:
    in this feed it fires on 'Likely Safe' lure pages (TS 2-5, no payload) and inflated
    the malicious count ~2x (1560 of 2700 records are 'Likely Safe' — verified)."""
    verdict = str(record.get("Verdict") or "").lower()
    return verdict in ("malicious", "suspicious", "high risk") or has_command(record)


def is_mixed_case_ps(text: str) -> bool:
    for m in RE_PS_ANY.finditer(text):
        if m.group(0) not in ("PowerShell", "powershell", "POWERSHELL"):
            return True
    return False


def _b64_is_ps(blob) -> bool:
    """True only for a Base64Strings blob the upstream flagged as PowerShell-bearing.
    ContainsPowerShell arrives as a stringified bool ('True'/'False'); the literal
    '[TRUNCATED BASE64]' is a truncation placeholder, not a payload."""
    if not isinstance(blob, dict):
        return False
    dec = str(blob.get("Decoded") or blob.get("decoded") or "").strip()
    if not dec or dec == "[TRUNCATED BASE64]":
        return False
    return str(blob.get("ContainsPowerShell")).strip().lower() == "true"


def has_b64(record: dict, text: str) -> bool:
    """A real base64-obfuscated payload: a Base64Strings blob flagged ContainsPowerShell
    (excluding the truncation placeholder), OR an explicit -enc / FromBase64String in the
    command text. The prior 'any blob with Decoded' rule was ~93% noise — lure-page UI
    strings (ContainsPowerShell=False) and '[TRUNCATED BASE64]' markers (judged + verified)."""
    b = record.get("Base64Strings")
    blobs = b if isinstance(b, list) else ([b] if isinstance(b, dict) else [])
    if any(_b64_is_ps(x) for x in blobs):
        return True
    return bool(RE["enc"].search(text))


def classify_site(record: dict) -> dict:
    """Return the cradle/evasion tags + staging hosts for one site."""
    text = extract_ps_text(record)
    urls = download_urls(record)
    has_iex = bool(RE["iex"].search(text))
    has_iwr = bool(RE["iwr"].search(text))
    has_url = bool(urls) or bool(RE["url"].search(text))

    staging = []
    for u in urls:
        try:
            host = urlparse(u).hostname or ""
        except ValueError:
            host = ""
        if host:
            staging.append((host, bool(CDN_PATTERNS.search(host))))

    return {
        "malicious":   is_malicious(record),
        # cradles (non-exclusive, mirrors baseline counting)
        "iwr_iex":     has_iwr and has_iex,
        "irm_iex":     bool(RE["irm"].search(text)) and has_iex and not has_iwr,
        "webclient":   bool(RE["webclient"].search(text)),
        "curl":        bool(RE["curl"].search(text)),
        "msiexec":     bool(RE["msiexec"].search(text)),
        "vbs_wscript": bool(RE["vbs_wscript"].search(text)),
        "hex_xor":     bool(RE["hex_xor"].search(text)),
        # A true inline payload: the site HAS a clipboard/PowerShell command and that
        # command carries no URL. The prior 'malicious and not has_url' admitted empty
        # lure pages — 60% of inline hits had no command text at all (judged + verified).
        "inline_no_url": is_malicious(record) and has_command(record) and not has_url,
        # evasion
        "mixed_case":  bool(text) and is_mixed_case_ps(text),
        "base64":      has_b64(record, text),
        "cdn_staging": any(cdn for _, cdn in staging),
        "self_delete": bool(RE["self_delete"].search(text)),
        "start_sleep": bool(RE["start_sleep"].search(text)),
        "hidden_window": bool(RE["hidden"].search(text)),
    }


CRADLE_KEYS  = ["iwr_iex", "irm_iex", "webclient", "curl", "msiexec", "vbs_wscript", "hex_xor", "inline_no_url"]
EVASION_KEYS = ["mixed_case", "base64", "cdn_staging", "self_delete", "start_sleep", "hidden_window"]


def aggregate_day(records) -> dict:
    """Compute one day's aggregate entry from its site records. Defensive about
    shape: a non-list day or non-dict elements must never inflate the counts —
    total_sites is the number of records actually classified, not len(raw)."""
    if not isinstance(records, list):
        records = []
    valid = [r for r in records if isinstance(r, dict)]
    cradles = {k: 0 for k in CRADLE_KEYS}
    evasion = {k: 0 for k in EVASION_KEYS}
    malicious = 0
    for r in valid:
        c = classify_site(r)
        if c["malicious"]:
            malicious += 1
        for k in CRADLE_KEYS:
            cradles[k] += int(bool(c[k]))
        for k in EVASION_KEYS:
            evasion[k] += int(bool(c[k]))
    return {"total_sites": len(valid), "malicious": malicious,
            "cradles": cradles, "evasion": evasion,
            "inline_payload": cradles["inline_no_url"]}


# ---------------------------------------------------------------------------
# Merge
# ---------------------------------------------------------------------------

ISO_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


def _valid_iso(s) -> bool:
    """ISO-shaped AND a real calendar date — rejects 2026-13-40 / 2026-02-30 / '' that
    a shape-only regex would admit (and which, sorting lexicographically after every real
    date, would poison the watermark)."""
    try:
        datetime.strptime(str(s), "%Y-%m-%d")
        return True
    except (ValueError, TypeError):
        return False


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def load_new_days(after: str) -> list:
    """Return [(date, records)] for cached days strictly after `after`, sorted.

    Filenames MUST be a strict zero-padded ISO date. This is load-bearing: the
    `day <= after` comparison is LEXICOGRAPHIC, so a stray non-date stem
    (latest.json, an editor backup, an unpadded 2026-6-9.json) could sort after
    a real date, get appended as a bogus daily entry, and poison the watermark —
    silently killing the append-only pipeline forever. Reject anything non-ISO.
    """
    today = _today()
    out = []
    for p in sorted(DAYS_DIR.glob("*.json")):
        day = p.stem
        if not _valid_iso(day):
            print(f"  WARN: ignoring non-/impossible-ISO-date cache file {p.name}", file=sys.stderr)
            continue
        if day > today:
            # A valid future date would set the watermark to the future and suppress
            # every real day thereafter — symmetric with ingest's today-cap.
            print(f"  WARN: ignoring future-dated cache file {p.name}", file=sys.stderr)
            continue
        if day <= after:
            continue
        try:
            recs = json.loads(p.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"  WARN: skip {p.name}: {exc}", file=sys.stderr)
            continue
        if not isinstance(recs, list):
            print(f"  WARN: skip {p.name}: expected a list of records, got {type(recs).__name__}",
                  file=sys.stderr)
            continue
        out.append((day, recs))
    return out


def load_carson() -> dict | None:
    """Return {count, updated, norm} from the Carson cache, or None if absent/unreadable.
    `norm` is the www-stripped lowercased host set used for the lure-overlap join."""
    if not CARSON_CACHE.exists():
        return None
    try:
        c = json.loads(CARSON_CACHE.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"  WARN: carson cache unreadable: {exc}", file=sys.stderr)
        return None
    norm = {re.sub(r"^www\.", "", str(d).lower()) for d in c.get("domains", [])}
    count = c.get("count")
    return {"count": count if isinstance(count, int) else None,
            "updated": c.get("updated"), "norm": norm}


def main() -> None:
    if not TRENDS_YML.exists():
        print(f"ERROR: baseline {TRENDS_YML} missing", file=sys.stderr)
        sys.exit(1)
    data = yaml.safe_load(TRENDS_YML.read_text(encoding="utf-8"))

    daily = data.setdefault("daily", [])
    meta = data.setdefault("meta", {})
    if not daily:
        print("ERROR: baseline has no daily[] — refusing to run (would not be append-only)", file=sys.stderr)
        sys.exit(1)

    # ── Watermark ────────────────────────────────────────────────────────────
    # Authoritative "append after" date. Prefer the explicit meta.appended_through
    # stamp this script maintains — it doesn't depend on parsing a human-facing
    # display string. First run: absent, so derive from max(daily_max, date_range
    # end). FAIL CLOSED if date_range end is present but unparseable: silently
    # collapsing to the much-earlier daily_max would re-append (and double-count)
    # months already in the totals — exactly what #011 exists to prevent.
    today = _today()
    valid_dates = [d["date"] for d in daily if _valid_iso(d.get("date")) and d["date"] <= today]
    daily_max = max(valid_dates) if valid_dates else ""
    appended_through = str(meta.get("appended_through", "")).strip()
    has_range_key = "date_range" in meta
    range_end = (str(meta.get("date_range", "")) or "").split(" to ")[-1].strip()
    if _valid_iso(appended_through):
        watermark = appended_through
    elif not has_range_key:
        watermark = daily_max          # genuine first run on a file with no totals coverage
    elif _valid_iso(range_end):
        watermark = max(daily_max, range_end)
    else:
        # date_range is present but empty/unparseable: FAIL CLOSED. Collapsing to the
        # earlier daily_max would re-append (double-count) history already in the totals.
        print(f"ERROR: meta.date_range end {range_end!r} is not a valid date — refusing to run "
              f"(cannot establish a safe watermark without risking re-counting history).",
              file=sys.stderr)
        sys.exit(1)
    print(f"Watermark (append after): {watermark}  (appended_through={appended_through or 'n/a'}, "
          f"daily_max={daily_max or 'n/a'}, range_end={range_end or 'n/a'})")

    new_days = load_new_days(watermark)

    # Carson refreshes on its own cadence — a Carson-only update (no new ClickGrab
    # day) is still a reason to write, so total_domains doesn't go stale when
    # ClickGrab is quiet. Detect change before deciding whether there's work to do.
    # The daily gist count is the live LANDSCAPE figure (meta.carson_landscape), kept
    # distinct from meta.total_domains — which is the command-classified set (the XLSX,
    # owned by build_domain_monthly.py) that the charts/cards reflect. See DECISIONS #012.
    carson = load_carson()
    carson_total = None
    carson_changed = False
    if carson:
        carson_total = (carson["count"] if carson["count"] is not None
                        else (len(carson["norm"]) if carson["norm"] else meta.get("carson_landscape")))
        carson_changed = (carson_total != meta.get("carson_landscape")
                          or carson["updated"] != meta.get("carson_updated"))

    if not new_days and not carson_changed:
        print("No new ClickGrab days and Carson unchanged — up to date. Nothing written.")
        return
    if new_days:
        print(f"Appending {len(new_days)} new day(s): {new_days[0][0]} .. {new_days[-1][0]}")

    cradles_total = data.setdefault("cradles_total", {})
    evasion_totals = data.setdefault("evasion_totals", {})
    # Index monthly entries by month so we can extend the boundary month in place.
    monthly = data.setdefault("monthly", [])
    monthly_idx = {m["month"]: m for m in monthly}

    add_reports = add_sites = add_mal = 0
    lure_hosts = set()   # unique lure-site hostnames across the new days (for Carson overlap)

    for day, records in new_days:
        agg = aggregate_day(records)
        for r in records:
            if isinstance(r, dict):
                u = r.get("URL") or r.get("Url") or r.get("url") or ""
                if not isinstance(u, str):
                    continue   # a non-string URL is never a valid host
                try:
                    h = urlparse(u if "//" in u else "//" + u).hostname
                except (ValueError, TypeError):
                    h = None
                if h:
                    lure_hosts.add(h.lower())

        # daily[] — append (full cradle schema so future runs stay consistent)
        daily.append({
            "date": day,
            "total_sites": agg["total_sites"],
            "malicious": agg["malicious"],
            "cradles": dict(agg["cradles"]),
            "evasion": dict(agg["evasion"]),
        })

        # *_total += deltas
        for k in CRADLE_KEYS:
            cradles_total[k] = cradles_total.get(k, 0) + agg["cradles"][k]
        for k in EVASION_KEYS:
            evasion_totals[k] = evasion_totals.get(k, 0) + agg["evasion"][k]
        evasion_totals["inline_payload"] = evasion_totals.get("inline_payload", 0) + agg["inline_payload"]

        # monthly[] — extend boundary month / create new month
        mk = day[:7]
        m = monthly_idx.get(mk)
        if m is None:
            m = {"month": mk, "total_sites": 0, "malicious": 0,
                 "cradles": {k: 0 for k in CRADLE_KEYS},
                 "evasion": {k: 0 for k in EVASION_KEYS}}
            monthly.append(m)
            monthly_idx[mk] = m
        m["total_sites"] = m.get("total_sites", 0) + agg["total_sites"]
        m["malicious"] = m.get("malicious", 0) + agg["malicious"]
        mc = m.setdefault("cradles", {})
        me = m.setdefault("evasion", {})
        for k in CRADLE_KEYS:
            mc[k] = mc.get(k, 0) + agg["cradles"][k]
        for k in EVASION_KEYS:
            me[k] = me.get(k, 0) + agg["evasion"][k]

        add_reports += 1
        add_sites += agg["total_sites"]
        add_mal += agg["malicious"]

    # meta — accumulate counts, advance window end + watermark, restamp generated.
    if new_days:
        meta["total_reports"] = meta.get("total_reports", 0) + add_reports
        meta["total_sites_crawled"] = meta.get("total_sites_crawled", 0) + add_sites
        meta["total_malicious"] = meta.get("total_malicious", 0) + add_mal
        start = (meta.get("date_range", "").split(" to ")[0]) or daily[0]["date"]
        meta["date_range"] = f"{start} to {new_days[-1][0]}"
        meta["appended_through"] = new_days[-1][0]   # explicit, ISO, machine watermark
    meta["generated"] = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # Carson landscape (domains-only feed): faithful host count + lure overlap.
    # carson_total is pre-computed (None-safe, so a genuine count of 0 records 0,
    # not the stale prior value); lure overlap is 0/0 on a Carson-only refresh.
    if carson:
        # Defense-in-depth floor (the ingest has its own): never let a bypassed/hand-edited
        # cache publish a 0 or implausibly-shrunken landscape count into the public page.
        prior = meta.get("carson_landscape")
        if carson_total in (None, 0) or (isinstance(prior, int) and isinstance(carson_total, int)
                                         and prior > 0 and carson_total < prior * 0.5):
            print(f"  WARN: Carson count {carson_total} implausibly low vs prior {prior} — "
                  f"keeping prior carson_landscape.", file=sys.stderr)
        else:
            meta["carson_landscape"] = carson_total
        meta["carson_updated"] = carson["updated"]
        lure_norm = {re.sub(r"^www\.", "", h) for h in lure_hosts}
        meta["carson_lure_overlap"] = len(lure_norm & carson["norm"])
        meta["carson_lure_observed"] = len(lure_norm)
        print(f"Carson: {meta['total_domains']} hosts; lure overlap "
              f"{meta['carson_lure_overlap']}/{meta['carson_lure_observed']} new-day lures")

    header = (
        "# Generated by scripts/analyze_clickgrab.py (baseline + append; see DECISIONS #011)\n"
        "# Sources: MHaggis ClickGrab nightly reports (raw blobs) + Carson ClickFix domain gist\n"
        "# Historical sections (payload_examples, domain_monthly, staging_domains) are frozen baseline.\n\n"
    )
    body = yaml.safe_dump(data, sort_keys=False, allow_unicode=True, default_flow_style=False, width=4096)
    TRENDS_YML.write_text(header + body, encoding="utf-8")

    print(f"\nAppended {add_reports} day(s): +{add_sites} sites, +{add_mal} malicious")
    print(f"Window now: {meta['date_range']}  | written: {TRENDS_YML}")


if __name__ == "__main__":
    main()
