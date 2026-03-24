"""
collect_infra_hunts.py — Proactive infrastructure hunting for the masq-infra pipeline.

Runs Shodan favicon and open-directory queries plus URLScan filename/title pivots
to find delivery infrastructure that may not yet appear in IOC feeds.
Writes output to cache/infra_records.json.

All records produced here get chain_observed: false initially and lower confidence
scores than IOC feed records since they are unconfirmed candidates.

Run standalone:
    python scripts/collect_infra_hunts.py
"""

import hashlib
import json
import os
import sys
import time
from pathlib import Path

import requests
import tldextract
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env")

CACHE_DIR = Path(__file__).parent.parent / "cache"
OUTPUT_PATH = CACHE_DIR / "infra_records.json"

REQUEST_TIMEOUT = 30

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Favicon hashes → brand names (known brand impersonation indicators)
FAVICON_HASHES: dict[int, str] = {
    -469815234:  "Telegram",
    991727625:   "7-Zip",
    9732861:     "VLC",
    -1899664115: "Notepad++",
    803527991:   "GoPhish",
    -127886975:  "Metasploit",
}

BRAND_LURES = [
    "7-zip", "winrar", "vlc", "discord", "telegram",
    "chatgpt", "zoom", "nordvpn", "metamask", "ledger", "exodus",
]

# Shodan open-directory queries
SHODAN_OPEN_DIR_QUERIES = [
    'title:"Index of /" ".exe"',
    'title:"Directory Listing" ".exe"',
    'title:"Index of /" ".msi"',
]

# ---------------------------------------------------------------------------
# Shared helpers (mirrored from collect_ioc_feeds.py for standalone use)
# ---------------------------------------------------------------------------

_STEALER = {"lumma", "redline", "vidar", "stealc", "amos", "risepro", "raccoon", "metastealer"}
_C2      = {"asyncrat", "remcos", "cobaltstrike", "darkcrystal", "njrat", "agenttesl a"}
_RMM     = {"anydesk", "screenconnect", "netsupport"}
_LOADER  = {"amadey", "smokeloader", "privateloader"}


def classify_family(family: str) -> str:
    key = family.lower().replace(" ", "").replace("-", "").replace("_", "")
    if key in _STEALER:
        return "stealer"
    if key in _C2:
        return "c2"
    if key in _RMM:
        return "rmm"
    if key in _LOADER:
        return "loader"
    return "unknown"


def score_record(
    has_sha256: bool,
    has_family: bool,
    has_domain: bool,
    from_confirmed_feed: bool = False,
    infra_bonus: int = 0,
) -> int:
    payload_pts  = (30 if has_sha256 else 0) + (10 if has_family else 0)
    delivery_pts = (30 if has_domain else 0) + (10 if from_confirmed_feed else 0)
    infra_pts    = min(infra_bonus, 20)
    return min(payload_pts + delivery_pts + infra_pts, 100)


def confidence_label(score: int) -> str:
    if score >= 90:
        return "confirmed"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def record_id(domain: str, sha256: str | None) -> str:
    return hashlib.sha256(f"{domain}{sha256 or ''}".encode()).hexdigest()


def extract_domain(url: str | None) -> str | None:
    if not url:
        return None
    try:
        ext = tldextract.extract(url)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
    except Exception:
        pass
    return None


def make_record(
    *,
    domain: str | None,
    ip: str | None = None,
    source: str,
    first_seen: str | None,
    last_seen: str | None = None,
    asn: str | None = None,
    payload_sha256: str | None = None,
    payload_family: str | None = None,
    payload_class: str = "unknown",
    payload_file_type: str | None = None,
    lure_brand: str | None = None,
    lure_type: str | None = None,
    favicon_hash: str | None = None,
    urlscan_uuid: str | None = None,
    vt_detected: bool | None = None,
    vt_detection_count: int | None = None,
    cert_cn: str | None = None,
    cert_issuer: str | None = None,
    cert_self_signed: bool | None = None,
    confidence: int = 0,
    triage_note: str | None = None,
    triage_source: str = "automated",
) -> dict:
    key = domain or ip or ""
    lbl = confidence_label(confidence)
    return {
        "id": record_id(key, payload_sha256),
        "domain": domain,
        "ip": ip,
        "asn": asn,
        "first_seen": first_seen or "",
        "last_seen": last_seen or first_seen or "",
        "source": source,
        "payload_sha256": payload_sha256,
        "payload_family": payload_family,
        "payload_class": payload_class,
        "payload_file_type": payload_file_type,
        "lure_brand": lure_brand,
        "lure_type": lure_type,
        "chain_observed": False,
        "chain_depth": 0,
        "chain": [],
        "cert_cn": cert_cn,
        "cert_issuer": cert_issuer,
        "cert_self_signed": cert_self_signed,
        "favicon_hash": favicon_hash,
        "urlscan_uuid": urlscan_uuid,
        "vt_detected": vt_detected,
        "vt_detection_count": vt_detection_count,
        "confidence": confidence,
        "confidence_label": lbl,
        "triage_note": triage_note,
        "triage_source": triage_source,
    }


# ---------------------------------------------------------------------------
# Shodan hunting
# ---------------------------------------------------------------------------

def hunt_shodan_favicons(api_key: str) -> list[dict]:
    try:
        import shodan  # type: ignore
    except ImportError:
        print("[WARN] shodan package not installed — skipping Shodan favicon hunt", file=sys.stderr)
        return []

    api = shodan.Shodan(api_key)
    records: list[dict] = []

    for fav_hash, brand in FAVICON_HASHES.items():
        query = f"http.favicon.hash:{fav_hash}"
        try:
            results = api.search(query)
        except shodan.APIError as exc:
            print(f"[WARN] Shodan favicon query failed ({brand}): {exc}", file=sys.stderr)
            time.sleep(1)
            continue
        except Exception as exc:
            print(f"[WARN] Shodan favicon query error ({brand}): {exc}", file=sys.stderr)
            time.sleep(1)
            continue

        for match in results.get("matches", []):
            ip = match.get("ip_str")
            hostnames = match.get("hostnames") or []
            domain = hostnames[0] if hostnames else None
            key = domain or ip
            if not key:
                continue

            port = match.get("port")
            org  = match.get("org")
            asn  = match.get("asn")
            ts   = (match.get("timestamp") or "")[:10]

            conf = score_record(
                has_sha256=False,
                has_family=False,
                has_domain=bool(domain),
                from_confirmed_feed=False,
                infra_bonus=15,
            )
            records.append(make_record(
                domain=domain,
                ip=ip,
                asn=asn,
                source="shodan_favicon",
                first_seen=ts,
                lure_brand=brand,
                confidence=conf,
                triage_note=f"Favicon hash {fav_hash} ({brand}) on port {port}, org={org}",
            ))

        time.sleep(1)

    return records


def hunt_shodan_open_dirs(api_key: str) -> list[dict]:
    try:
        import shodan  # type: ignore
    except ImportError:
        print("[WARN] shodan package not installed — skipping Shodan open-dir hunt", file=sys.stderr)
        return []

    api = shodan.Shodan(api_key)
    records: list[dict] = []

    for query in SHODAN_OPEN_DIR_QUERIES:
        try:
            results = api.search(query)
        except shodan.APIError as exc:
            print(f"[WARN] Shodan open-dir query failed: {exc}", file=sys.stderr)
            time.sleep(1)
            continue
        except Exception as exc:
            print(f"[WARN] Shodan open-dir query error: {exc}", file=sys.stderr)
            time.sleep(1)
            continue

        for match in results.get("matches", []):
            ip = match.get("ip_str")
            hostnames = match.get("hostnames") or []
            domain = hostnames[0] if hostnames else None
            key = domain or ip
            if not key:
                continue

            port = match.get("port")
            asn  = match.get("asn")
            ts   = (match.get("timestamp") or "")[:10]

            conf = score_record(
                has_sha256=False,
                has_family=False,
                has_domain=bool(domain),
                from_confirmed_feed=False,
                infra_bonus=5,
            )
            records.append(make_record(
                domain=domain,
                ip=ip,
                asn=asn,
                source="shodan_open_dir",
                first_seen=ts,
                confidence=conf,
                triage_note=f"Open directory listing on port {port} (query: {query!r})",
            ))

        time.sleep(1)

    return records


# ---------------------------------------------------------------------------
# URLScan hunting
# ---------------------------------------------------------------------------

def _urlscan_search(session: requests.Session, query: str) -> list[dict]:
    """Run a single URLScan search and return result hits."""
    try:
        resp = session.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": query, "size": 100},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json().get("results") or []
    except Exception as exc:
        print(f"[WARN] URLScan search failed (q={query!r}): {exc}", file=sys.stderr)
        return []


def hunt_urlscan(api_key: str) -> list[dict]:
    session = requests.Session()
    session.headers["API-Key"] = api_key

    records: list[dict] = []

    # Per-brand filename pivots
    for brand in BRAND_LURES:
        for ext in ("exe", "msi"):
            query = f"filename:*.{ext} AND page.domain:*{brand}* AND date:>now-30d"
            hits = _urlscan_search(session, query)
            for hit in hits:
                rec = _urlscan_hit_to_record(hit, source="urlscan_filename")
                if rec:
                    records.append(rec)
            time.sleep(2)

    # Broad download-page title pivot
    brand_group = "|".join(BRAND_LURES)
    broad_query = (
        f"page.title:*download* AND "
        f"page.domain:*({brand_group})* AND date:>now-30d"
    )
    hits = _urlscan_search(session, broad_query)
    for hit in hits:
        rec = _urlscan_hit_to_record(hit, source="urlscan_filename")
        if rec:
            records.append(rec)
    time.sleep(2)

    return records


def _urlscan_hit_to_record(hit: dict, source: str) -> dict | None:
    page = hit.get("page") or {}
    task = hit.get("task") or {}
    verdicts = hit.get("verdicts") or {}
    overall = verdicts.get("overall") or {}
    lists = hit.get("lists") or {}

    domain = page.get("domain")
    if not domain:
        return None

    ip            = page.get("ip")
    asn           = page.get("asn")
    urlscan_uuid  = task.get("uuid")
    first_seen    = (task.get("time") or "")[:10]
    vt_malicious  = bool(overall.get("malicious"))
    hashes        = lists.get("hashes") or []
    sha256        = hashes[0] if hashes else None

    # Confidence: infra hunt baseline 20, +10 if verdict malicious, +10 if sha256
    infra_bonus = 20
    extra = (10 if vt_malicious else 0) + (10 if sha256 else 0)
    conf = min(
        score_record(
            has_sha256=bool(sha256),
            has_family=False,
            has_domain=True,
            from_confirmed_feed=False,
            infra_bonus=infra_bonus,
        ) + extra,
        100,
    )

    return make_record(
        domain=domain,
        ip=ip,
        asn=asn,
        source=source,
        first_seen=first_seen,
        payload_sha256=sha256,
        urlscan_uuid=urlscan_uuid,
        vt_detected=vt_malicious,
        confidence=conf,
    )


# ---------------------------------------------------------------------------
# Deduplication (by domain)
# ---------------------------------------------------------------------------

def deduplicate(records: list[dict]) -> list[dict]:
    """Keep highest-confidence record per domain (or per IP if no domain)."""
    best: dict[str, dict] = {}
    for rec in records:
        key = rec.get("domain") or rec.get("ip") or rec["id"]
        if key not in best or rec["confidence"] > best[key]["confidence"]:
            best[key] = rec
    return sorted(best.values(), key=lambda r: r["confidence"], reverse=True)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    shodan_key  = os.environ.get("SHODAN_API_KEY",  "").strip()
    urlscan_key = os.environ.get("URLSCAN_API_KEY", "").strip()

    shodan_fav:  list[dict] = []
    shodan_dirs: list[dict] = []
    urlscan_recs: list[dict] = []

    if shodan_key:
        print("[INFO] Running Shodan favicon hunt …", file=sys.stderr)
        shodan_fav = hunt_shodan_favicons(shodan_key)
        print("[INFO] Running Shodan open-dir hunt …", file=sys.stderr)
        shodan_dirs = hunt_shodan_open_dirs(shodan_key)
    else:
        print("[WARN] SHODAN_API_KEY not set — skipping Shodan hunts", file=sys.stderr)

    if urlscan_key:
        print("[INFO] Running URLScan hunts …", file=sys.stderr)
        urlscan_recs = hunt_urlscan(urlscan_key)
    else:
        print("[WARN] URLSCAN_API_KEY not set — skipping URLScan hunts", file=sys.stderr)

    raw_total = len(shodan_fav) + len(shodan_dirs) + len(urlscan_recs)
    all_records = deduplicate(shodan_fav + shodan_dirs + urlscan_recs)
    dupes_removed = raw_total - len(all_records)

    OUTPUT_PATH.write_text(json.dumps(all_records, indent=2, ensure_ascii=False))

    print(
        f"[SUMMARY] shodan_favicon={len(shodan_fav)}  "
        f"shodan_open_dir={len(shodan_dirs)}  "
        f"urlscan={len(urlscan_recs)}  "
        f"total_raw={raw_total}  "
        f"after_dedup={len(all_records)}  "
        f"dupes_removed={dupes_removed}",
        file=sys.stderr,
    )
    print(f"[INFO] Wrote {len(all_records)} records → {OUTPUT_PATH}", file=sys.stderr)


if __name__ == "__main__":
    main()
