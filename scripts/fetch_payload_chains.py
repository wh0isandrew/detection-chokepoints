"""
fetch_payload_chains.py — Redirect chain reconstruction and enrichment.

Reads cache/ioc_records.json and cache/infra_records.json, looks up each
domain via URLScan to reconstruct redirect chains, fetches favicon hashes,
re-scores confidence, and writes the unified enriched output to
cache/enriched_records.json.

Hard limit: max 200 URLScan result fetches per run (free-tier guard).

Run standalone:
    python scripts/fetch_payload_chains.py
"""

import base64
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import mmh3
import requests
import tldextract
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env")

CACHE_DIR   = Path(__file__).parent.parent / "cache"
IOC_PATH    = CACHE_DIR / "ioc_records.json"
INFRA_PATH  = CACHE_DIR / "infra_records.json"
OUTPUT_PATH = CACHE_DIR / "enriched_records.json"

REQUEST_TIMEOUT     = 10
FAVICON_TIMEOUT     = 5
URLSCAN_RATE_SLEEP  = 2   # seconds between URLScan API calls
FAVICON_RATE_SLEEP  = 1   # seconds between favicon fetches
MAX_URLSCAN_LOOKUPS = 200

# ---------------------------------------------------------------------------
# Payload role classification constants
# ---------------------------------------------------------------------------

PAYLOAD_MIME_TYPES = {
    "application/x-msdownload",
    "application/octet-stream",
    "application/x-executable",
    "application/vnd.microsoft.portable-executable",
}

PAYLOAD_EXTENSIONS = {".exe", ".msi", ".msix", ".zip", ".dmg", ".pkg", ".deb"}

CDN_DOMAINS = {
    "github.com",
    "githubusercontent.com",
    "raw.githubusercontent.com",
    "discord.com",
    "cdn.discordapp.com",
    "discordapp.com",
    "dropbox.com",
    "dl.dropboxusercontent.com",
}

# ---------------------------------------------------------------------------
# Shared helpers
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


def confidence_label(score: int) -> str:
    if score >= 90:
        return "confirmed"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


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


# ---------------------------------------------------------------------------
# Chain node role classification
# ---------------------------------------------------------------------------

def classify_role(url: str, mime_type: str, status_code: int | None) -> str:
    """Determine the role of a single request node in a redirect chain."""
    if status_code in (301, 302, 303, 307, 308):
        return "redirector"

    # Payload delivery by MIME type
    mt = (mime_type or "").lower()
    for pm in PAYLOAD_MIME_TYPES:
        if pm in mt:
            return "payload-delivery"

    # Payload delivery by URL extension
    path = urlparse(url).path.lower()
    for ext in PAYLOAD_EXTENSIONS:
        if path.endswith(ext):
            return "payload-delivery"

    # CDN node
    netloc = urlparse(url).netloc.lower().lstrip("www.")
    # strip port
    netloc = netloc.split(":")[0]
    if netloc in CDN_DOMAINS or any(netloc.endswith(f".{cdn}") for cdn in CDN_DOMAINS):
        return "cdn"

    return "lure"


# ---------------------------------------------------------------------------
# Favicon hash fetching
# ---------------------------------------------------------------------------

def compute_favicon_hash(domain: str) -> int | None:
    """Fetch /favicon.ico for a domain and return its MurmurHash3 int, or None."""
    try:
        resp = requests.get(
            f"https://{domain}/favicon.ico",
            timeout=FAVICON_TIMEOUT,
            allow_redirects=True,
        )
        if resp.status_code == 200 and resp.content:
            encoded = base64.encodebytes(resp.content)
            return mmh3.hash(encoded)
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# URLScan API helpers
# ---------------------------------------------------------------------------

def fetch_urlscan_result(uuid: str, session: requests.Session) -> dict | None:
    """Fetch a full URLScan result by scan UUID."""
    try:
        resp = session.get(
            f"https://urlscan.io/api/v1/result/{uuid}/",
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()
    except requests.HTTPError as exc:
        print(f"[WARN] URLScan result fetch {uuid} failed: {exc}", file=sys.stderr)
    except Exception as exc:
        print(f"[WARN] URLScan result fetch {uuid} error: {exc}", file=sys.stderr)
    return None


def search_urlscan_domain(domain: str, session: requests.Session) -> str | None:
    """Search URLScan for a domain and return the most recent scan UUID, or None."""
    query = f"page.domain:{domain} AND date:>now-30d"
    try:
        resp = session.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": query, "size": 5, "sort": "date"},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        results = resp.json().get("results") or []
        if results:
            return (results[0].get("task") or {}).get("uuid")
    except Exception as exc:
        print(f"[WARN] URLScan domain search {domain!r} failed: {exc}", file=sys.stderr)
    return None


# ---------------------------------------------------------------------------
# Chain reconstruction
# ---------------------------------------------------------------------------

def reconstruct_chain(result: dict) -> list[dict]:
    """Build an ordered chain list from a URLScan result JSON."""
    chain: list[dict] = []
    requests_data = (result.get("data") or {}).get("requests") or []

    prev_domain: str | None = None

    for entry in requests_data:
        req  = entry.get("request") or {}
        resp = entry.get("response") or {}

        url = req.get("url") or ""
        if not url:
            continue

        # Status code may be in response.response.status or response.status
        inner_resp = resp.get("response") or {}
        status_code = inner_resp.get("status") or resp.get("status")
        if isinstance(status_code, str):
            try:
                status_code = int(status_code)
            except ValueError:
                status_code = None

        mime_type = (inner_resp.get("mimeType") or "").lower()
        ip = resp.get("remoteIPAddress") or inner_resp.get("remoteIPAddress")

        domain = extract_domain(url) or urlparse(url).netloc
        role = classify_role(url, mime_type, status_code)

        # Deduplicate consecutive identical domains (collapse redirect loops)
        if domain == prev_domain and role not in ("payload-delivery", "redirector"):
            continue

        chain.append({
            "url": url,
            "domain": domain,
            "role": role,
            "status_code": status_code,
            "ip": ip or None,
        })
        prev_domain = domain

    return chain


# ---------------------------------------------------------------------------
# Re-scoring after enrichment
# ---------------------------------------------------------------------------

def rescore_record(record: dict) -> dict:
    """Re-compute confidence score using all available signals on the record."""
    has_sha256  = bool(record.get("payload_sha256"))
    has_family  = bool(record.get("payload_family"))
    has_domain  = bool(record.get("domain"))
    chain_obs   = bool(record.get("chain_observed"))
    fav_present = record.get("favicon_hash") is not None

    # Payload confirmation (0–40)
    payload_pts = (30 if has_sha256 else 0) + (10 if has_family else 0)

    # Delivery confirmation (0–40): chain gives full 40 if observed, otherwise
    # use the domain-present heuristic from the original source
    if chain_obs:
        delivery_pts = 40
    else:
        # Preserve original delivery points: confirmed feeds give 40, hunts give 30
        source = record.get("source", "")
        if source in ("malwarebazaar", "threatfox", "urlhaus"):
            delivery_pts = 40 if has_domain else 0
        else:
            delivery_pts = 30 if has_domain else 0

    # Infrastructure signal (0–20)
    infra_pts = 0
    if fav_present:
        infra_pts += 10
    if record.get("urlscan_uuid"):
        infra_pts += 5
    if record.get("vt_detected"):
        infra_pts += 5
    infra_pts = min(infra_pts, 20)

    score = min(payload_pts + delivery_pts + infra_pts, 100)
    record["confidence"] = score
    record["confidence_label"] = confidence_label(score)
    return record


# ---------------------------------------------------------------------------
# Record enrichment
# ---------------------------------------------------------------------------

def enrich_record(
    record: dict,
    session: requests.Session,
    budget: dict,
    favicon_counter: dict,
) -> dict:
    """Enrich a single record with chain data and favicon hash."""
    domain = record.get("domain")

    # ── URLScan chain reconstruction ─────────────────────────────────────
    if budget["remaining"] > 0:
        uuid = record.get("urlscan_uuid")
        result = None

        if uuid:
            result = fetch_urlscan_result(uuid, session)
            budget["remaining"] -= 1
            time.sleep(URLSCAN_RATE_SLEEP)
        elif domain:
            uuid = search_urlscan_domain(domain, session)
            budget["remaining"] -= 1
            time.sleep(URLSCAN_RATE_SLEEP)
            if uuid:
                record["urlscan_uuid"] = uuid
                result = fetch_urlscan_result(uuid, session)
                budget["remaining"] -= 1
                time.sleep(URLSCAN_RATE_SLEEP)

        if result:
            chain = reconstruct_chain(result)
            record["chain"] = chain
            record["chain_observed"] = len(chain) >= 2
            record["chain_depth"] = len(chain)

            # Try to extract a payload hash from the URLScan result if missing
            if not record.get("payload_sha256"):
                hashes = (result.get("lists") or {}).get("hashes") or []
                if hashes:
                    record["payload_sha256"] = hashes[0]

    # ── Favicon hash ──────────────────────────────────────────────────────
    if domain and record.get("favicon_hash") is None:
        fhash = compute_favicon_hash(domain)
        record["favicon_hash"] = str(fhash) if fhash is not None else None
        favicon_counter["fetched"] += 1
        time.sleep(FAVICON_RATE_SLEEP)

    # ── Re-score ──────────────────────────────────────────────────────────
    rescore_record(record)
    return record


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    urlscan_key = os.environ.get("URLSCAN_API_KEY", "").strip()
    if not urlscan_key:
        print(
            "[WARN] URLSCAN_API_KEY not set — chain reconstruction requires URLScan. "
            "Records will be written unenriched.",
            file=sys.stderr,
        )

    # Load input records
    ioc_records: list[dict] = []
    infra_records: list[dict] = []

    if IOC_PATH.exists():
        try:
            ioc_records = json.loads(IOC_PATH.read_text(encoding="utf-8"))
            print(f"[INFO] Loaded {len(ioc_records)} IOC records from {IOC_PATH}", file=sys.stderr)
        except Exception as exc:
            print(f"[WARN] Failed to load {IOC_PATH}: {exc}", file=sys.stderr)
    else:
        print(f"[WARN] {IOC_PATH} not found — run collect_ioc_feeds.py first", file=sys.stderr)

    if INFRA_PATH.exists():
        try:
            infra_records = json.loads(INFRA_PATH.read_text(encoding="utf-8"))
            print(f"[INFO] Loaded {len(infra_records)} infra records from {INFRA_PATH}", file=sys.stderr)
        except Exception as exc:
            print(f"[WARN] Failed to load {INFRA_PATH}: {exc}", file=sys.stderr)
    else:
        print(f"[WARN] {INFRA_PATH} not found — run collect_infra_hunts.py first", file=sys.stderr)

    all_records = ioc_records + infra_records
    print(f"[INFO] Processing {len(all_records)} records total …", file=sys.stderr)

    session = requests.Session()
    if urlscan_key:
        session.headers["API-Key"] = urlscan_key

    budget  = {"remaining": MAX_URLSCAN_LOOKUPS}
    favicon_counter = {"fetched": 0}

    enriched: list[dict] = []
    for i, rec in enumerate(all_records, 1):
        if i % 50 == 0:
            print(
                f"[INFO] {i}/{len(all_records)} processed "
                f"(URLScan budget remaining: {budget['remaining']})",
                file=sys.stderr,
            )
        enriched.append(enrich_record(rec, session, budget, favicon_counter))

    OUTPUT_PATH.write_text(json.dumps(enriched, indent=2, ensure_ascii=False))

    # Confidence distribution summary
    dist: dict[str, int] = {"low": 0, "medium": 0, "high": 0, "confirmed": 0}
    chains_found = sum(1 for r in enriched if r.get("chain_observed"))
    for r in enriched:
        lbl = r.get("confidence_label", "low")
        dist[lbl] = dist.get(lbl, 0) + 1

    print(
        f"[SUMMARY] records_processed={len(enriched)}  "
        f"chains_found={chains_found}  "
        f"favicons_fetched={favicon_counter['fetched']}  "
        f"urlscan_lookups_used={MAX_URLSCAN_LOOKUPS - budget['remaining']}  "
        f"confidence_dist={dist}",
        file=sys.stderr,
    )
    print(f"[INFO] Wrote {len(enriched)} enriched records → {OUTPUT_PATH}", file=sys.stderr)


if __name__ == "__main__":
    main()
