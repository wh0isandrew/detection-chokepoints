"""
collect_ioc_feeds.py — IOC feed collector for the masq-infra pipeline.

Queries MalwareBazaar, ThreatFox, and URLhaus for confirmed malicious payload
records, assembles unified schema records, deduplicates, and writes output to
cache/ioc_records.json.

Run standalone:
    python scripts/collect_ioc_feeds.py
"""

import hashlib
import json
import os
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import requests
import tldextract
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env")

CACHE_DIR = Path(__file__).parent.parent / "cache"
OUTPUT_PATH = CACHE_DIR / "ioc_records.json"

REQUEST_TIMEOUT = 30

# ---------------------------------------------------------------------------
# Malware family → payload_class mapping
# ---------------------------------------------------------------------------

_STEALER = {"lumma", "redline", "vidar", "stealc", "amos", "risepro", "raccoon", "metastealer"}
_C2      = {"asyncrat", "remcos", "cobaltstrike", "darkcrystal", "njrat", "agenttesl a"}
_RMM     = {"anydesk", "screenconnect", "netsupport"}
_LOADER  = {"amadey", "smokeloader", "privateloader"}

# MB tags to query (display-case preserved for the API, normalised for mapping)
MB_TAGS = [
    "Lumma", "RedLine", "Vidar", "StealC", "AsyncRAT", "Remcos", "AgentTesla",
    "CobaltStrike", "Amadey", "RisePro", "MetaStealer", "Raccoon", "AMOS",
    "DarkCrystal", "NjRAT", "SmokeLoader", "PrivateLoader", "NetSupport",
    "AnyDesk", "ScreenConnect",
]


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def classify_family(family: str) -> str:
    """Map a malware family name to its broad payload class."""
    key = family.lower().replace(" ", "").replace("-", "").replace("_", "")
    # handle common aliases
    key = key.replace("agenttesl a", "agenttesl a")  # keep whitespace-normalised key
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
    from_confirmed_feed: bool = True,
    infra_bonus: int = 0,
) -> int:
    """Compute 0–100 confidence score per schema rules.

    Payload confirmation  (0–40): +30 if sha256 known, +10 if family known
    Delivery confirmation (0–40): +30 if domain extracted, +10 if confirmed feed
    Infrastructure signal (0–20): infra_bonus clamped to 20
    """
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
    """Return the registered domain (e.g. 'example.com') from a URL, or None."""
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
    domain: str,
    source: str,
    first_seen: str | None,
    last_seen: str | None = None,
    ip: str | None = None,
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
    """Assemble a schema-conformant record with all fields present."""
    lbl = confidence_label(confidence)
    return {
        "id": record_id(domain, payload_sha256),
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
# MalwareBazaar
# ---------------------------------------------------------------------------

def collect_malwarebazaar(api_key: str) -> list[dict]:
    records: list[dict] = []
    session = requests.Session()
    session.headers.update({"Auth-Key": api_key})

    for tag in MB_TAGS:
        try:
            resp = session.post(
                "https://mb-api.abuse.ch/api/v1/",
                data={"query": "get_taginfo", "tag": tag, "limit": 100},
                timeout=REQUEST_TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            print(f"[WARN] MalwareBazaar tag={tag} failed: {exc}", file=sys.stderr)
            time.sleep(1)
            continue

        if data.get("query_status") != "ok" or not data.get("data"):
            time.sleep(1)
            continue

        for sample in data["data"]:
            sha256 = sample.get("sha256_hash")
            file_type = sample.get("file_type")
            first_seen = (sample.get("first_seen") or "")[:10]
            dl_urls = sample.get("urls_download") or []
            dl_url = dl_urls[0] if dl_urls else None
            domain = extract_domain(dl_url)
            if not domain:
                continue  # no delivery domain — skip

            payload_class = classify_family(tag)
            conf = score_record(
                has_sha256=bool(sha256),
                has_family=True,
                has_domain=True,
                from_confirmed_feed=True,
            )
            records.append(make_record(
                domain=domain,
                source="malwarebazaar",
                first_seen=first_seen,
                payload_sha256=sha256,
                payload_family=tag,
                payload_class=payload_class,
                payload_file_type=file_type,
                confidence=conf,
            ))

        time.sleep(1)

    return records


# ---------------------------------------------------------------------------
# ThreatFox
# ---------------------------------------------------------------------------

def collect_threatfox(api_key: str) -> list[dict]:
    """Query ThreatFox for IOCs from the last 30 days.

    ThreatFox does not require an auth header but the key is accepted if provided.
    """
    records: list[dict] = []
    headers = {}
    if api_key:
        headers["Auth-Key"] = api_key

    try:
        resp = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "get_iocs", "days": 30},
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        print(f"[WARN] ThreatFox query failed: {exc}", file=sys.stderr)
        return records

    time.sleep(0.5)

    iocs = data.get("data") or []
    for item in iocs:
        if (item.get("confidence_level") or 0) < 75:
            continue

        ioc_type = item.get("ioc_type", "")
        ioc_value = item.get("ioc_value", "")

        if ioc_type in ("url", "domain"):
            domain = extract_domain(ioc_value) if ioc_type == "url" else ioc_value.strip()
        else:
            # ip:port and other types have no delivery domain
            continue

        if not domain:
            continue

        family_raw = item.get("malware_printable") or item.get("malware") or ""
        payload_class = classify_family(family_raw)
        first_seen = (item.get("first_seen") or "")[:10]
        last_seen  = (item.get("last_seen")  or "")[:10]
        tags = item.get("tags") or []

        conf = score_record(
            has_sha256=False,
            has_family=bool(family_raw),
            has_domain=True,
            from_confirmed_feed=True,
        )
        records.append(make_record(
            domain=domain,
            source="threatfox",
            first_seen=first_seen,
            last_seen=last_seen,
            payload_family=family_raw or None,
            payload_class=payload_class,
            confidence=conf,
        ))

    return records


# ---------------------------------------------------------------------------
# URLhaus
# ---------------------------------------------------------------------------

def collect_urlhaus(api_key: str) -> list[dict]:
    records: list[dict] = []
    session = requests.Session()
    if api_key:
        session.headers["Auth-Key"] = api_key

    try:
        resp = session.post(
            "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/500/",
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        print(f"[WARN] URLhaus query failed: {exc}", file=sys.stderr)
        return records

    time.sleep(0.5)

    urls = data.get("urls") or []
    for item in urls:
        if item.get("url_status") not in ("online", "unknown"):
            continue

        domain = extract_domain(item.get("url"))
        if not domain:
            continue

        tags = item.get("tags") or []

        # Determine family from tags — pick the first tag that maps non-unknown
        family_raw = ""
        for t in tags:
            cls = classify_family(t)
            if cls != "unknown":
                family_raw = t
                break

        payload_class = classify_family(family_raw) if family_raw else "unknown"
        first_seen = (item.get("date_added") or "")[:10]

        # Payload hash may be embedded in url_info_from_api
        sha256 = None
        url_info = item.get("url_info_from_api") or {}
        if isinstance(url_info, dict):
            payloads = url_info.get("payloads") or []
            for p in payloads:
                if isinstance(p, dict) and p.get("response_sha256"):
                    sha256 = p["response_sha256"]
                    break

        conf = score_record(
            has_sha256=bool(sha256),
            has_family=bool(family_raw),
            has_domain=True,
            from_confirmed_feed=True,
        )
        records.append(make_record(
            domain=domain,
            source="urlhaus",
            first_seen=first_seen,
            payload_sha256=sha256,
            payload_family=family_raw or None,
            payload_class=payload_class,
            confidence=conf,
        ))

    return records


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def deduplicate(records: list[dict]) -> list[dict]:
    """Keep highest-confidence version of each record id."""
    best: dict[str, dict] = {}
    for rec in records:
        rid = rec["id"]
        if rid not in best or rec["confidence"] > best[rid]["confidence"]:
            best[rid] = rec
    return sorted(best.values(), key=lambda r: r["confidence"], reverse=True)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    mb_key = os.environ.get("MB_API_KEY", "").strip()
    tf_key = os.environ.get("THREATFOX_API_KEY", "").strip()
    uh_key = os.environ.get("URLHAUS_API_KEY", "").strip()

    mb_records: list[dict] = []
    tf_records: list[dict] = []
    uh_records: list[dict] = []

    if mb_key:
        print("[INFO] Collecting MalwareBazaar …", file=sys.stderr)
        mb_records = collect_malwarebazaar(mb_key)
    else:
        print("[WARN] MB_API_KEY not set — skipping MalwareBazaar", file=sys.stderr)

    if tf_key:
        print("[INFO] Collecting ThreatFox …", file=sys.stderr)
        tf_records = collect_threatfox(tf_key)
    else:
        print("[WARN] THREATFOX_API_KEY not set — skipping ThreatFox", file=sys.stderr)
        # ThreatFox works without a key too; attempt unauthenticated
        print("[INFO] Attempting ThreatFox without auth key …", file=sys.stderr)
        tf_records = collect_threatfox("")

    if uh_key:
        print("[INFO] Collecting URLhaus …", file=sys.stderr)
        uh_records = collect_urlhaus(uh_key)
    else:
        print("[WARN] URLHAUS_API_KEY not set — skipping URLhaus", file=sys.stderr)

    raw_total = len(mb_records) + len(tf_records) + len(uh_records)
    all_records = deduplicate(mb_records + tf_records + uh_records)
    dupes_removed = raw_total - len(all_records)

    OUTPUT_PATH.write_text(json.dumps(all_records, indent=2, ensure_ascii=False))

    print(
        f"[SUMMARY] MalwareBazaar={len(mb_records)}  "
        f"ThreatFox={len(tf_records)}  "
        f"URLhaus={len(uh_records)}  "
        f"total_raw={raw_total}  "
        f"after_dedup={len(all_records)}  "
        f"dupes_removed={dupes_removed}",
        file=sys.stderr,
    )
    print(f"[INFO] Wrote {len(all_records)} records → {OUTPUT_PATH}", file=sys.stderr)


if __name__ == "__main__":
    main()
