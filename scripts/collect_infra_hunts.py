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

VALIDIN_API_BASE = "https://api.validin.com/api/v1"
VALIDIN_CALL_BUDGET = 100

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
# Validin API helpers
# ---------------------------------------------------------------------------

def validin_get(endpoint: str, api_key: str) -> dict | None:
    """Make a GET request to the Validin API and return parsed JSON or None."""
    try:
        resp = requests.get(
            VALIDIN_API_BASE + endpoint,
            headers={"Authorization": api_key},
            timeout=15,
        )
        resp.raise_for_status()
        result = resp.json()
    except Exception as exc:
        print(f"[WARN] Validin API error ({endpoint}): {exc}", file=sys.stderr)
        result = None
    finally:
        time.sleep(1)
    return result


def is_cloudflare_ip(ip: str, asn_string: str | None) -> bool:
    """Return True if the IP belongs to Cloudflare based on ASN string."""
    if not asn_string:
        return False
    lower = asn_string.lower()
    return any(marker in lower for marker in ("as13335", "cloudflarenet", "cloudflare"))


def has_cs_headers(headers_string: str | None) -> bool:
    """Return True if the HTTP response headers match known Cobalt Strike patterns."""
    if not headers_string:
        return False
    has_404 = "404 Not Found" in headers_string
    has_zero_len = "Content-Length: 0" in headers_string
    has_keepalive_or_plain = (
        "Keep-Alive: timeout=10" in headers_string
        or "Content-Type: text/plain" in headers_string
    )
    return has_404 and has_zero_len and has_keepalive_or_plain


# ---------------------------------------------------------------------------
# Validin pDNS and co-host collection
# ---------------------------------------------------------------------------

def collect_validin_pdns(
    domains: list[str],
    ips: list[str],
    api_key: str,
    budget: dict,
) -> list[dict]:
    """Collect pDNS IP history for domains and co-hosted domains for IPs."""
    pdns_candidates: list[dict] = []
    cohost_candidates: list[dict] = []
    calls_used = 0

    for domain in domains:
        if budget["remaining"] <= 0:
            break
        resp = validin_get(f"/intelligence/pdns/domain/{domain}", api_key)
        budget["remaining"] -= 1
        calls_used += 1
        if not resp:
            continue
        records = resp.get("records") or resp.get("results") or []
        for entry in records:
            ip = entry.get("ip_address") or entry.get("value")
            if not ip or ip in ips:
                continue
            pdns_candidates.append({
                "domain": domain,
                "ip": ip,
                "source": "validin_pdns",
                "confidence": 30,
                "chain_observed": False,
                "first_seen": None,
                "last_seen": None,
                "payload_class": "unknown",
                "payload_family": None,
                "lure_type": "unknown",
                "note": f"Historical IP resolution for confirmed delivery domain {domain}",
            })

    for ip in ips:
        if budget["remaining"] <= 0:
            break
        resp = validin_get(f"/intelligence/pdns/ip/{ip}", api_key)
        budget["remaining"] -= 1
        calls_used += 1
        if not resp:
            continue
        records = resp.get("records") or resp.get("results") or []
        for entry in records:
            cohosted_domain = entry.get("domain") or entry.get("value")
            if not cohosted_domain or cohosted_domain in domains:
                continue
            matched = any(brand in cohosted_domain.lower() for brand in BRAND_LURES)
            if matched:
                cohost_candidates.append({
                    "domain": cohosted_domain,
                    "ip": ip,
                    "source": "validin_cohost",
                    "confidence": 25,
                    "chain_observed": False,
                    "first_seen": None,
                    "last_seen": None,
                    "payload_class": "unknown",
                    "payload_family": None,
                    "lure_type": "unknown",
                    "note": f"Co-hosted with confirmed delivery domain. Shared IP: {ip}",
                })

    print(
        f"[INFO] Validin pDNS: {len(pdns_candidates)} pDNS candidates, "
        f"{len(cohost_candidates)} co-host candidates, "
        f"{calls_used} API calls used",
        file=sys.stderr,
    )
    return pdns_candidates + cohost_candidates


def collect_validin_cert_pivot(
    domains: list[str],
    api_key: str,
    budget: dict,
) -> list[dict]:
    """Pivot on certificate fingerprints found in pDNS responses."""
    candidates: list[dict] = []
    pivots_attempted = 0
    calls_used = 0

    for domain in domains:
        if budget["remaining"] <= 0:
            break
        resp = validin_get(f"/intelligence/pdns/domain/{domain}", api_key)
        budget["remaining"] -= 1
        calls_used += 1
        if not resp:
            continue

        # Extract certificate fingerprints from response
        fingerprints: list[str] = []
        for cert in resp.get("certificates") or []:
            fp = cert.get("fingerprint") or cert.get("sha256")
            if fp:
                fingerprints.append(fp)
        for fp in resp.get("certificate_fingerprints") or []:
            if fp and fp not in fingerprints:
                fingerprints.append(fp)

        for fingerprint in fingerprints:
            if budget["remaining"] <= 0:
                break
            pivots_attempted += 1
            cert_resp = validin_get(f"/intelligence/certificate/{fingerprint}", api_key)
            budget["remaining"] -= 1
            calls_used += 1
            if not cert_resp:
                continue
            records = cert_resp.get("records") or cert_resp.get("results") or []
            for entry in records:
                pivoted_ip = entry.get("ip_address") or entry.get("value")
                if not pivoted_ip:
                    continue
                candidates.append({
                    "domain": domain,
                    "ip": pivoted_ip,
                    "source": "validin_cert_pivot",
                    "confidence": 35,
                    "chain_observed": False,
                    "first_seen": None,
                    "last_seen": None,
                    "payload_class": "unknown",
                    "payload_family": None,
                    "lure_type": "unknown",
                    "note": f"Cert fingerprint pivot from {domain}. Fingerprint: {fingerprint}",
                })

    print(
        f"[INFO] Validin cert pivot: {pivots_attempted} pivots attempted, "
        f"{len(candidates)} candidates found, "
        f"{calls_used} API calls used",
        file=sys.stderr,
    )
    return candidates


# ---------------------------------------------------------------------------
# Validin CloudFlare origin IP unmasking
# ---------------------------------------------------------------------------

def collect_validin_cf_origins(
    domains: list[str],
    api_key: str,
    budget: dict,
) -> list[dict]:
    """Unmask real origin IPs behind CloudFlare-fronted delivery domains."""
    origin_records: list[dict] = []
    cohost_records: list[dict] = []
    cf_fronted_checked = 0
    origin_ips_found = 0
    cf_certs_confirmed = 0
    suspicious_headers_found = 0
    calls_used = 0

    for domain in domains:
        if budget["remaining"] <= 0:
            break

        # Step 1 — check if domain is CF-fronted
        pdns_resp = validin_get(f"/intelligence/pdns/domain/{domain}", api_key)
        budget["remaining"] -= 1
        calls_used += 1
        if not pdns_resp:
            continue

        pdns_records = pdns_resp.get("records") or pdns_resp.get("results") or []
        resolved: list[tuple[str, str]] = []
        for entry in pdns_records:
            ip = entry.get("ip_address") or entry.get("value") or ""
            asn = entry.get("asn") or ""
            if ip:
                resolved.append((ip, asn))

        if not resolved:
            continue

        # If any resolved IP is not CloudFlare, skip — not a CF-fronted domain
        if any(not is_cloudflare_ip(ip, asn) for ip, asn in resolved):
            continue

        cf_fronted_checked += 1

        if budget["remaining"] <= 0:
            break

        # Step 2 — find non-CF IPs in host-pair connections
        pairs_resp = validin_get(f"/intelligence/host_pairs/domain/{domain}", api_key)
        budget["remaining"] -= 1
        calls_used += 1
        if not pairs_resp:
            continue

        pair_records = pairs_resp.get("records") or pairs_resp.get("results") or []
        candidate_origins: list[tuple[str, str]] = []
        for entry in pair_records:
            ip = entry.get("ip_address") or entry.get("value") or ""
            asn = entry.get("asn") or ""
            if ip and not is_cloudflare_ip(ip, asn):
                candidate_origins.append((ip, asn))

        if not candidate_origins:
            continue

        # Step 3 — verify each candidate origin IP
        for candidate_ip, candidate_asn in candidate_origins:
            if budget["remaining"] <= 0:
                break

            host_resp = validin_get(f"/intelligence/host_responses/ip/{candidate_ip}", api_key)
            budget["remaining"] -= 1
            calls_used += 1
            if not host_resp:
                continue

            host_records = host_resp.get("records") or host_resp.get("results") or []

            cf_origin_cert = False
            http_suspicious = False

            for entry in host_records:
                issuer = (
                    entry.get("certificate_issuer")
                    or entry.get("issuer")
                    or ""
                )
                if (
                    "CloudFlare, Inc." in issuer
                    and "CloudFlare Origin SSL Certificate Authority" in issuer
                ):
                    cf_origin_cert = True

                banner = (
                    entry.get("banner")
                    or entry.get("data")
                    or entry.get("headers")
                    or ""
                )
                if has_cs_headers(banner):
                    http_suspicious = True

                # Co-hosted domains on the origin IP
                cohosted = entry.get("domain") or entry.get("hostname") or ""
                if cohosted and cohosted not in domains:
                    cohost_records.append({
                        "domain": cohosted,
                        "ip": candidate_ip,
                        "source": "validin_cf_cohost",
                        "confidence": 30,
                        "chain_observed": False,
                        "payload_class": "unknown",
                        "payload_family": None,
                        "lure_type": "unknown",
                        "note": (
                            f"Shares CF origin IP {candidate_ip} with confirmed domain {domain}"
                        ),
                    })

            confidence = 25
            if cf_origin_cert:
                confidence += 15
                cf_certs_confirmed += 1
            if http_suspicious:
                confidence += 15
                suspicious_headers_found += 1

            note = (
                f"CloudFlare origin IP unmasked via Validin SNI crawl. "
                f"Domain {domain} fronted by CF. Origin at {candidate_ip}."
            )
            if cf_origin_cert:
                note += " CF Origin cert confirmed."
            if http_suspicious:
                note += " CS-like HTTP headers on origin."

            origin_records.append({
                "domain": domain,
                "ip": candidate_ip,
                "asn": candidate_asn,
                "source": "validin_cf_origin",
                "cf_masked": True,
                "cf_origin_cert": cf_origin_cert,
                "http_headers_suspicious": http_suspicious,
                "confidence": confidence,
                "chain_observed": False,
                "payload_class": "unknown",
                "payload_family": None,
                "lure_type": "unknown",
                "note": note,
            })
            origin_ips_found += 1

    print(
        f"[INFO] Validin CF origin: {cf_fronted_checked} CF-fronted domains checked, "
        f"{origin_ips_found} origin IPs found, "
        f"{cf_certs_confirmed} CF certs confirmed, "
        f"{suspicious_headers_found} suspicious headers found, "
        f"{calls_used} API calls used",
        file=sys.stderr,
    )
    return origin_records + cohost_records


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
# Validin pivot orchestrator
# ---------------------------------------------------------------------------

def collect_validin_pivots(confirmed_records: list[dict], api_key: str) -> list[dict]:
    """Run pDNS and cert-pivot collection seeded from confirmed IOC records."""
    confirmed_sources = {"malwarebazaar", "threatfox", "urlhaus"}
    domains = [
        r["domain"] for r in confirmed_records
        if r.get("domain") and r.get("source") in confirmed_sources
    ]
    ips = [
        r["ip"] for r in confirmed_records
        if r.get("ip") and r.get("source") in confirmed_sources
    ]

    budget: dict = {"remaining": VALIDIN_CALL_BUDGET}
    pdns_results = collect_validin_pdns(domains, ips, api_key, budget)
    cert_results = collect_validin_cert_pivot(domains, api_key, budget)

    all_candidates = pdns_results + cert_results

    # Deduplicate: skip domains already in confirmed records; keep highest
    # confidence when a domain appears multiple times across candidates.
    confirmed_domains = {r["domain"] for r in confirmed_records if r.get("domain")}
    best: dict[str, dict] = {}
    for cand in all_candidates:
        domain = cand.get("domain")
        if not domain or domain in confirmed_domains:
            continue
        if domain not in best or cand["confidence"] > best[domain]["confidence"]:
            best[domain] = cand

    return list(best.values())


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
    validin_key = os.environ.get("VALIDIN_API_KEY", "").strip()

    if os.environ.get("VALIDIN_ONLY") == "true":
        # Skip Shodan and URLScan, only run Validin
        # Load confirmed records from IOC cache
        ioc_path = CACHE_DIR / "ioc_records.json"
        if ioc_path.exists():
            confirmed = json.loads(ioc_path.read_text())
        else:
            confirmed = []
        all_records: list[dict] = []
        if validin_key:
            validin_results = collect_validin_pivots(confirmed, validin_key)
            all_records.extend(validin_results)
        else:
            print("[WARN] VALIDIN_API_KEY not set", file=sys.stderr)

        OUTPUT_PATH.write_text(json.dumps(all_records, indent=2, ensure_ascii=False))
        print(
            f"[SUMMARY] validin={len(all_records)}  after_dedup={len(all_records)}",
            file=sys.stderr,
        )
        print(f"[INFO] Wrote {len(all_records)} records → {OUTPUT_PATH}", file=sys.stderr)
    else:
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

        # Normal flow: add Validin after other hunts
        if validin_key:
            ioc_path = CACHE_DIR / "ioc_records.json"
            if ioc_path.exists():
                confirmed = json.loads(ioc_path.read_text())
            else:
                confirmed = []
            validin_results = collect_validin_pivots(confirmed, validin_key)
            all_records.extend(validin_results)
        else:
            print("[WARN] VALIDIN_API_KEY not set — skipping Validin pivots", file=sys.stderr)

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
