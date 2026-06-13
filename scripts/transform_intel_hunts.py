#!/usr/bin/env python3
"""
transform_intel_hunts.py
Read validated hunt intel objects from de-intel-pipeline and produce
_data/masq_infra_hunts.yml for the masq-infra trends page.

Usage:
    python scripts/transform_intel_hunts.py
    python scripts/transform_intel_hunts.py --input "C:/Users/Bob/de-intel-pipeline/hunts"
    python scripts/transform_intel_hunts.py --input path/to/hunts --output _data/masq_infra_hunts.yml
"""

from __future__ import annotations

import argparse
import json
import os
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = Path.home() / "de-intel-pipeline" / "hunts"
DEFAULT_OUTPUT = REPO_ROOT / "_data" / "masq_infra_hunts.yml"

# Map threat_name keywords to display brand + delivery metadata
BRAND_HINTS: list[tuple[str, str, str, str]] = [
    ("chatgpt", "ChatGPT / OpenAI", "EXE download (JS-gated)", "loader"),
    ("claude", "Claude / Anthropic", "ClickFix paste-to-run", "loader"),
    ("codex", "OpenAI Codex CLI", "Domain squat / credential harvest", "unknown"),
    ("lmstudio", "LM Studio", "API endpoint impersonation", "unknown"),
    ("lm-studio", "LM Studio", "API endpoint impersonation", "unknown"),
    ("notion", "Notion", "Coverage survey (no desktop delivery)", "unknown"),
]

DELIVERY_KEYWORDS: dict[str, str] = {
    "T1204.002": "EXE download",
    "T1218.005": "mshta HTA",
    "T1059.004": "curl | shell",
    "T1059.001": "PowerShell",
    "T1102": "CDN staging",
    "T1553.002": "Code signing abuse",
    "T1027": "Obfuscation",
    "T1036.005": "Brand masquerade",
    "T1566.002": "Phishing / lure page",
}


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "hunt"


def infer_brand(threat_name: str) -> tuple[str, str, str]:
    lower = threat_name.lower()
    for needle, brand, delivery, payload_class in BRAND_HINTS:
        if needle in lower:
            return brand, delivery, payload_class
    return threat_name, "Unknown", "unknown"


def load_hunts(input_dir: Path) -> list[dict[str, Any]]:
    hunts: list[dict[str, Any]] = []
    for path in sorted(input_dir.glob("*.json")):
        with path.open(encoding="utf-8") as fh:
            data = json.load(fh)
        data["_source_file"] = path.name
        data["_slug"] = slugify(path.stem)
        hunts.append(data)
    return hunts


def domain_iocs(hunt: dict[str, Any]) -> list[str]:
    domains: list[str] = []
    for ioc in hunt.get("iocs", []):
        if ioc.get("ioc_type") == "domain":
            domains.append(ioc["value"])
    return domains


def mitre_ids(hunt: dict[str, Any]) -> list[str]:
    ids: list[str] = []
    for ttp in hunt.get("ttps", []):
        mid = ttp.get("mitre_id")
        if mid and mid not in ids:
            ids.append(mid)
    return ids


def delivery_methods(hunt: dict[str, Any]) -> list[str]:
    methods: list[str] = []
    for mid in mitre_ids(hunt):
        label = DELIVERY_KEYWORDS.get(mid)
        if label and label not in methods:
            methods.append(label)
    text = " ".join(
        ttp.get("value", "") for ttp in hunt.get("ttps", [])
    ).lower()
    if "bunnycdn" in text or "b-cdn.net" in text:
        if "CDN staging" not in methods:
            methods.append("CDN staging")
    if "favicon" in text and "Favicon pivot" not in methods:
        methods.append("Favicon pivot")
    if "cloudflare pages" in text and "Cloudflare Pages" not in methods:
        methods.append("Cloudflare Pages")
    if not methods:
        methods.append("Survey / squat only")
    return methods


def has_confirmed_delivery(hunt: dict[str, Any]) -> bool:
    iocs = hunt.get("iocs", [])
    has_hash = any(i.get("ioc_type") == "sha256" for i in iocs)
    has_payload_url = any(
        i.get("ioc_type") == "url"
        and any(x in i.get("value", "").lower() for x in (".exe", "/claude", "/curl/", "mshta"))
        for i in iocs
    )
    delivery_ttps = {"T1204.002", "T1218.005", "T1059.004", "T1102"}
    return has_hash or has_payload_url or bool(set(mitre_ids(hunt)) & delivery_ttps)


def build_campaign(hunt: dict[str, Any]) -> dict[str, Any]:
    brand, default_delivery, payload_class = infer_brand(hunt["threat_name"])
    window = hunt.get("date_window") or {}
    domains = domain_iocs(hunt)
    return {
        "slug": hunt["_slug"],
        "threat_name": hunt["threat_name"],
        "brand": brand,
        "collected_at": hunt.get("collected_at"),
        "date_start": window.get("start"),
        "date_end": window.get("end"),
        "sources_queried": hunt.get("sources_queried", []),
        "delivery_methods": delivery_methods(hunt),
        "payload_class": payload_class,
        "confirmed_delivery": has_confirmed_delivery(hunt),
        "ttp_count": len(hunt.get("ttps", [])),
        "ioc_count": len(hunt.get("iocs", [])),
        "infra_count": len(hunt.get("infrastructure", [])),
        "behavior_count": len(hunt.get("behaviors", [])),
        "mitre_ids": mitre_ids(hunt),
        "domains": domains[:12],
        "primary_domain": domains[0] if domains else None,
        "coverage_note": hunt.get("coverage_note"),
        "ttps": [
            {
                "value": t.get("value"),
                "mitre_id": t.get("mitre_id"),
                "note": t.get("note"),
            }
            for t in hunt.get("ttps", [])
        ],
        "iocs": [
            {
                "value": i.get("value"),
                "ioc_type": i.get("ioc_type"),
                "note": i.get("note"),
            }
            for i in hunt.get("iocs", [])
        ],
        "infrastructure": [
            {"value": f.get("value"), "note": f.get("note")}
            for f in hunt.get("infrastructure", [])
        ],
        "behaviors": [
            {"value": b.get("value"), "note": b.get("note")}
            for b in hunt.get("behaviors", [])
        ],
    }


def extract_infra_patterns(hunts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    patterns: Counter[str] = Counter()
    for hunt in hunts:
        blob = " ".join(
            f.get("value", "")
            for f in hunt.get("infrastructure", [])
            + hunt.get("behaviors", [])
            + hunt.get("ttps", [])
        ).lower()
        if "cloudflare" in blob:
            patterns["Cloudflare-fronted infrastructure"] += 1
        if "bunnycdn" in blob or "b-cdn.net" in blob:
            patterns["BunnyCDN payload staging"] += 1
        if "oracle" in blob or "as31898" in blob:
            patterns["Oracle Cloud hosting"] += 1
        if "favicon" in blob or "hash:" in blob:
            patterns["Favicon hash pivot discovery"] += 1
        if "authenticode" in blob or "code signing" in blob or "ssl.com" in blob:
            patterns["Shell-company Authenticode signing"] += 1
        if "base64" in blob:
            patterns["Base64 URL obfuscation in page JS"] += 1
        if "mshta" in blob:
            patterns["mshta HTA delivery path"] += 1
        if "tracking.php" in blob or "utm_" in blob:
            patterns["Affiliate / UTM tracking backend"] += 1
        if "localhost" in blob or "api." in blob:
            patterns["Developer API endpoint impersonation"] += 1
        if "co.com" in blob or "domain squat" in blob or "squat" in blob:
            patterns["Post-launch domain squatting"] += 1

    return [
        {"pattern": name, "hunt_count": count}
        for name, count in patterns.most_common()
    ]


def build_brand_matrix(campaigns: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_brand: dict[str, dict[str, Any]] = {}
    for camp in campaigns:
        brand = camp["brand"]
        entry = by_brand.setdefault(
            brand,
            {
                "brand": brand,
                "campaigns": [],
                "delivery_methods": set(),
                "confirmed_delivery": False,
            },
        )
        entry["campaigns"].append(camp["threat_name"])
        entry["delivery_methods"].update(camp["delivery_methods"])
        entry["confirmed_delivery"] = (
            entry["confirmed_delivery"] or camp["confirmed_delivery"]
        )

    matrix: list[dict[str, Any]] = []
    for brand, entry in sorted(by_brand.items()):
        matrix.append(
            {
                "brand": brand,
                "campaign_count": len(entry["campaigns"]),
                "campaigns": entry["campaigns"],
                "delivery_methods": sorted(entry["delivery_methods"]),
                "confirmed_delivery": entry["confirmed_delivery"],
            }
        )
    return matrix


def build_ttp_summary(hunts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counter: Counter[str] = Counter()
    for hunt in hunts:
        for ttp in hunt.get("ttps", []):
            mid = ttp.get("mitre_id")
            if mid:
                counter[mid] += 1
    return [
        {
            "mitre_id": mid,
            "label": DELIVERY_KEYWORDS.get(mid, mid),
            "count": count,
        }
        for mid, count in counter.most_common()
    ]


def build_detection_gaps(hunts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []
    for hunt in hunts:
        note = hunt.get("coverage_note")
        if not note:
            continue
        gaps.append(
            {
                "threat_name": hunt["threat_name"],
                "slug": hunt["_slug"],
                "coverage_note": note,
            }
        )
    return gaps


def build_meta(hunts: list[dict[str, Any]], campaigns: list[dict[str, Any]]) -> dict[str, Any]:
    dates: list[str] = []
    for hunt in hunts:
        window = hunt.get("date_window") or {}
        for key in ("start", "end"):
            if window.get(key):
                dates.append(window[key])
        if hunt.get("collected_at"):
            dates.append(hunt["collected_at"][:10])

    all_sources: set[str] = set()
    for hunt in hunts:
        all_sources.update(hunt.get("sources_queried", []))

    brands = sorted({c["brand"] for c in campaigns})
    confirmed = sum(1 for c in campaigns if c["confirmed_delivery"])

    return {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "hunt_count": len(hunts),
        "campaign_count": len(campaigns),
        "confirmed_delivery_count": confirmed,
        "brands_targeted": brands,
        "sources_queried": sorted(all_sources),
        "date_range": f"{min(dates)} to {max(dates)}" if dates else None,
        "pipeline": "de-intel-pipeline",
    }


def transform(input_dir: Path) -> dict[str, Any]:
    hunts = load_hunts(input_dir)
    if not hunts:
        raise SystemExit(f"No hunt JSON files found in {input_dir}")

    campaigns = [build_campaign(h) for h in hunts]
    return {
        "meta": build_meta(hunts, campaigns),
        "campaigns": campaigns,
        "brand_matrix": build_brand_matrix(campaigns),
        "ttp_summary": build_ttp_summary(hunts),
        "infra_patterns": extract_infra_patterns(hunts),
        "detection_gaps": build_detection_gaps(hunts),
    }


def write_yaml(data: dict[str, Any], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if yaml is not None:
        with output_path.open("w", encoding="utf-8") as fh:
            yaml.safe_dump(
                data,
                fh,
                sort_keys=False,
                allow_unicode=True,
                default_flow_style=False,
                width=120,
            )
    else:
        # Minimal fallback without PyYAML
        with output_path.open("w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
            fh.write("\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT,
        help=f"Hunt JSON directory (default: {DEFAULT_INPUT})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Output YAML path (default: {DEFAULT_OUTPUT})",
    )
    args = parser.parse_args()

    if not args.input.is_dir():
        raise SystemExit(f"Input directory not found: {args.input}")

    data = transform(args.input)
    write_yaml(data, args.output)
    print(
        f"Wrote {args.output} "
        f"(hunts={data['meta']['hunt_count']}, brands={len(data['meta']['brands_targeted'])})"
    )


if __name__ == "__main__":
    main()
