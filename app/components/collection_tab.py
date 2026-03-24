"""Collection tab — runs IOC feeds, infrastructure hunts, chain reconstruction,
and AI triage scripts, then shows cache file status."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

import streamlit as st

from app.utils.helpers import REPO_ROOT, load_records, run_script

_SCRIPTS = Path(REPO_ROOT / "scripts")
_CACHE = Path(REPO_ROOT / "cache")


def _parse_summary(stderr: str) -> dict[str, str]:
    """Parse key=value pairs from the [SUMMARY] line written to stderr."""
    for line in stderr.splitlines():
        if "[SUMMARY]" in line:
            pairs: dict[str, str] = {}
            for m in re.finditer(r"(\w+)=(\S+)", line.split("[SUMMARY]", 1)[1]):
                pairs[m.group(1)] = m.group(2)
            return pairs
    return {}


def _build_env(secrets: dict) -> dict:
    return {
        "MB_API_KEY":        secrets.get("mb", ""),
        "THREATFOX_API_KEY": secrets.get("threatfox", ""),
        "URLHAUS_API_KEY":   secrets.get("urlhaus", ""),
        "URLSCAN_API_KEY":   secrets.get("urlscan", ""),
        "SHODAN_API_KEY":    secrets.get("shodan", ""),
        "ANTHROPIC_API_KEY": secrets.get("anthropic", ""),
    }


def _file_status(rel_path: str) -> str:
    p = REPO_ROOT / rel_path
    if not p.exists():
        return "not yet generated"
    mtime = datetime.fromtimestamp(p.stat().st_mtime)
    return mtime.strftime("%Y-%m-%d %H:%M")


def render(secrets: dict) -> None:
    """Render the Collection tab."""
    st.header("Data Collection")
    st.info(
        "Runs IOC feeds and infrastructure hunts and writes results to **cache/**. "
        "Scripts communicate via environment variables — no .env file is read here."
    )

    env = _build_env(secrets)

    # ── Two columns: IOC Feeds | Infrastructure Hunts ──────────────────────
    left, right = st.columns(2)

    with left:
        st.subheader("IOC Feeds")
        cb_mb = st.checkbox("MalwareBazaar", value=True, key="cb_mb")
        cb_tf = st.checkbox("ThreatFox", value=True, key="cb_tf")
        cb_uh = st.checkbox("URLhaus", value=True, key="cb_uh")

        if st.button("Run IOC Collection", key="btn_ioc"):
            with st.spinner("Running collect_ioc_feeds.py …"):
                rc, _, stderr = run_script(
                    str(_SCRIPTS / "collect_ioc_feeds.py"), env
                )
            if rc == 0:
                summary = _parse_summary(stderr)
                count = summary.get("after_dedup", "?")
                st.success(f"IOC collection complete — **{count}** deduplicated records written.")
            else:
                st.error(f"Script exited with code {rc}.\n\n```\n{stderr[-2000:]}\n```")

    with right:
        st.subheader("Infrastructure Hunts")
        cb_shodan = st.checkbox("Shodan favicon hunts", value=True, key="cb_shodan")
        cb_urlscan = st.checkbox("URLScan filename pivots", value=True, key="cb_urlscan")

        if st.button("Run Infrastructure Hunts", key="btn_infra"):
            with st.spinner("Running collect_infra_hunts.py …"):
                rc, _, stderr = run_script(
                    str(_SCRIPTS / "collect_infra_hunts.py"), env
                )
            if rc == 0:
                summary = _parse_summary(stderr)
                count = summary.get("after_dedup", "?")
                st.success(f"Infrastructure hunt complete — **{count}** deduplicated records written.")
            else:
                st.error(f"Script exited with code {rc}.\n\n```\n{stderr[-2000:]}\n```")

    # Suppress unused-variable warnings for the checkboxes (UI state only)
    _ = cb_mb, cb_tf, cb_uh, cb_shodan, cb_urlscan

    st.divider()

    # ── Chain Reconstruction ────────────────────────────────────────────────
    st.subheader("Chain Reconstruction")
    st.write(
        "Fetches URLScan redirect chains and favicon hashes for all collected records. "
        "Rate limited to 200 URLScan lookups per run."
    )
    if st.button("Run Chain Reconstruction", key="btn_chains"):
        with st.spinner("Running fetch_payload_chains.py …"):
            rc, _, stderr = run_script(
                str(_SCRIPTS / "fetch_payload_chains.py"), env
            )
        if rc == 0:
            summary = _parse_summary(stderr)
            processed = summary.get("records_processed", "?")
            chains = summary.get("chains_found", "?")
            st.success(
                f"Chain reconstruction complete — **{processed}** records processed, "
                f"**{chains}** chains found."
            )
        else:
            st.error(f"Script exited with code {rc}.\n\n```\n{stderr[-2000:]}\n```")

    st.divider()

    # ── AI Triage ───────────────────────────────────────────────────────────
    st.subheader("AI Triage")
    st.warning(
        "Uses Anthropic API. Limited to 50 calls per run. "
        "Only runs on records where payload class is **unknown**."
    )

    enriched = load_records(str(_CACHE / "enriched_records.json"))
    unknown_count = sum(1 for r in enriched if r.get("payload_class") == "unknown")
    st.metric("Unknown payload_class records", unknown_count)

    if st.button("Run Claude Triage", key="btn_triage"):
        with st.spinner("Running claude_triage.py …"):
            rc, _, stderr = run_script(
                str(_SCRIPTS / "claude_triage.py"), env
            )
        if rc == 0:
            summary = _parse_summary(stderr)
            triaged = summary.get("records_triaged", "?")
            st.success(f"AI triage complete — **{triaged}** records classified.")
        else:
            st.error(f"Script exited with code {rc}.\n\n```\n{stderr[-2000:]}\n```")

    st.divider()

    # ── Cache File Status ───────────────────────────────────────────────────
    st.subheader("Cache File Status")
    cache_files = {
        "cache/ioc_records.json":      "IOC Records",
        "cache/infra_records.json":    "Infra Records",
        "cache/enriched_records.json": "Enriched Records",
        "cache/triaged_records.json":  "Triaged Records",
    }
    cols = st.columns(len(cache_files))
    for col, (rel_path, label) in zip(cols, cache_files.items()):
        col.metric(label, _file_status(rel_path))
