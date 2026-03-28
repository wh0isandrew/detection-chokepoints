"""Collection tab — runs IOC feeds, infrastructure hunts, chain reconstruction,
and AI triage scripts, then shows cache file status.

On Streamlit Cloud the filesystem is ephemeral — collected data must be pushed
back to the GitHub repo so the Jekyll/GitHub Pages site can serve it."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

import streamlit as st

from app.utils.helpers import (
    REPO_ROOT,
    github_commit_data,
    github_create_pr,
    load_records,
    run_script,
)

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
        "VALIDIN_API_KEY":   secrets.get("validin", ""),
        "VT_API_KEY":        secrets.get("vt", ""),
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

        with st.expander("Validin DNS Pivots"):
            st.caption(
                "Expands confirmed delivery domains using Validin forward DNS. "
                "Finds historical IP resolutions, co-hosted domains, and cert-linked "
                "infrastructure. Requires IOC feeds to be collected first."
            )
            ioc_records = load_records(str(_CACHE / "ioc_records.json"))
            st.write(f"{len(ioc_records)} confirmed records available for pivoting")
            cb_pdns = st.checkbox("pDNS IP history", value=True, key="cb_pdns")
            cb_cohost = st.checkbox("Co-hosted domain discovery", value=True, key="cb_cohost")
            cb_cert = st.checkbox("Certificate fingerprint pivot", value=True, key="cb_cert")
            st.caption("Limited to 100 API calls per run.")
            if st.button("Run Validin Pivots", key="btn_validin"):
                validin_env = {**env, "VALIDIN_ONLY": "true"}
                with st.spinner("Running Validin pivots …"):
                    rc, _, stderr = run_script(
                        str(_SCRIPTS / "collect_infra_hunts.py"), validin_env
                    )
                if rc == 0:
                    st.success("Validin pivots complete.")
                else:
                    st.error(f"Failed: {stderr[-2000:]}")
            _ = cb_pdns, cb_cohost, cb_cert

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

    st.divider()

    # ── Publish to GitHub ──────────────────────────────────────────────────
    st.subheader("Publish to GitHub")
    st.info(
        "Streamlit Cloud has an **ephemeral filesystem** — collected data is lost "
        "when the app restarts. Use this section to push `_data/masq_infra.json` "
        "back to the GitHub repo so the GitHub Pages site displays the latest data."
    )

    gh_token = secrets.get("github", "")
    if not gh_token:
        st.warning(
            "GH_TOKEN not configured in Streamlit secrets. "
            "Add a GitHub personal access token with `contents: write` and "
            "`pull-requests: write` permissions to enable publishing."
        )
    else:
        masq_path = REPO_ROOT / "_data" / "masq_infra.json"
        history_path = REPO_ROOT / "_data" / "masq_infra_history.json"

        has_masq = masq_path.exists()
        has_history = history_path.exists()

        if not has_masq:
            st.caption(
                "_data/masq_infra.json not found. Run the full pipeline "
                "(IOC Collection → Build Data export) first."
            )

        pub_col1, pub_col2 = st.columns(2)

        with pub_col1:
            if st.button(
                "Commit directly to main",
                key="btn_publish_direct",
                disabled=not has_masq,
            ):
                files: dict[str, str] = {}
                files["_data/masq_infra.json"] = masq_path.read_text(encoding="utf-8")
                if has_history:
                    files["_data/masq_infra_history.json"] = history_path.read_text(
                        encoding="utf-8"
                    )

                ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
                msg = f"chore: update masq-infra data [{ts}]"

                with st.spinner("Committing to GitHub …"):
                    result = github_commit_data(gh_token, files, msg)

                if result["ok"]:
                    st.success(
                        f"Committed to main ({result['sha'][:8]}). "
                        "GitHub Pages will rebuild automatically."
                    )
                else:
                    st.error(f"Commit failed: {result['error']}")

        with pub_col2:
            if st.button(
                "Open a review PR",
                key="btn_publish_pr",
                disabled=not has_masq,
            ):
                date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
                pr_branch = f"data/masq-infra-{date_str}"
                ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
                msg = f"chore: update masq-infra data [{ts}]"

                files = {}
                files["_data/masq_infra.json"] = masq_path.read_text(encoding="utf-8")
                if has_history:
                    files["_data/masq_infra_history.json"] = history_path.read_text(
                        encoding="utf-8"
                    )

                with st.spinner("Creating branch and PR …"):
                    # Create the branch via the API
                    import requests as req  # noqa: PLC0415
                    from app.utils.helpers import _get_repo_slug, _GITHUB_API  # noqa: PLC0415

                    slug = _get_repo_slug()
                    headers = {
                        "Authorization": f"token {gh_token}",
                        "Accept": "application/vnd.github+json",
                    }

                    # Get main branch SHA
                    r = req.get(
                        f"{_GITHUB_API}/repos/{slug}/git/ref/heads/main",
                        headers=headers, timeout=15,
                    )
                    if r.status_code != 200:
                        st.error(f"Cannot resolve main branch: {r.status_code}")
                    else:
                        main_sha = r.json()["object"]["sha"]

                        # Create or update the PR branch
                        r = req.post(
                            f"{_GITHUB_API}/repos/{slug}/git/refs",
                            headers=headers, timeout=15,
                            json={"ref": f"refs/heads/{pr_branch}", "sha": main_sha},
                        )
                        # 422 = branch already exists; update it instead
                        if r.status_code == 422:
                            req.patch(
                                f"{_GITHUB_API}/repos/{slug}/git/refs/heads/{pr_branch}",
                                headers=headers, timeout=15,
                                json={"sha": main_sha, "force": True},
                            )

                        # Commit data to the PR branch
                        result = github_commit_data(
                            gh_token, files, msg, branch=pr_branch,
                        )
                        if not result["ok"]:
                            st.error(f"Commit failed: {result['error']}")
                        else:
                            # Create the PR
                            pr_result = github_create_pr(
                                gh_token,
                                head_branch=pr_branch,
                                base_branch="main",
                                title=f"chore: update masq-infra data [{date_str}]",
                                body=(
                                    "Pipeline data update from Streamlit Cloud.\n\n"
                                    "Review the changes, then merge to publish "
                                    "to the live site."
                                ),
                            )
                            if pr_result["ok"]:
                                st.success(f"PR created: {pr_result['url']}")
                            else:
                                st.error(f"PR failed: {pr_result['error']}")
