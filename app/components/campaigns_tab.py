"""Campaigns tab — review high-confidence infrastructure clusters."""

from __future__ import annotations

from pathlib import Path

import streamlit as st

from app.utils.helpers import (
    REPO_ROOT,
    confidence_badge,
    load_campaigns,
    payload_class_color,
    run_script,
)

_CACHE   = REPO_ROOT / "cache"
_SCRIPTS = REPO_ROOT / "scripts"


def _class_chip(cls: str) -> str:
    color = payload_class_color(cls)
    return (
        f'<span style="background:{color}33; color:{color}; '
        f'border:1px solid {color}; border-radius:4px; '
        f'padding:1px 6px; font-size:0.75rem; margin-right:4px">'
        f'{cls}</span>'
    )


def _lure_chip(lure: str) -> str:
    return (
        f'<span style="background:#374151; color:#d1d5db; '
        f'border-radius:4px; padding:1px 6px; '
        f'font-size:0.75rem; margin-right:4px">'
        f'{lure}</span>'
    )


def render() -> None:
    """Render the Campaigns tab."""
    campaigns     = load_campaigns(str(_CACHE / "campaigns.json"))
    low_conf_cams = load_campaigns(str(_CACHE / "low_confidence_campaigns.json"))

    low_conf_count = len(low_conf_cams)

    if not campaigns:
        st.info(
            "No campaigns found. Clustering requires at least one hard signal "
            "(shared favicon, shared IP, shared payload hash, or shared certificate "
            "pattern) across two or more domains. Run the collection and chain "
            "reconstruction pipeline first, then run `cluster_campaigns.py`."
        )
        if low_conf_count:
            st.caption(
                f"{low_conf_count} low-confidence clusters are in "
                f"cache/low_confidence_campaigns.json for manual review."
            )
        return

    st.info(
        "Only campaigns with a confirmed hard signal (shared favicon, shared IP, "
        "shared payload hash, or shared certificate pattern) and confidence score ≥ 70 "
        "are shown. "
        f"**{low_conf_count}** additional cluster(s) below threshold are available in "
        "`cache/low_confidence_campaigns.json` for manual review."
    )

    # ── Campaign cards ────────────────────────────────────────────────────────
    for camp in campaigns:
        with st.container():
            signal_label = camp.get("hard_signal", "").replace("_", " ").title()
            signal_val   = str(camp.get("hard_signal_value", ""))[:20]
            st.markdown(f"### {signal_label}: `{signal_val}`")

            col1, col2, col3 = st.columns(3)
            col1.metric("Domains", camp.get("domain_count", 0))
            col2.metric("Confidence", camp.get("confidence", 0))
            col3.metric("Date range",
                        f"{camp.get('first_seen', '?')} — {camp.get('last_seen', '?')}")

            st.markdown(
                confidence_badge(camp.get("confidence", 0)),
                unsafe_allow_html=True,
            )

            classes_html = "".join(_class_chip(c) for c in camp.get("payload_classes", []))
            lures_html   = "".join(_lure_chip(l) for l in camp.get("lure_types", []))
            if classes_html or lures_html:
                st.markdown(classes_html + lures_html, unsafe_allow_html=True)

            narrative = camp.get("narrative")
            if narrative:
                st.markdown(f"*{narrative}*")

            with st.expander("Show domains"):
                for d in camp.get("domains", []):
                    st.code(d, language=None)

            with st.expander("Show records"):
                st.write(
                    "Click below to navigate to the Samples tab filtered to these domains."
                )
                if st.button(
                    "Open in Samples tab",
                    key=f"open_samples_{camp.get('id', signal_val)}",
                ):
                    st.session_state["records_filter_domains"] = camp.get("domains", [])
                    st.session_state["active_tab"] = "🗂  Samples"
                    st.rerun()

            st.divider()

    # ── Generate Narratives button ────────────────────────────────────────────
    st.subheader("AI Narrative Generation")
    st.caption("Requires ANTHROPIC_API_KEY. Generates analyst summaries for each campaign.")

    anthropic_key = st.session_state.get("_secrets_anthropic", "")
    if st.button("Generate Narratives", key="btn_gen_narratives"):
        from app.utils.helpers import load_secrets  # noqa: PLC0415
        secrets = load_secrets()
        env = {"ANTHROPIC_API_KEY": secrets.get("anthropic", "")}
        with st.spinner("Running cluster_campaigns.py --narratives …"):
            rc, _, stderr = run_script(
                str(_SCRIPTS / "cluster_campaigns.py"),
                {**env, "NARRATIVES": "1"},
            )
        if rc == 0:
            st.success("Narratives generated. Reload the page to see updated text.")
        else:
            st.error(f"Script exited with code {rc}.\n\n```\n{stderr[-2000:]}\n```")
