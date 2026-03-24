"""Samples tab — full record table with export controls."""

from __future__ import annotations

import json

import pandas as pd
import streamlit as st

from app.utils.helpers import REPO_ROOT, load_records, run_script

_CACHE   = REPO_ROOT / "cache"
_DATA    = REPO_ROOT / "_data"
_SCRIPTS = REPO_ROOT / "scripts"


def render() -> None:
    """Render the Samples tab."""
    records = load_records(str(_CACHE / "triaged_records.json"))
    records = [r for r in records if r.get("confidence", 0) >= 40]

    # Apply domain filter from campaigns tab cross-navigation
    filter_domains: list[str] | None = st.session_state.pop("records_filter_domains", None)
    if filter_domains:
        records = [r for r in records if r.get("domain") in filter_domains]
        st.info(
            f"Filtered to **{len(records)}** records matching "
            f"{len(filter_domains)} domain(s) from Campaigns tab."
        )

    if not records:
        st.info("No records with confidence ≥ 40 found. Run the full pipeline first.")
        return

    st.metric("Records (confidence ≥ 40)", len(records))

    # ── Build display dataframe ──────────────────────────────────────────────
    rows = []
    for r in records:
        sha256 = r.get("payload_sha256")
        uuid   = r.get("urlscan_uuid")
        rows.append({
            "first_seen":      r.get("first_seen"),
            "domain":          r.get("domain", ""),
            "payload_sha256":  (sha256[:16] + "…") if sha256 else "",
            "payload_family":  r.get("payload_family", ""),
            "payload_class":   r.get("payload_class", "unknown"),
            "lure_type":       r.get("lure_type", ""),
            "chain_observed":  r.get("chain_observed", False),
            "confidence":      r.get("confidence", 0),
            "source":          r.get("source", ""),
            "urlscan_url": (
                f"https://urlscan.io/result/{uuid}/" if uuid else None
            ),
        })

    df = pd.DataFrame(rows)

    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "first_seen":     st.column_config.DateColumn("First Seen", format="YYYY-MM-DD"),
            "confidence":     st.column_config.ProgressColumn(
                                  "Confidence", min_value=0, max_value=100, format="%d"
                              ),
            "chain_observed": st.column_config.CheckboxColumn("Chain"),
            "urlscan_url":    st.column_config.LinkColumn(
                                  "URLScan", display_text="🔗 View"
                              ),
            "payload_sha256": st.column_config.TextColumn("SHA256 (prefix)"),
        },
    )

    # Warn on rows without chain observation
    no_chain = sum(1 for r in records if not r.get("chain_observed", False))
    if no_chain:
        st.caption(
            f"⚠️ {no_chain} record(s) have no observed delivery chain — "
            "the payload is confirmed malicious but URLScan coverage is unavailable."
        )

    st.divider()

    # ── Export controls ──────────────────────────────────────────────────────
    st.subheader("Export")

    ecol1, ecol2 = st.columns(2)

    with ecol1:
        if st.button("Export masq_infra.json", key="btn_export_masq"):
            from app.utils.helpers import load_secrets  # noqa: PLC0415
            secrets = load_secrets()
            env = {"ANTHROPIC_API_KEY": secrets.get("anthropic", "")}
            with st.spinner("Running build_data.py …"):
                rc, _, stderr = run_script(str(_SCRIPTS / "build_data.py"), env)
            if rc == 0:
                out_path = _DATA / "masq_infra.json"
                if out_path.exists():
                    data_bytes = out_path.read_bytes()
                    try:
                        built = json.loads(data_bytes)
                        rec_count  = len(built.get("records", []))
                        camp_count = len(built.get("campaigns", []))
                    except Exception:
                        rec_count = camp_count = "?"
                    st.success(
                        f"Build complete — **{rec_count}** records, "
                        f"**{camp_count}** campaigns."
                    )
                    st.download_button(
                        label="⬇ Download masq_infra.json",
                        data=data_bytes,
                        file_name="masq_infra.json",
                        mime="application/json",
                        key="dl_masq_infra",
                    )
                else:
                    st.warning("Build succeeded but output file not found.")
            else:
                st.error(f"Build failed (exit {rc}).\n\n```\n{stderr[-2000:]}\n```")

    with ecol2:
        raw_path = _CACHE / "triaged_records.json"
        if raw_path.exists():
            st.download_button(
                label="⬇ Download raw records (JSON)",
                data=raw_path.read_bytes(),
                file_name="triaged_records.json",
                mime="application/json",
                key="dl_raw_records",
            )
        else:
            st.caption("cache/triaged_records.json not yet generated.")
