"""Raw Records tab — review collected data before export."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from app.utils.helpers import REPO_ROOT, load_records, payload_class_color

_CACHE = REPO_ROOT / "cache"


def render() -> None:
    """Render the Raw Records tab."""
    records = load_records(str(_CACHE / "triaged_records.json"))

    if not records:
        st.info("No triaged records found. Run the collection and triage pipeline first.")
        return

    st.metric("Total records", len(records))

    # ── Filters ─────────────────────────────────────────────────────────────
    with st.expander("Filters", expanded=True):
        all_classes = sorted({r.get("payload_class", "unknown") for r in records if r.get("payload_class")})
        all_lures   = sorted({r.get("lure_type", "") for r in records if r.get("lure_type")})
        all_sources = sorted({r.get("source", "") for r in records if r.get("source")})

        fc1, fc2, fc3 = st.columns(3)
        sel_class  = fc1.multiselect("Payload class", all_classes, default=all_classes)
        sel_lure   = fc2.multiselect("Lure type", all_lures, default=all_lures)
        sel_source = fc3.multiselect("Source", all_sources, default=all_sources)

        fc4, fc5 = st.columns([2, 1])
        min_conf      = fc4.slider("Minimum confidence", 0, 100, 40)
        chain_only    = fc5.checkbox("Chain observed only", value=False)

        domain_search = st.text_input("Domain search (substring)", placeholder="e.g. 'update'")

    # ── Apply Filters ────────────────────────────────────────────────────────
    filtered = [
        r for r in records
        if r.get("payload_class", "unknown") in sel_class
        and (not sel_lure or r.get("lure_type", "") in sel_lure)
        and r.get("source", "") in sel_source
        and r.get("confidence", 0) >= min_conf
        and (not chain_only or r.get("chain_observed", False))
        and (not domain_search or domain_search.lower() in r.get("domain", "").lower())
    ]
    st.caption(f"Showing **{len(filtered)}** of {len(records)} records")

    if not filtered:
        st.warning("No records match the current filters.")
        return

    # ── DataFrame ────────────────────────────────────────────────────────────
    display_cols = [
        "first_seen", "domain", "payload_family", "payload_class",
        "lure_type", "confidence", "chain_observed", "source",
    ]

    rows = []
    for r in filtered:
        rows.append({col: r.get(col) for col in display_cols})
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
        },
    )

    # ── Record Detail ────────────────────────────────────────────────────────
    with st.expander("Record detail"):
        domains = [r.get("domain", "") for r in filtered]
        sel_domain = st.selectbox("Select domain", domains, key="records_detail_domain")
        if sel_domain:
            match = next((r for r in filtered if r.get("domain") == sel_domain), None)
            if match:
                st.json(match)

    # ── Excluded Count ───────────────────────────────────────────────────────
    below = sum(1 for r in records if r.get("confidence", 0) < 40)
    if below:
        st.metric(
            "Excluded from export",
            f"{below} records",
            help="Records with confidence < 40 are not included in masq_infra.json",
            delta=f"confidence < 40",
            delta_color="inverse",
        )
