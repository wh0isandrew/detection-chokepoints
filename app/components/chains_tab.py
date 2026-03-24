"""Delivery Chains tab — visualise observed redirect chains."""

from __future__ import annotations

from collections import Counter

import pandas as pd
import streamlit as st

from app.utils.helpers import REPO_ROOT, load_records

_CACHE = REPO_ROOT / "cache"

_ROLE_COLORS: dict[str, str] = {
    "redirector":       "#6b7280",
    "lure":             "#d97706",
    "payload-delivery": "#dc2626",
    "cdn":              "#2563eb",
}


def _chain_card(node: dict, color: str) -> str:
    domain  = node.get("domain", "?")
    role    = node.get("role", "?")
    status  = node.get("status_code")
    status_html = f'<div style="font-size:0.7rem;color:#94a3b8">{status}</div>' if status else ""
    return (
        f'<div style="background:{color}20; border:1px solid {color}; '
        f'border-radius:8px; padding:0.5rem 0.75rem; text-align:center; '
        f'min-height:60px">'
        f'<div style="color:{color}; font-weight:700; font-size:0.8rem; '
        f'text-transform:uppercase">{role}</div>'
        f'<div style="font-family:monospace; font-size:0.8rem; '
        f'word-break:break-all">{domain}</div>'
        f'{status_html}'
        f'</div>'
    )


def _render_chain_flow(chain: list[dict]) -> None:
    if not chain:
        return
    n = len(chain)
    cols = st.columns(max(1, n * 2 - 1))
    for i, node in enumerate(chain):
        color = _ROLE_COLORS.get(node.get("role", ""), "#6b7280")
        cols[i * 2].markdown(_chain_card(node, color), unsafe_allow_html=True)
        if i < n - 1:
            cols[i * 2 + 1].markdown(
                '<div style="text-align:center;padding-top:1.2rem;'
                'font-size:1.5rem;color:#94a3b8">→</div>',
                unsafe_allow_html=True,
            )


def render() -> None:
    """Render the Delivery Chains tab."""
    records = load_records(str(_CACHE / "triaged_records.json"))
    all_count = len(records)

    chain_records = [r for r in records if r.get("chain_observed", False)]

    if not chain_records:
        st.info(
            "No observed delivery chains yet. Chain data depends on URLScan coverage — "
            "many records will not have an observed chain. This is expected. "
            "Run **Chain Reconstruction** in the Collection tab to fetch available chains."
        )
        return

    pct = round(len(chain_records) / all_count * 100) if all_count else 0
    st.metric(
        "Records with observed chains",
        f"{len(chain_records)} of {all_count}",
        delta=f"{pct}%",
        delta_color="normal",
    )

    # ── Chain selector ───────────────────────────────────────────────────────
    domain_opts = [r.get("domain", "") for r in chain_records]
    sel_domain = st.selectbox("Select domain to inspect", domain_opts, key="chains_domain_sel")

    sel_record = next((r for r in chain_records if r.get("domain") == sel_domain), None)

    if sel_record:
        chain = sel_record.get("chain", [])
        st.subheader(f"Chain for {sel_domain}")
        _render_chain_flow(chain)

        with st.expander("Raw chain JSON"):
            st.json(chain)

    st.divider()

    # ── Summary table ────────────────────────────────────────────────────────
    st.subheader("Chain depth distribution")
    depth_counts: Counter = Counter()
    for r in chain_records:
        d = r.get("chain_depth", 0)
        depth_counts["5+" if d >= 5 else str(d)] += 1

    depth_df = pd.DataFrame(
        [{"Depth": k, "Count": v} for k, v in sorted(depth_counts.items())],
    )
    st.dataframe(depth_df, use_container_width=False, hide_index=True)

    cdn_count = sum(
        1 for r in chain_records
        if any(n.get("role") == "cdn" for n in r.get("chain", []))
    )
    st.metric("Chains routing through CDN", cdn_count)
