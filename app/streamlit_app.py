"""Masq Infra Review — Streamlit app entry point."""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure the repo root is on sys.path so `app.*` imports resolve correctly
# when Streamlit is invoked as `streamlit run app/streamlit_app.py`.
_REPO_ROOT = Path(__file__).parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import streamlit as st

st.set_page_config(
    page_title="Masq Infra Review",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

from app.components import (  # noqa: E402
    campaigns_tab,
    chains_tab,
    collection_tab,
    infrastructure_tab,
    payloads_tab,
    samples_tab,
)
from app.utils.helpers import REPO_ROOT, load_secrets  # noqa: E402

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown(
    """
<style>
/* Remove default main container padding */
.main .block-container {
    padding-top: 1rem !important;
    padding-bottom: 1rem !important;
}
/* Dark card / metric containers */
[data-testid="metric-container"] {
    background: #1e293b;
    border-radius: 8px;
    padding: 0.75rem 1rem;
}
/* Monospace for hash and domain values */
.mono, code {
    font-family: monospace !important;
    font-size: 0.85rem !important;
}
/* Sidebar navigation: larger font, more padding */
section[data-testid="stSidebar"] .stRadio label {
    font-size: 1rem;
    padding: 0.4rem 0.5rem;
    border-radius: 6px;
    cursor: pointer;
    transition: background 0.15s;
}
section[data-testid="stSidebar"] .stRadio label:hover {
    background: #1e293b;
}
/* Payload class badge colours */
.badge-stealer { color: #ef4444; font-weight: 600; }
.badge-c2      { color: #f97316; font-weight: 600; }
.badge-rmm     { color: #8b5cf6; font-weight: 600; }
.badge-loader  { color: #06b6d4; font-weight: 600; }
.badge-unknown { color: #6b7280; font-weight: 600; }
</style>
""",
    unsafe_allow_html=True,
)

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## **Masq Infra**")
    st.markdown(
        '<p style="color:#94a3b8; font-size:0.85rem; margin-top:-0.5rem">'
        "Payload delivery infrastructure review</p>",
        unsafe_allow_html=True,
    )
    st.divider()

    _TAB_LABELS = [
        "📡  Collection",
        "⛓  Delivery Chains",
        "☠️  Payloads",
        "🔗  Campaigns",
        "🏗  Infrastructure",
        "🗂  Samples",
    ]

    # Support cross-tab navigation (e.g. from Campaigns → Samples)
    _active = st.session_state.pop("active_tab", _TAB_LABELS[0])
    _default_idx = _TAB_LABELS.index(_active) if _active in _TAB_LABELS else 0

    selected = st.radio(
        "Navigation",
        _TAB_LABELS,
        index=_default_idx,
        label_visibility="collapsed",
    )

    st.divider()

    # Pipeline status
    _export_path = REPO_ROOT / "_data" / "masq_infra.json"
    if _export_path.exists():
        from datetime import datetime  # noqa: PLC0415
        _mtime = datetime.fromtimestamp(_export_path.stat().st_mtime)
        st.caption(f"Last export: {_mtime.strftime('%Y-%m-%d %H:%M')}")
    else:
        st.caption("Not yet exported")

    st.markdown(
        '<p style="color:#64748b; font-size:0.75rem; margin-top:1rem">'
        "Data sourced from MalwareBazaar, ThreatFox, URLhaus, URLScan, Shodan. "
        "Best-effort OSINT — free tier coverage only.</p>",
        unsafe_allow_html=True,
    )

# ── Load secrets & show API key warning ──────────────────────────────────────
secrets = load_secrets()
if not secrets.get("urlscan") or not secrets.get("mb"):
    st.warning(
        "⚠️ URLSCAN_API_KEY or MB_API_KEY not configured. Collection will be limited."
    )

# ── Route to selected tab ─────────────────────────────────────────────────────
if selected == "📡  Collection":
    collection_tab.render(secrets)
elif selected == "⛓  Delivery Chains":
    chains_tab.render()
elif selected == "☠️  Payloads":
    payloads_tab.render()
elif selected == "🔗  Campaigns":
    campaigns_tab.render()
elif selected == "🏗  Infrastructure":
    infrastructure_tab.render()
elif selected == "🗂  Samples":
    samples_tab.render()
