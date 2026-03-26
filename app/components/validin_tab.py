"""Validin Pivots tab — shows pDNS history, co-hosted domains, and cert pivots."""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import streamlit as st

from app.utils.helpers import REPO_ROOT, load_records, payload_class_color, confidence_badge

_CACHE = Path(REPO_ROOT / "cache")


def render() -> None:
    """Render the Validin Pivots tab."""
    all_records = load_records(str(_CACHE / "infra_records.json"))
    validin_records = [r for r in all_records if (r.get("source") or "").startswith("validin")]

    if not validin_records:
        st.info(
            "Validin pivots have not been run yet. Go to the Collection tab and run Validin Pivots."
        )
        return

    # ── Metric cards ──────────────────────────────────────────────────────────
    pdns_count  = sum(1 for r in validin_records if r.get("source") == "validin_pdns")
    cohost_count = sum(1 for r in validin_records if r.get("source") == "validin_cohost")
    cert_count  = sum(1 for r in validin_records if r.get("source") == "validin_cert_pivot")
    total_count = len(validin_records)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("pDNS Candidates", pdns_count)
    c2.metric("Co-hosted Domains", cohost_count)
    c3.metric("Cert Pivot Candidates", cert_count)
    c4.metric("Total Validin Records", total_count)

    # ── Three inner tabs ───────────────────────────────────────────────────────
    tab_pdns, tab_cohost, tab_cert = st.tabs([
        "🔍 pDNS History",
        "🏠 Co-hosted Domains",
        "🔐 Cert Pivot",
    ])

    with tab_pdns:
        pdns_records = [r for r in validin_records if r.get("source") == "validin_pdns"]
        if not pdns_records:
            st.info("No pDNS history found.")
        else:
            st.caption(
                "Historical IP resolutions for confirmed delivery domains. "
                "Multiple IPs indicate the operator rotated hosting."
            )
            df = pd.DataFrame(pdns_records)[["domain", "ip", "confidence", "note"]]
            st.dataframe(
                df,
                column_config={
                    "domain": st.column_config.TextColumn("domain"),
                    "ip": st.column_config.TextColumn("ip"),
                },
                use_container_width=True,
            )

    with tab_cohost:
        cohost_records = [r for r in validin_records if r.get("source") == "validin_cohost"]
        if not cohost_records:
            st.info("No co-hosted domains found.")
        else:
            st.warning(
                "Co-hosted domains are candidates only. Legitimate sites may share IPs on "
                "shared hosting. Cross-reference before treating as confirmed."
            )
            df = pd.DataFrame(cohost_records)[["domain", "ip", "confidence", "note"]]
            st.dataframe(df, use_container_width=True)

    with tab_cert:
        cert_records = [r for r in validin_records if r.get("source") == "validin_cert_pivot"]
        if not cert_records:
            st.info("No cert pivot results found.")
        else:
            df = pd.DataFrame(cert_records)[["domain", "ip", "confidence", "note"]]
            st.dataframe(
                df,
                column_config={
                    "ip": st.column_config.LinkColumn(
                        "ip",
                        display_text=".*",
                    ),
                },
                use_container_width=True,
            )

    st.divider()

    # ── VT cross-reference ────────────────────────────────────────────────────
    st.subheader("Cross-reference Candidates")
    st.caption("Verify Validin candidates against VirusTotal before promoting to confirmed.")

    all_validin_domains = sorted({r["domain"] for r in validin_records if r.get("domain")})

    selected = st.multiselect(
        "Select domains to check on VirusTotal",
        options=all_validin_domains,
    )

    if st.button("Check on VirusTotal") and selected:
        vt_key = st.secrets.get("VT_API_KEY", "")
        if not vt_key:
            st.error("VT_API_KEY not configured in Streamlit secrets.")
        else:
            import requests
            import time

            for domain in selected:
                with st.spinner(f"Checking {domain}..."):
                    r = requests.get(
                        f"https://www.virustotal.com/api/v3/domains/{domain}",
                        headers={"x-apikey": vt_key},
                        timeout=15,
                    )
                    time.sleep(0.5)
                    if r.status_code == 200:
                        data = r.json().get("data", {}).get("attributes", {})
                        malicious = data.get("last_analysis_stats", {}).get("malicious", 0)
                        reputation = data.get("reputation", 0)
                        categories = data.get("categories", {})
                        st.write(f"**{domain}**")
                        col1, col2, col3 = st.columns(3)
                        col1.metric("Malicious detections", malicious)
                        col2.metric("Reputation", reputation)
                        col3.write("Categories:")
                        col3.write(", ".join(categories.values()) or "none")
                    elif r.status_code == 404:
                        st.write(f"**{domain}** — not found on VirusTotal")
                    else:
                        st.write(f"**{domain}** — VT error {r.status_code}")
