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
    tab_pdns, tab_cohost, tab_cert, tab_cf = st.tabs([
        "🔍 pDNS History",
        "🏠 Co-hosted Domains",
        "🔐 Cert Pivot",
        "☁️ CF Origin",
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

    with tab_cf:
        cf_records = [
            r for r in validin_records
            if r.get("source") in ("validin_cf_origin", "validin_cf_cohost")
        ]
        if not cf_records:
            st.info(
                "No CloudFlare origin IPs found. CF origin unmasking only applies to "
                "domains that resolve exclusively to CloudFlare IPs."
            )
        else:
            st.caption(
                "Validin uses SNI-aware crawling to connect directly to virtual hosts on "
                "their assigned IPv4 addresses. When an origin server is publicly reachable, "
                "Validin can reveal the real IP behind a CloudFlare-fronted domain via the "
                "CloudFlare Origin certificate installed on that server."
            )

            origin_records = [r for r in cf_records if r.get("source") == "validin_cf_origin"]
            cohost_cf_records = [r for r in cf_records if r.get("source") == "validin_cf_cohost"]

            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Origin IPs unmasked", len(origin_records))
            m2.metric("CF Origin cert confirmed", sum(1 for r in origin_records if r.get("cf_origin_cert")))
            m3.metric("Suspicious headers on origin", sum(1 for r in origin_records if r.get("http_headers_suspicious")))
            m4.metric("Co-hosted on origin IP", len(cohost_cf_records))

            if origin_records:
                _cols = ["domain", "ip", "asn", "cf_origin_cert", "http_headers_suspicious", "confidence", "note"]
                df_origin = pd.DataFrame(origin_records).reindex(columns=_cols)

                def _highlight(row: pd.Series) -> list[str]:
                    conf = row.get("confidence", 0)
                    if conf >= 55:
                        return ["background-color: #ef444415"] * len(row)
                    if conf >= 40:
                        return ["background-color: #f5a62315"] * len(row)
                    return [""] * len(row)

                st.dataframe(
                    df_origin.style.apply(_highlight, axis=1),
                    column_config={
                        "ip": st.column_config.LinkColumn(
                            "Validin",
                            display_text=".*",
                        ),
                    },
                    use_container_width=True,
                )

            st.subheader("Co-hosted on Origin IP")
            if cohost_cf_records:
                df_cohost = pd.DataFrame(cohost_cf_records)[["domain", "ip", "note"]]
                st.dataframe(df_cohost, use_container_width=True)
                st.caption(
                    "These domains share the same origin IP. They may be operated by the same "
                    "actor or hosted on shared infrastructure. Verify each independently."
                )

            st.subheader("Confirm with Shodan")
            st.caption(
                "Fingerprint the origin IP directly to check for C2 characteristics. "
                "Combines Validin CF unmasking with Shodan HTTP header and JARM analysis."
            )

            origin_ips = sorted({r["ip"] for r in origin_records if r.get("ip")})
            selected_ip = st.selectbox(
                "Select origin IP to fingerprint",
                options=["— select —"] + origin_ips,
            )

            if st.button("Check on Shodan") and selected_ip != "— select —":
                shodan_key = st.secrets.get("SHODAN_API_KEY", "")
                if not shodan_key:
                    st.error("SHODAN_API_KEY not configured.")
                else:
                    import shodan as shodan_api

                    with st.spinner(f"Querying Shodan for {selected_ip}..."):
                        try:
                            api = shodan_api.Shodan(shodan_key)
                            host = api.host(selected_ip)
                            st.write(f"**Org:** {host.get('org')}")
                            st.write(f"**ASN:** {host.get('asn')}")
                            st.write(f"**Open ports:** {host.get('ports')}")
                            for svc in host.get("data", []):
                                port = svc.get("port")
                                banner = svc.get("data", "")
                                transport = svc.get("transport", "tcp")
                                st.write(f"**Port {port}/{transport}**")
                                if banner:
                                    st.code(banner[:500], language=None)
                                    # Inline CS header check (mirrors has_cs_headers logic)
                                    _has_404 = "404 Not Found" in banner
                                    _has_zero = "Content-Length: 0" in banner
                                    _has_ka = (
                                        "Keep-Alive: timeout=10" in banner
                                        or "Content-Type: text/plain" in banner
                                    )
                                    if _has_404 and _has_zero and _has_ka:
                                        st.error("⚠️ CS-like HTTP headers detected on this origin IP")
                                ssl = svc.get("ssl", {})
                                jarm = ssl.get("jarm", "")
                                if jarm:
                                    st.write(f"JARM: `{jarm}`")
                                    _CS_JARMS = [
                                        "2ad2ad16d2ad2ad00042d42d00042ddb04deffa1705e2edc44cae1ed24a4da",
                                        "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1",
                                    ]
                                    if any(jarm.startswith(j[:20]) for j in _CS_JARMS):
                                        st.error("⚠️ JARM matches known Cobalt Strike signature")
                        except Exception as e:
                            st.error(f"Shodan error: {e}")

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
