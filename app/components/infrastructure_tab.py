"""Infrastructure tab — delivery domains, favicon clusters, ASN distribution."""

from __future__ import annotations

from collections import Counter, defaultdict

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from app.utils.helpers import REPO_ROOT, load_records

_CACHE = REPO_ROOT / "cache"

_CDN_KEYWORDS = ["cloudflare", "amazon", "google", "fastly", "akamai"]


def _is_cdn_asn(asn: str) -> bool:
    if not asn:
        return False
    asn_lower = asn.lower()
    return any(kw in asn_lower for kw in _CDN_KEYWORDS)


def render() -> None:
    """Render the Infrastructure tab."""
    records = load_records(str(_CACHE / "triaged_records.json"))

    if not records:
        st.info("No triaged records found. Run the collection pipeline first.")
        return

    # ── Section 1: Confirmed Delivery Domains ────────────────────────────────
    st.subheader("Confirmed Delivery Domains")

    # Group by domain, take first record's infra fields
    domain_map: dict[str, dict] = {}
    domain_count: Counter = Counter()
    for r in records:
        dom = r.get("domain", "")
        domain_count[dom] += 1
        if dom not in domain_map:
            domain_map[dom] = r

    all_asns = sorted({
        r.get("asn", "") for r in records if r.get("asn")
    })
    sel_asn = st.selectbox(
        "Filter by ASN", ["All ASNs"] + all_asns, key="infra_asn_filter"
    )

    rows = []
    for dom, r in domain_map.items():
        asn = r.get("asn", "")
        if sel_asn != "All ASNs" and asn != sel_asn:
            continue
        rows.append({
            "domain":          dom,
            "ip":              r.get("ip", ""),
            "asn":             asn,
            "favicon_hash":    r.get("favicon_hash", ""),
            "cert_issuer":     r.get("cert_issuer", ""),
            "cert_self_signed": r.get("cert_self_signed"),
            "record_count":    domain_count[dom],
        })

    if rows:
        dom_df = pd.DataFrame(rows)
        st.dataframe(
            dom_df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "favicon_hash": st.column_config.TextColumn("Favicon Hash"),
                "record_count": st.column_config.NumberColumn("# Records"),
                "cert_self_signed": st.column_config.CheckboxColumn("Self-Signed"),
            },
        )
    else:
        st.caption("No records match the current ASN filter.")

    st.divider()

    # ── Section 2: Favicon Clusters ──────────────────────────────────────────
    st.subheader("Favicon Clusters")

    favicon_domains: dict[str, list[str]] = defaultdict(list)
    for r in records:
        fh = r.get("favicon_hash")
        if fh:
            dom = r.get("domain", "")
            if dom not in favicon_domains[fh]:
                favicon_domains[fh].append(dom)

    clusters = {fh: doms for fh, doms in favicon_domains.items() if len(doms) >= 2}

    if not clusters:
        st.caption("No favicon clusters found (need 2+ domains sharing a favicon hash).")
    else:
        for fh, doms in sorted(clusters.items(), key=lambda x: len(x[1]), reverse=True):
            shodan_url = f"https://www.shodan.io/search?query=http.favicon.hash:{fh}"
            with st.expander(
                f"`{fh}` — {len(doms)} domain(s)  [🔍 Shodan]({shodan_url})",
                expanded=False,
            ):
                st.markdown(f"[View on Shodan]({shodan_url})")
                for d in doms[:20]:
                    st.code(d, language=None)
                if len(doms) > 20:
                    st.caption(f"… and {len(doms) - 20} more")

    st.divider()

    # ── Section 3: ASN Distribution ─────────────────────────────────────────
    st.subheader("ASN Distribution (adversary-controlled hosting)")

    asn_counts: Counter = Counter()
    for r in records:
        asn = r.get("asn", "")
        if asn and not _is_cdn_asn(asn):
            asn_counts[asn] += 1

    top15_asns = asn_counts.most_common(15)
    if top15_asns:
        asns, cnts = zip(*top15_asns)
        fig = go.Figure(
            go.Bar(
                x=list(cnts),
                y=list(asns),
                orientation="h",
                marker_color="#6366f1",
            )
        )
        fig.update_layout(
            xaxis_title="Domain count",
            yaxis={"categoryorder": "total ascending"},
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#f1f5f9",
            margin={"l": 20, "r": 20, "t": 20, "b": 20},
            height=400,
        )
        st.plotly_chart(fig, use_container_width=True)
        st.caption(
            "CDN providers (Cloudflare, Amazon, Google, Fastly, Akamai) are excluded "
            "from this chart — we want to show adversary-controlled hosting, not CDN usage."
        )
    else:
        st.caption("No ASN data available after excluding CDN providers.")
