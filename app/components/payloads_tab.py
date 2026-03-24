"""Payloads tab — primary analytical section with charts and pivot tables."""

from __future__ import annotations

from collections import Counter

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from app.utils.helpers import REPO_ROOT, load_records, payload_class_color

_CACHE = REPO_ROOT / "cache"

_ALL_CLASSES = ["stealer", "c2", "rmm", "loader", "unknown"]


def render() -> None:
    """Render the Payloads tab."""
    records = load_records(str(_CACHE / "triaged_records.json"))

    if not records:
        st.info("No triaged records found. Run the collection and triage pipeline first.")
        return

    total = len(records)
    families = {r.get("payload_family") for r in records if r.get("payload_family")}
    chain_n = sum(1 for r in records if r.get("chain_observed", False))
    chain_pct = round(chain_n / total * 100) if total else 0
    unknown_n = sum(1 for r in records if r.get("payload_class") == "unknown")
    unknown_pct = round(unknown_n / total * 100) if total else 0

    # ── Metric row ───────────────────────────────────────────────────────────
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total records", total)
    m2.metric("Distinct payload families", len(families))
    m3.metric("Chain observed", f"{chain_n} ({chain_pct}%)")
    m4.metric(
        "Unknown payload class",
        f"{unknown_n} ({unknown_pct}%)",
        delta="⚠ high" if unknown_pct > 20 else None,
        delta_color="inverse" if unknown_pct > 20 else "normal",
    )

    st.divider()

    # ── Payload class bar chart ──────────────────────────────────────────────
    class_counts = Counter(r.get("payload_class", "unknown") for r in records)
    classes_sorted = sorted(_ALL_CLASSES, key=lambda c: class_counts.get(c, 0), reverse=True)
    counts = [class_counts.get(c, 0) for c in classes_sorted]
    colors = [payload_class_color(c) for c in classes_sorted]

    fig = go.Figure(
        go.Bar(
            x=counts,
            y=classes_sorted,
            orientation="h",
            marker_color=colors,
            text=counts,
            textposition="outside",
        )
    )
    fig.update_layout(
        title="Payload Class Distribution",
        xaxis_title="Record count",
        yaxis={"categoryorder": "array", "categoryarray": list(reversed(classes_sorted))},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="#f1f5f9",
        margin={"l": 20, "r": 30, "t": 40, "b": 20},
        height=300,
    )
    st.plotly_chart(fig, use_container_width=True)

    st.divider()

    # ── Top 15 families ──────────────────────────────────────────────────────
    st.subheader("Top Payload Families")
    family_data: dict[str, dict] = {}
    for r in records:
        fam = r.get("payload_family")
        if not fam:
            continue
        if fam not in family_data:
            family_data[fam] = {"family": fam, "class": r.get("payload_class", "unknown"), "count": 0}
        family_data[fam]["count"] += 1

    top15 = sorted(family_data.values(), key=lambda x: x["count"], reverse=True)[:15]
    for row in top15:
        row["pct"] = f"{round(row['count'] / total * 100, 1)}%"

    fam_df = pd.DataFrame(top15, columns=["family", "class", "count", "pct"])
    st.dataframe(fam_df, use_container_width=True, hide_index=True)

    st.divider()

    # ── Lure × payload pivot ─────────────────────────────────────────────────
    st.subheader("Lure Type → Payload Class")
    df = pd.DataFrame(records)
    if "lure_type" in df.columns and "payload_class" in df.columns:
        df["lure_type"] = df["lure_type"].fillna("unknown")
        df["payload_class"] = df["payload_class"].fillna("unknown")
        try:
            pivot = df.pivot_table(
                index="lure_type",
                columns="payload_class",
                values="domain",
                aggfunc="count",
                fill_value=0,
            )
            # Ensure all classes are present as columns
            for cls in _ALL_CLASSES:
                if cls not in pivot.columns:
                    pivot[cls] = 0
            pivot = pivot[[c for c in _ALL_CLASSES if c in pivot.columns]]

            def _highlight_row_max(row: pd.Series) -> list[str]:
                max_val = row.max()
                return [
                    "background-color: #2563eb40" if v == max_val and max_val > 0 else ""
                    for v in row
                ]

            styled = pivot.style.apply(_highlight_row_max, axis=1)
            st.dataframe(styled, use_container_width=True)
        except Exception:
            st.dataframe(df[["lure_type", "payload_class"]].value_counts().reset_index())

    st.divider()

    # ── No-chain-observation callout ─────────────────────────────────────────
    no_chain = sum(1 for r in records if not r.get("chain_observed", False))
    if no_chain:
        st.info(
            f"**{no_chain}** records confirmed malicious but delivery chain not observed "
            f"in available URLScan data. These records appear in Payloads and Samples "
            f"but are excluded from Delivery Chains."
        )
