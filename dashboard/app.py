

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

st.set_page_config(page_title="VulnPulse — CVE Exploitation Risk", layout="wide")


def title_with_subtitle(title, subtitle):
    """
    Builds a Plotly title dict with a smaller subtitle line underneath,
    using HTML tags inside the title text -- this works across all
    Plotly versions, unlike the newer title_subtitle kwarg which isn't
    universally supported yet.
    """
    return dict(text=f"{title}<br><span style='font-size:12px;color:#94a3b8'>{subtitle}</span>")


from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

@st.cache_data
def load_data():
    merged = pd.read_csv(ROOT / "data" / "processed" / "dashboard_data.csv")
    comparison = pd.read_csv(ROOT / "data" / "processed" / "model_vs_epss.csv")

    merged["published_date"] = (
        pd.to_datetime(merged["published_date"], utc=True)
        .dt.tz_localize(None)
    )

    return merged, comparison


merged, comparison = load_data()

PLOT_TEMPLATE = "plotly_dark"
ACCENT = "#ef4444"
ACCENT2 = "#3b82f6"

# ============================================================
# HEADER
# ============================================================
st.title("🛡️ VulnPulse — CVE Exploitation Risk Dashboard")
st.caption("Does CVSS severity actually predict which vulnerabilities get exploited? · NVD + CISA KEV + EPSS, 2023–2026 · Full methodology in README")

# ============================================================
# KPI ROW
# ============================================================
total_cves = len(merged)
exploited_count = int(merged["exploited"].sum())
exploited_pct = exploited_count / total_cves * 100
avg_cvss = merged["cvss_score"].mean()
avg_cvss_exploited = merged[merged["exploited"] == 1]["cvss_score"].mean()

k1, k2, k3, k4, k5 = st.columns(5)
k1.metric("Total CVEs", f"{total_cves:,}")
k2.metric("Confirmed Exploited", f"{exploited_count:,}", f"{exploited_pct:.2f}%")
k3.metric("Avg CVSS (all)", f"{avg_cvss:.1f}")
k4.metric("Avg CVSS (exploited)", f"{avg_cvss_exploited:.1f}", f"+{avg_cvss_exploited - avg_cvss:.1f}")
k5.metric("Period", "2023–2026")

st.divider()

# ============================================================
# ROW 1: Severity exploit-rate bar + Exploited share pie
# ============================================================
row1_col1, row1_col2 = st.columns([1.4, 1])

with row1_col1:
    totals_by_severity = merged["cvss_severity"].value_counts()
    exploited_by_severity = merged[merged["exploited"] == 1]["cvss_severity"].value_counts()
    exploit_rate = (exploited_by_severity / totals_by_severity * 100).dropna().reset_index()
    exploit_rate.columns = ["severity", "rate"]
    order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    exploit_rate["severity"] = pd.Categorical(exploit_rate["severity"], categories=order, ordered=True)
    exploit_rate = exploit_rate.sort_values("severity")

    fig1 = px.bar(
        exploit_rate, x="severity", y="rate", text="rate",
        color="rate", color_continuous_scale=["#fecaca", ACCENT, "#7f1d1d"],
    )
    fig1.update_traces(
        texttemplate="%{text:.2f}%", textposition="outside",
        hovertemplate="<b>%{x} severity</b><br>%{y:.2f}%% of these CVEs were exploited<extra></extra>"
    )
    fig1.update_layout(
        title=title_with_subtitle("Exploitation Rate by CVSS Severity", "Even Critical CVEs are exploited only ~1.6% of the time"),
        template=PLOT_TEMPLATE, showlegend=False, coloraxis_showscale=False,
        yaxis_title="% exploited", xaxis_title=None,
        margin=dict(t=70, b=10)
    )
    st.plotly_chart(fig1, use_container_width=True)

with row1_col2:
    pie_data = pd.DataFrame({
        "status": ["Not Exploited", "Exploited"],
        "count": [total_cves - exploited_count, exploited_count]
    })
    fig2 = go.Figure(data=[go.Pie(
        labels=pie_data["status"], values=pie_data["count"], hole=0.55,
        marker_colors=["#334155", ACCENT],
        hovertemplate="<b>%{label}</b><br>%{value:,} CVEs (%{percent})<extra></extra>",
        textinfo="none"
    )])
    fig2.update_layout(
        title=title_with_subtitle("Share of CVEs Ever Exploited", f"{exploited_pct:.2f}% of all {total_cves:,} CVEs — hover for detail"),
        template=PLOT_TEMPLATE,
        annotations=[dict(text=f"{exploited_pct:.1f}%", x=0.5, y=0.5, font_size=22, showarrow=False)],
        margin=dict(t=70, b=10)
    )
    st.plotly_chart(fig2, use_container_width=True)

# ============================================================
# ROW 2: Time-to-exploit histogram + Monthly trend line
# ============================================================
row2_col1, row2_col2 = st.columns([1, 1.4])

exploited_only = merged[merged["exploited"] == 1].copy()
exploited_only["days_clipped"] = exploited_only["days_to_exploit"].clip(-30, 180)

with row2_col1:
    within_7 = (exploited_only["days_to_exploit"] <= 7).sum()
    total_dated = exploited_only["days_to_exploit"].notna().sum()
    neg_days = (exploited_only["days_to_exploit"] < 0).sum()

    fig3 = px.histogram(
        exploited_only, x="days_clipped", nbins=35,
        color_discrete_sequence=[ACCENT2],
    )
    fig3.add_vline(x=0, line_dash="dash", line_color="white")
    fig3.update_traces(
        hovertemplate="Days from publish: %{x}<br>%{y} CVEs<extra></extra>"
    )
    fig3.update_layout(
        title=title_with_subtitle("Time to Exploitation",
                                    f"{within_7/total_dated*100:.0f}% exploited within 7 days · {neg_days/total_dated*100:.0f}% before/on publish date"),
        template=PLOT_TEMPLATE,
        xaxis_title="Days between publish & exploitation (clipped at 180)",
        yaxis_title="CVEs",
        margin=dict(t=70, b=10)
    )
    st.plotly_chart(fig3, use_container_width=True)

with row2_col2:
    monthly = merged.copy()
    monthly["month"] = monthly["published_date"].dt.to_period("M").dt.to_timestamp()
    monthly_totals = monthly.groupby("month").size().reset_index(name="published")
    monthly_exploited = monthly[monthly["exploited"] == 1].groupby("month").size().reset_index(name="exploited")
    monthly_merged = monthly_totals.merge(monthly_exploited, on="month", how="left").fillna(0)

    fig4 = go.Figure()
    fig4.add_trace(go.Scatter(
        x=monthly_merged["month"], y=monthly_merged["published"], name="CVEs Published",
        line=dict(color="#64748b", width=2), yaxis="y1",
        hovertemplate="%{x|%b %Y}<br>%{y} CVEs published<extra></extra>"
    ))
    fig4.add_trace(go.Scatter(
        x=monthly_merged["month"], y=monthly_merged["exploited"], name="CVEs Exploited",
        line=dict(color=ACCENT, width=3), yaxis="y2",
        hovertemplate="%{x|%b %Y}<br>%{y} exploited<extra></extra>"
    ))
    fig4.update_layout(
        title=title_with_subtitle("Published Volume vs. Exploited Volume Over Time",
                                    "Right axis (red) is exploited CVEs — much smaller scale than left axis (gray)"),
        template=PLOT_TEMPLATE,
        yaxis=dict(title="CVEs published/month"),
        yaxis2=dict(title="CVEs exploited/month", overlaying="y", side="right"),
        legend=dict(orientation="h", yanchor="bottom", y=1.15, xanchor="right", x=1),
        margin=dict(t=90, b=10)
    )
    st.plotly_chart(fig4, use_container_width=True)

# ============================================================
# ROW 3: Model vs EPSS + Top vendors
# ============================================================
row3_col1, row3_col2 = st.columns([1, 1])


def precision_at_k(df, score_col, k):
    top_k = df.sort_values(score_col, ascending=False).head(k)
    return top_k["true_label"].sum() / k * 100


with row3_col1:
    k_values = [50, 100, 500, 1000]
    bench_data = []
    for k in k_values:
        bench_data.append({"k": str(k), "source": "Our Model", "precision": precision_at_k(comparison, "predicted_risk", k)})
        bench_data.append({"k": str(k), "source": "EPSS", "precision": precision_at_k(comparison, "epss_score", k)})
    bench_df = pd.DataFrame(bench_data)

    fig5 = px.bar(
        bench_df, x="k", y="precision", color="source", barmode="group",
        color_discrete_map={"Our Model": "#93c5fd", "EPSS": ACCENT2},
    )
    fig5.update_traces(hovertemplate="Top %{x} CVEs<br>%{y:.1f}%% were real exploits<extra>%{fullData.name}</extra>")
    fig5.update_layout(
        title=title_with_subtitle("Prediction Quality: Our Model vs. EPSS",
                                    "EPSS wins, but our CVSS-only baseline still beats random by ~17x at top 50"),
        template=PLOT_TEMPLATE,
        xaxis_title="If a team could only patch the top K riskiest CVEs...",
        yaxis_title="% actually exploited (precision)",
        legend_title=None,
        margin=dict(t=70, b=10)
    )
    st.plotly_chart(fig5, use_container_width=True)

with row3_col2:
    top_vendors = (
        merged[merged["exploited"] == 1]["vendor"]
        .value_counts()
        .head(10)
        .reset_index()
    )
    top_vendors.columns = ["vendor", "exploited_count"]

    fig6 = px.bar(
        top_vendors.sort_values("exploited_count"), x="exploited_count", y="vendor",
        orientation="h",
        color="exploited_count", color_continuous_scale=["#fecaca", ACCENT, "#7f1d1d"],
    )
    fig6.update_traces(hovertemplate="<b>%{y}</b><br>%{x} exploited CVEs<extra></extra>")
    fig6.update_layout(
        title=title_with_subtitle("Top 10 Vendors by Confirmed Exploited CVEs",
                                    "Which vendors account for the most confirmed real-world exploits"),
        template=PLOT_TEMPLATE, coloraxis_showscale=False,
        xaxis_title="Exploited CVEs", yaxis_title=None,
        margin=dict(t=70, b=10)
    )
    st.plotly_chart(fig6, use_container_width=True)

st.caption("Data: NVD API 2.0 · CISA KEV Catalog · FIRST.org EPSS API — hover any chart for exact figures. Full write-up: project README.")