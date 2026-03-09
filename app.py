import os
import pandas as pd
import streamlit as st
import plotly.express as px

st.set_page_config(page_title="Threat Intelligence Dashboard", layout="wide")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(BASE_DIR, "data", "analyzed_posts.csv")

@st.cache_data
def load_data():
    df = pd.read_csv(DATA_PATH)
    df["created_at"] = pd.to_datetime(df["created_utc"], unit="s")
    return df

df = load_data()

st.title("Threat Intelligence Dashboard (Reddit MVP)")

# ===== Sidebar Filters =====
st.sidebar.header("Filters")

subreddits = sorted(df["source"].dropna().unique().tolist())
severities = ["Low", "Medium", "High", "Critical"]

selected_subreddits = st.sidebar.multiselect(
    "Select Subreddits",
    subreddits,
    default=subreddits
)

selected_severities = st.sidebar.multiselect(
    "Select Severity",
    severities,
    default=severities
)

keyword = st.sidebar.text_input("Search keyword", "")

date_min = df["created_at"].min().date()
date_max = df["created_at"].max().date()

date_range = st.sidebar.date_input(
    "Date Range",
    value=(date_min, date_max)
)

# ===== Apply Filters =====
filtered_df = df[df["source"].isin(selected_subreddits)]
filtered_df = filtered_df[filtered_df["severity"].isin(selected_severities)]

if isinstance(date_range, tuple) and len(date_range) == 2:
    start_date, end_date = date_range
    filtered_df = filtered_df[
        (filtered_df["created_at"].dt.date >= start_date) &
        (filtered_df["created_at"].dt.date <= end_date)
    ]

if keyword.strip():
    filtered_df = filtered_df[
        filtered_df["text_norm"].str.contains(keyword.lower(), na=False)
    ]

# ===== KPI Cards =====
total_posts = len(filtered_df)
flagged_posts = len(filtered_df[filtered_df["severity"].isin(["Medium", "High", "Critical"])])
high_critical = len(filtered_df[filtered_df["severity"].isin(["High", "Critical"])])

all_cves = []
for cve_str in filtered_df["cves"].fillna(""):
    if cve_str.strip():
        all_cves.extend(cve_str.split(", "))
unique_cves = len(set(all_cves))

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Posts", total_posts)
col2.metric("Flagged Threats", flagged_posts)
col3.metric("High / Critical", high_critical)
col4.metric("Unique CVEs", unique_cves)

# ===== Threat Summary =====
top_attack_type = "N/A"
if not filtered_df["attack_type"].dropna().empty:
    top_attack_type = filtered_df["attack_type"].value_counts().idxmax()

top_cve = "N/A"
if all_cves:
    top_cve = pd.Series(all_cves).value_counts().idxmax()

st.info(
    f"**Threat Summary:** {total_posts} posts analyzed. "
    f"{high_critical} High/Critical threats detected. "
    f"Most discussed attack type: **{top_attack_type}**. "
    f"Top CVE: **{top_cve}**."
)

st.divider()

# ===== Severity Distribution =====
st.subheader("Threat Severity Distribution")

severity_counts = filtered_df["severity"].value_counts().reset_index()
severity_counts.columns = ["severity", "count"]

fig_severity = px.pie(
    severity_counts,
    names="severity",
    values="count",
    title="Threat Severity Breakdown"
)

st.plotly_chart(fig_severity, use_container_width=True)

# ===== Threat Trend =====
st.subheader("Threat Trend by Day")
trend_df = filtered_df.copy()
trend_df["date"] = trend_df["created_at"].dt.date
trend_counts = trend_df.groupby(["date", "attack_type"]).size().reset_index(name="count")

fig_trend = px.line(
    trend_counts,
    x="date",
    y="count",
    color="attack_type",
    markers=True,
    title="Threat Trend Over Time"
)
st.plotly_chart(fig_trend, use_container_width=True)

# ===== Attack Type Distribution =====
st.subheader("Attack Type Distribution")
attack_counts = filtered_df["attack_type"].value_counts().reset_index()
attack_counts.columns = ["attack_type", "count"]

fig_attack = px.bar(
    attack_counts,
    x="attack_type",
    y="count",
    title="Posts by Attack Type"
)
st.plotly_chart(fig_attack, use_container_width=True)

# ===== Top CVEs =====
st.subheader("Top CVEs")
if all_cves:
    cve_counts = pd.Series(all_cves).value_counts().reset_index()
    cve_counts.columns = ["CVE", "count"]
    st.dataframe(cve_counts.head(10), use_container_width=True)
else:
    st.info("No CVEs found in the current filtered data.")

st.divider()

# ===== Latest Posts =====
st.subheader("Latest Threat Posts")
latest_posts = filtered_df.sort_values("created_at", ascending=False)[
    ["created_at", "source", "title", "attack_type", "severity", "severity_score", "cves", "permalink"]
]
st.dataframe(latest_posts.head(50), use_container_width=True)

# ===== Alerts =====
st.subheader("High / Critical Alerts")
alerts_df = filtered_df[filtered_df["severity"].isin(["High", "Critical"])].sort_values("created_at", ascending=False)

# ===== Threat Alert Box =====
critical_alerts = filtered_df[filtered_df["severity"] == "Critical"].sort_values("created_at", ascending=False)

if not critical_alerts.empty:
    latest = critical_alerts.iloc[0]

    st.error(
        f"CRITICAL THREAT DETECTED\n\n"
        f"**Title:** {latest['title']}\n\n"
        f"**Source:** r/{latest['source']}\n\n"
        f"**Attack Type:** {latest['attack_type']}\n\n"
        f"**CVEs:** {latest['cves'] if str(latest['cves']).strip() else 'None detected'}"
    )

if not alerts_df.empty:
    st.dataframe(
        alerts_df[["created_at", "source", "title", "attack_type", "severity", "severity_score", "cves", "permalink"]].head(20),
        use_container_width=True
    )
else:
    st.success("No High or Critical alerts found for the selected filters.")