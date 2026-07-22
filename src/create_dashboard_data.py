import pandas as pd

df = pd.read_csv("data/processed/cves_merged.csv")

columns = [
    "published_date",
    "exploited",
    "cvss_score",
    "cvss_severity",
    "days_to_exploit",
    "vendor"
]

dashboard = df[columns].copy()

dashboard.to_csv(
    "data/processed/dashboard_data.csv",
    index=False
)

print(f"Original rows: {len(df):,}")
print(f"Dashboard rows: {len(dashboard):,}")