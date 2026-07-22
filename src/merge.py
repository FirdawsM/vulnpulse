"""
merge.py

Goal: join our cleaned NVD data with the CISA KEV list, so every
CVE gets labeled either "exploited" or "not exploited" — this
label is what our model will learn to predict.
"""

import pandas as pd
import os

CLEANED_NVD_PATH = "data/processed/cves_cleaned.csv"
KEV_PATH = "data/raw/kev.csv"
OUTPUT_PATH = "data/processed/cves_merged.csv"


def main():
    nvd_df = pd.read_csv(CLEANED_NVD_PATH)
    kev_df = pd.read_csv(KEV_PATH)

    print(f"NVD records: {len(nvd_df)}")
    print(f"KEV records: {len(kev_df)}")

    # KEV's CVE column is literally called "cveID" — let's check
    print("KEV columns:", kev_df.columns.tolist())

    # We only need two things from KEV: the CVE ID (to match on)
    # and the date it was added to KEV (to calculate days_to_exploit)
    kev_slim = kev_df[["cveID", "dateAdded"]].rename(
        columns={"cveID": "cve_id", "dateAdded": "kev_date_added"}
    )

    # LEFT JOIN: keep ALL nvd_df rows, and attach KEV info
    # wherever a match exists. If no match, kev_date_added stays empty.
    merged = nvd_df.merge(kev_slim, on="cve_id", how="left")

    # If kev_date_added is NOT empty, this CVE was exploited = 1
    # If it IS empty (NaN), this CVE was not exploited = 0
    merged["exploited"] = merged["kev_date_added"].notna().astype(int)

    # Calculate days between publish and exploitation
    merged["published_date"] = pd.to_datetime(merged["published_date"], utc=True).dt.tz_localize(None)
    merged["kev_date_added"] = pd.to_datetime(merged["kev_date_added"])
    merged["days_to_exploit"] = (merged["kev_date_added"] - merged["published_date"]).dt.days

    exploited_count = merged["exploited"].sum()
    print(f"\nExploited CVEs found: {exploited_count}")
    print(f"Not exploited: {len(merged) - exploited_count}")

    os.makedirs("data/processed", exist_ok=True)
    merged.to_csv(OUTPUT_PATH, index=False)
    print(f"\nDone. Saved merged data to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()