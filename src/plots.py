"""
plots.py

Goal: create the core visuals for our findings — saved as image
files we can drop into the README and reference for the dashboard.
"""

import pandas as pd
import matplotlib.pyplot as plt
import os

DATA_PATH = "data/processed/cves_merged.csv"
OUTPUT_DIR = "dashboard/plots"


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    df = pd.read_csv(DATA_PATH)
    exploited_only = df[df["exploited"] == 1]

    # --- Plot 1: Exploitation rate by severity ---
    totals = df["cvss_severity"].value_counts()
    exploited_counts = exploited_only["cvss_severity"].value_counts()
    rate = (exploited_counts / totals * 100).dropna().sort_values()

    plt.figure(figsize=(8, 5))
    rate.plot(kind="barh", color="#f87171")
    plt.xlabel("% of CVEs in this severity band that were exploited")
    plt.title("Exploitation Rate by CVSS Severity")
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "exploit_rate_by_severity.png"))
    plt.close()

    # --- Plot 2: Days to exploit distribution ---
    days = exploited_only["days_to_exploit"].dropna()
    days_clipped = days.clip(-30, 180)  # clip extreme outliers for readability

    plt.figure(figsize=(8, 5))
    plt.hist(days_clipped, bins=40, color="#3b82f6")
    plt.axvline(0, color="black", linestyle="--", linewidth=1)
    plt.xlabel("Days between CVE publish date and KEV exploitation date")
    plt.ylabel("Number of CVEs")
    plt.title("Time-to-Exploitation Distribution")
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "days_to_exploit.png"))
    plt.close()

    print(f"Saved plots to {OUTPUT_DIR}/")


if __name__ == "__main__":
    main()