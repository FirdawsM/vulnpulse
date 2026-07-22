"""
main.py

Goal: run the entire VulnPulse pipeline in order, one step at a time.
This is the "conductor" — it doesn't do any data work itself,
it just calls each stage's script in the right sequence.
"""

from fetch_nvd import main as fetch_nvd_main
from fetch_kev import fetch_kev
from clean import main as clean_main
from merge import main as merge_main
from plots import main as plots_main


def run_pipeline():
    print("=== Step 1: Fetching NVD data ===")
    fetch_nvd_main()

    print("\n=== Step 2: Fetching KEV data ===")
    fetch_kev()

    print("\n=== Step 3: Cleaning data ===")
    clean_main()

    print("\n=== Step 4: Merging data ===")
    merge_main()

    print("\n=== Step 5: Generating plots ===")
    plots_main()

    print("\n=== Pipeline complete ===")


if __name__ == "__main__":
    run_pipeline()