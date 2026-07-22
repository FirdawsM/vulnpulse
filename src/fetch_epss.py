"""
fetch_epss.py

Goal: pull EPSS scores for the CVEs in our test set. Saves progress
incrementally (appending after each batch) so a connection error
partway through doesn't lose everything already fetched — it can
just be rerun and it'll skip CVEs already saved.
"""

import requests
import pandas as pd
import time
import os

EPSS_URL = "https://api.first.org/data/v1/epss"
OUTPUT_PATH = "data/processed/epss_scores.csv"


def fetch_batch_with_retry(cve_param, max_retries=5):
    """
    Tries a single batch request, retrying with a growing wait time
    if the connection resets or times out (this API is a bit flaky
    under sustained load, similar to what we saw with NVD earlier).
    """
    for attempt in range(max_retries):
        try:
            response = requests.get(EPSS_URL, params={"cve": cve_param}, timeout=15)
            response.raise_for_status()
            return response.json()
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            wait = 5 * (attempt + 1)
            print(f"    Connection issue ({e.__class__.__name__}), waiting {wait}s, retry {attempt + 1}/{max_retries}...")
            time.sleep(wait)
    raise RuntimeError(f"Failed after {max_retries} retries for this batch.")


def main():
    predictions = pd.read_csv("data/processed/model_predictions.csv")
    all_cve_ids = predictions["cve_id"].tolist()

    # If we already have partial results saved, figure out which
    # CVEs we still need, so a rerun doesn't start from zero
    already_fetched = set()
    if os.path.exists(OUTPUT_PATH):
        existing = pd.read_csv(OUTPUT_PATH)
        already_fetched = set(existing["cve_id"])
        print(f"Found {len(already_fetched)} already-fetched CVEs, resuming...")

    remaining_cve_ids = [c for c in all_cve_ids if c not in already_fetched]
    print(f"Fetching EPSS scores for {len(remaining_cve_ids)} remaining CVEs...")

    batch_size = 100
    file_exists = os.path.exists(OUTPUT_PATH)

    for i in range(0, len(remaining_cve_ids), batch_size):
        batch = remaining_cve_ids[i:i + batch_size]
        cve_param = ",".join(batch)

        data = fetch_batch_with_retry(cve_param)

        batch_scores = []
        for entry in data.get("data", []):
            batch_scores.append({
                "cve_id": entry["cve"],
                "epss_score": float(entry["epss"])
            })

        # Append this batch to the CSV immediately — so if it crashes
        # on the NEXT batch, this one is already safely saved to disk
        batch_df = pd.DataFrame(batch_scores)
        batch_df.to_csv(OUTPUT_PATH, mode="a", header=not file_exists, index=False)
        file_exists = True

        print(f"  Fetched + saved batch {i // batch_size + 1} ({len(batch)} CVEs)")
        time.sleep(0.5)

    print(f"\nDone. All EPSS scores saved to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()