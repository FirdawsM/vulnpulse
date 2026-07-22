"""
fetch_nvd.py

Goal: download CVE records from the NVD API 2.0, for a given date range,
and save the raw JSON responses to disk (data/raw/).
"""


import requests
import json
import time
from datetime import datetime, timedelta
import os

from dotenv  import load_dotenv
load_dotenv()
API_KEY = os.getenv("NVD_API_KEY")


BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RAW_DATA_DIR = "data/raw"
RESULTS_PER_PAGE = 2000

YEARS_BACK = 3


def daterange_chunks(start_date, end_date, chunk_days=119):
    current_start = start_date
    while current_start < end_date:
        current_end = min(current_start + timedelta(days=chunk_days), end_date)
        yield current_start, current_end
        current_start = current_end

        

def fetch_cves_for_range(pub_start, pub_end):
    all_vulnerabilities = []
    start_index = 0

    while True:
        params = {
            "pubStartDate": pub_start.strftime("%Y-%m-%dT00:00:00.000"),
            "pubEndDate": pub_end.strftime("%Y-%m-%dT23:59:59.999"),
            "resultsPerPage": RESULTS_PER_PAGE,
            "startIndex": start_index,
        }

        print(f"  Requesting startIndex={start_index} ...")
        headers = {
            "apiKey": API_KEY,
            "User-Agent": "vulnpulse-cve-fetcher"
        } if API_KEY else {"User-Agent": "vulnpulse-cve-fetcher"}

        response = requests.get(BASE_URL, params=params, headers=headers)

        if response.status_code in (404, 403, 429):
            print(f"  Got {response.status_code}, waiting 15s and retrying...")
            time.sleep(15)
            continue

    
        data = response.json()

        vulns = data.get("vulnerabilities", [])
        all_vulnerabilities.extend(vulns)

        total_results = data.get("totalResults", 0)
        start_index += RESULTS_PER_PAGE

        time.sleep(0.6)

        if start_index >= total_results:
            break

    return all_vulnerabilities


def main():
    os.makedirs(RAW_DATA_DIR, exist_ok=True)

    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=365 * YEARS_BACK)

    all_cves = []

    for chunk_start, chunk_end in daterange_chunks(start_date, end_date):
        print(f"Fetching CVEs from {chunk_start.date()} to {chunk_end.date()}")
        chunk_cves = fetch_cves_for_range(chunk_start, chunk_end)
        print(f"  -> got {len(chunk_cves)} CVEs")
        all_cves.extend(chunk_cves)

    output_path = os.path.join(RAW_DATA_DIR, "nvd_cves_raw.json")
    with open(output_path, "w") as f:
        json.dump(all_cves, f)

    print(f"\nDone. Saved {len(all_cves)} total CVEs to {output_path}")


if __name__ == "__main__":
    main()