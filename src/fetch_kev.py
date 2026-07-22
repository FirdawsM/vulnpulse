"""
fetch_kev.py

Goal: download the CISA Known Exploited Vulnerabilities (KEV) catalog
as a CSV and save it to data/raw/.
"""

import requests
import os


KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.csv"
RAW_DATA_DIR = "data/raw"


def fetch_kev():
    os.makedirs(RAW_DATA_DIR, exist_ok=True)
    response = requests.get(KEV_URL)
    response.raise_for_status()

    output_path = os.path.join(RAW_DATA_DIR, "kev.csv")
    with open(output_path, "wb") as f:
        f.write(response.content)

    print(f"Saved KEV catalog to {output_path}")


if __name__ == "__main__":
    fetch_kev()