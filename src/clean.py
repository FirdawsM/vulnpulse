"""
clean.py

Goal: take the raw, messy nvd_cves_raw.json file and turn it into
one clean, flat table (CSV) with just the fields we need.

"""

import json
import pandas as pd
import os

RAW_PATH = "data/raw/nvd_cves_raw.json"
PROCESSED_DIR = "data/processed"


def pick_cvss_score(metrics):
    """
    A single CVE can have MULTIPLE danger scores (v2, v3.1, v4.0),
    and they don't always agree with each other.

    We need ONE consistent score per CVE, so we pick in this order
    of preference: v3.1 first (most widely used), then fall back
    to v2 if v3.1 doesn't exist. We skip v4.0 on purpose, since
    it's newer and not consistently available across older CVEs,
    which would make our comparisons unfair.

    Returns a tuple: (score, severity, version_used)
    e.g. (6.3, "MEDIUM", "3.1")
    Returns (None, None, None) if no usable score exists at all.
    """
    if "cvssMetricV31" in metrics:
        data = metrics["cvssMetricV31"][0]["cvssData"]
        return {
            "cvss_score": data["baseScore"],
            "cvss_severity": data["baseSeverity"],
            "cvss_version_used": "3.1",
            "attack_vector": data.get("attackVector"),
            "attack_complexity": data.get("attackComplexity"),
            "privileges_required": data.get("privilegesRequired"),
            "user_interaction": data.get("userInteraction"),
        }

    if "cvssMetricV2" in metrics:
        data = metrics["cvssMetricV2"][0]["cvssData"]
        severity = metrics["cvssMetricV2"][0].get("baseSeverity")
        return {
            "cvss_score": data["baseScore"],
            "cvss_severity": severity,
            "cvss_version_used": "2.0",
            # v2 uses different field names for similar concepts
            "attack_vector": data.get("accessVector"),
            "attack_complexity": data.get("accessComplexity"),
            "privileges_required": data.get("authentication"),
            "user_interaction": None,  # v2 doesn't have this concept
        }

    return {
        "cvss_score": None, "cvss_severity": None, "cvss_version_used": None,
        "attack_vector": None, "attack_complexity": None,
        "privileges_required": None, "user_interaction": None,
    }

def clean_cve_record(raw_entry):
    """
    Takes ONE raw CVE record (the messy nested dict from NVD)
    and extracts just the fields we care about into a flat dict.

    Returns None if this CVE should be skipped entirely
    (e.g. it's REJECTED and not a real vulnerability).
    """
    cve = raw_entry["cve"]

    # Skip fake/withdrawn entries — they're not real vulnerabilities
    if cve.get("vulnStatus") in ("Rejected", "Disputed"):
        return None

    cve_id = cve["id"]
    published_date = cve["published"]

    # Descriptions is a list (sometimes multiple languages) —
    # we just want the English one
    description = ""
    for desc in cve.get("descriptions", []):
        if desc["lang"] == "en":
            description = desc["value"]
            break

    # Pull vendor/product from the first affected entry, if it exists
    vendor = None
    product = None
    affected = cve.get("affected", [])
    if affected:
        affected_data = affected[0].get("affectedData", [])
        if affected_data:
            vendor = affected_data[0].get("vendor")
            product = affected_data[0].get("product")

    # Get our single, consistent CVSS score
    metrics = cve.get("metrics", {})
    cvss_data = pick_cvss_score(metrics)
    return {
        "cve_id": cve_id,
        "published_date": published_date,
        "vendor": vendor,
        "product": product,
        "description": description,
        **cvss_data,  # unpacks all the CVSS fields into this dict
    }

def main():
    os.makedirs(PROCESSED_DIR, exist_ok=True)

    print("Loading raw JSON file (this may take a moment, it's a big file)...")
    with open(RAW_PATH, "r") as f:
        raw_data = json.load(f)

    print(f"Loaded {len(raw_data)} raw CVE entries. Cleaning now...")

    cleaned_records = []
    skipped_count = 0

    for entry in raw_data:
        cleaned = clean_cve_record(entry)
        if cleaned is None:
            skipped_count += 1
            continue
        cleaned_records.append(cleaned)

    print(f"Skipped {skipped_count} rejected/disputed CVEs.")
    print(f"Kept {len(cleaned_records)} clean CVE records.")

    # Turn our list of dicts into a proper table (DataFrame)
    df = pd.DataFrame(cleaned_records)

    # NOTE: our date-chunked NVD fetch can pull the same CVE twice when
    # it falls exactly on a chunk boundary date (the boundary day gets
    # included in both the ending chunk and the starting chunk). Drop
    # any duplicate cve_id, keeping the first occurrence, so downstream
    # merging/modeling isn't double-counting the same vulnerability.
    before_dedup = len(df)
    df = df.drop_duplicates(subset="cve_id", keep="first")
    duplicates_removed = before_dedup - len(df)
    if duplicates_removed > 0:
        print(f"Removed {duplicates_removed} duplicate CVE rows (chunk-boundary overlap).")

    # How many CVEs don't have any CVSS score at all?
    unscored_count = df["cvss_score"].isna().sum()
    print(f"Note: {unscored_count} CVEs have no CVSS score yet (kept, but flagged).")

    output_path = os.path.join(PROCESSED_DIR, "cves_cleaned.csv")
    df.to_csv(output_path, index=False)

    print(f"\nDone. Saved cleaned data to {output_path}")


if __name__ == "__main__":
    main()