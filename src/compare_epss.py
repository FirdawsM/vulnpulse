"""

Goal: merge our model's predictions with EPSS scores for the same
test-set CVEs, then compare both using precision@k — the same
honest, ranking-based evaluation we used for our own model.
"""

import pandas as pd

PREDICTIONS_PATH = "data/processed/model_predictions.csv"
EPSS_PATH = "data/processed/epss_scores.csv"


def precision_at_k(df, score_col, k_values):
    """
    Given a dataframe with a 'true_label' column and a score column,
    sort by that score (descending) and report precision at each K.
    """
    results = {}
    sorted_df = df.sort_values(score_col, ascending=False)
    for k in k_values:
        top_k = sorted_df.head(k)
        hits = top_k["true_label"].sum()
        results[k] = (hits, hits / k * 100)
    return results


def main():
    predictions = pd.read_csv(PREDICTIONS_PATH)
    epss = pd.read_csv(EPSS_PATH).drop_duplicates(subset="cve_id", keep="first")

    # Inner join: only compare on CVEs where BOTH our model and EPSS
    # have a score, so the comparison is fair and like-for-like
    merged = predictions.merge(epss, on="cve_id", how="inner")

    print(f"Our predictions: {len(predictions)} CVEs")
    print(f"EPSS scores: {len(epss)} CVEs")
    print(f"Matched (both have scores): {len(merged)} CVEs")
    print(f"Exploited CVEs in matched set: {merged['true_label'].sum()}\n")

    k_values = [50, 100, 500, 1000]

    print("=== Our Model (precision@k) ===")
    our_results = precision_at_k(merged, "predicted_risk", k_values)
    for k, (hits, pct) in our_results.items():
        print(f"Top {k}: {hits} exploited ({pct:.1f}%)")

    print("\n=== EPSS (precision@k) ===")
    epss_results = precision_at_k(merged, "epss_score", k_values)
    for k, (hits, pct) in epss_results.items():
        print(f"Top {k}: {hits} exploited ({pct:.1f}%)")

    # Save the merged comparison for later inspection / dashboard use
    merged.to_csv("data/processed/model_vs_epss.csv", index=False)
    print("\nSaved comparison to data/processed/model_vs_epss.csv")


if __name__ == "__main__":
    main()