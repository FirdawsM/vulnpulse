"""
model.py

Baseline model to predict CVE exploitation risk, using CVSS score
plus attack characteristics (vector, complexity, privileges, user
interaction). Evaluated with a TIME-based train/test split, since
we're predicting the future, not just classifying the past.

Instead of a fixed 0.5 threshold (which is misleading when the
positive class is this rare — only ~0.4% of CVEs get exploited),
we evaluate using precision@k: "if a security team could only
patch the top K riskiest CVEs today, how many would actually be
real threats?" This mirrors how a model like this would genuinely
be used in practice.
"""

import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score

DATA_PATH = "data/processed/cves_merged.csv"
SPLIT_DATE = "2025-01-01"


def prepare_data():
    df = pd.read_csv(DATA_PATH)
    df["published_date"] = pd.to_datetime(df["published_date"], utc=True).dt.tz_localize(None)

    # Drop rows with no CVSS score — can't use as a feature if missing
    df = df.dropna(subset=["cvss_score"]).reset_index(drop=True)

    # Fill missing categorical values with "UNKNOWN" so get_dummies
    # doesn't silently mishandle those rows
    categorical_cols = ["attack_vector", "attack_complexity", "privileges_required", "user_interaction"]
    for col in categorical_cols:
        df[col] = df[col].fillna("UNKNOWN")

    # One-hot encode the categorical columns into separate 0/1 columns
    df_encoded = pd.get_dummies(df, columns=categorical_cols)

    # Keep cve_id around so we can inspect which specific CVEs
    # the model ranks as highest-risk later
    df_encoded["cve_id"] = df["cve_id"]

    dummy_cols = [c for c in df_encoded.columns if any(c.startswith(cat + "_") for cat in categorical_cols)]
    feature_cols = ["cvss_score"] + dummy_cols

    X = df_encoded[feature_cols]
    y = df_encoded["exploited"]
    dates = df_encoded["published_date"]

    return X, y, dates, feature_cols, df_encoded


def main():
    X, y, dates, feature_cols, df_encoded = prepare_data()

    split_point = pd.Timestamp(SPLIT_DATE)
    train_mask = dates < split_point
    test_mask = dates >= split_point

    X_train, y_train = X[train_mask], y[train_mask]
    X_test, y_test = X[test_mask], y[test_mask]

    print(f"Training set: {len(X_train)} CVEs ({y_train.sum()} exploited)")
    print(f"Test set: {len(X_test)} CVEs ({y_test.sum()} exploited)")
    print(f"Features used: {feature_cols}\n")

    model = LogisticRegression(class_weight="balanced", max_iter=1000)
    model.fit(X_train, y_train)

    y_pred_proba = model.predict_proba(X_test)[:, 1]  # probability of exploitation

    # --- Ranking-based evaluation (the honest, practical way to judge this) ---
    results = pd.DataFrame({
        "cve_id": df_encoded.loc[X_test.index, "cve_id"].values,
        "true_label": y_test.values,
        "predicted_risk": y_pred_proba
    }).sort_values("predicted_risk", ascending=False)

    print("=== Precision@K (if a team could only patch the top K riskiest CVEs) ===")
    for k in [50, 100, 500, 1000]:
        top_k = results.head(k)
        hits = top_k["true_label"].sum()
        print(f"Top {k}: {hits} were actually exploited ({hits/k*100:.1f}% precision@{k})")

    auc = roc_auc_score(y_test, y_pred_proba)
    print(f"\nAUC-ROC: {auc:.3f}")

    # Save the ranked results so we can inspect specific CVEs later
    results.to_csv("data/processed/model_predictions.csv", index=False)
    print("\nSaved ranked predictions to data/processed/model_predictions.csv")


if __name__ == "__main__":
    main()