#!/usr/bin/env python3
"""
train_model.py

Step 3-4 of the AI-based NIDS project:
  1. Load the flow-feature CSV produced by capture_and_extract.py
  2. Train a Random Forest classifier to distinguish normal vs attack flows
  3. Evaluate with precision/recall/F1 and a confusion matrix
  4. Compare against a simple rule-based baseline (SYN-rate threshold)
  5. Save the trained model to disk for use in live detection

Works with TWO kinds of input:
  1. flows_labeled.csv from capture_and_extract.py (your own captured traffic)
  2. nsl_kdd_train.csv / nsl_kdd_test.csv from prepare_nsl_kdd.py (benchmark dataset)
Feature columns and categorical encoding are detected automatically from
whatever CSV you pass in -- you don't need to edit this file to switch.

Usage:
    # Your own captured + labeled traffic
    python3 train_model.py --data flows_labeled.csv --model nids_model.joblib

    # NSL-KDD, with a separate pre-labeled test file
    python3 train_model.py --data nsl_kdd_train.csv --test-data nsl_kdd_test.csv --model nids_model.joblib

Requires: pip install scikit-learn pandas joblib --break-system-packages
"""

import argparse

import joblib
import numpy as np
import pandas as pd
from pandas.api.types import is_numeric_dtype
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

# Columns that are identifiers/metadata, never used as ML features, even if present
NON_FEATURE_COLUMNS = {
    "label", "difficulty", "src_ip", "dst_ip", "src_port", "dst_port",
}


def load_data(path):
    df = pd.read_csv(path)
    if "label" not in df.columns:
        raise ValueError("CSV must have a 'label' column.")
    df = df[df["label"] != "unknown"].copy()
    if df.empty:
        raise ValueError(
            "No labeled rows found. Fill in the 'label' column "
            "(e.g. 'normal', 'portscan', 'dos') before training."
        )
    return df


def get_feature_columns(df):
    return [c for c in df.columns if c not in NON_FEATURE_COLUMNS]


def fit_categorical_encoders(dfs, feature_cols):
    """Fits one LabelEncoder per non-numeric feature column on the UNION of
    values across all given dataframes (train + test), so a category value
    that only appears in the test set (common in NSL-KDD) doesn't crash
    transform() later."""
    encoders = {}
    for col in feature_cols:
        if not is_numeric_dtype(dfs[0][col]):
            combined = pd.concat([df[col] for df in dfs])
            encoders[col] = LabelEncoder().fit(combined)
    return encoders


def apply_categorical_encoders(df, encoders):
    df = df.copy()
    for col, enc in encoders.items():
        df[col] = enc.transform(df[col])
    return df


def rule_based_baseline(df):
    """Very simple heuristic: flag as attack if SYN count is high relative to ACKs
    (classic port-scan / SYN-flood signature). Only runs when those columns exist
    (i.e. flow-capture data) -- skipped automatically for NSL-KDD-style input."""
    if "syn_count" not in df.columns or "ack_count" not in df.columns:
        return None
    return np.where(
        (df["syn_count"] > 5) & (df["ack_count"] < df["syn_count"] * 0.5),
        "attack_flagged",
        "normal_flagged",
    )


def main():
    parser = argparse.ArgumentParser(description="Train and evaluate the NIDS classifier")
    parser.add_argument("--data", required=True, help="Path to labeled training CSV")
    parser.add_argument("--test-data", help="Optional separate labeled test CSV (e.g. nsl_kdd_test.csv). "
                                             "If omitted, --data is split with --test-size instead.")
    parser.add_argument("--model", default="nids_model.joblib", help="Output path for trained model")
    parser.add_argument("--test-size", type=float, default=0.25, help="Fraction held out for testing (ignored if --test-data given)")
    args = parser.parse_args()

    train_df = load_data(args.data)
    feature_cols = get_feature_columns(train_df)
    print(f"Loaded {len(train_df)} labeled rows. Classes: {train_df['label'].value_counts().to_dict()}")
    print(f"Using {len(feature_cols)} feature columns: {feature_cols}")

    label_encoder = LabelEncoder()

    if args.test_data:
        test_df = load_data(args.test_data)
        encoders = fit_categorical_encoders([train_df, test_df], feature_cols)
        train_df = apply_categorical_encoders(train_df, encoders)
        test_df = apply_categorical_encoders(test_df, encoders)
        label_encoder.fit(pd.concat([train_df["label"], test_df["label"]]))
        X_train, y_train = train_df[feature_cols], label_encoder.transform(train_df["label"])
        X_test, y_test = test_df[feature_cols], label_encoder.transform(test_df["label"])
        df_test = test_df
    else:
        encoders = fit_categorical_encoders([train_df], feature_cols)
        train_df = apply_categorical_encoders(train_df, encoders)
        y_all = label_encoder.fit_transform(train_df["label"])
        X_train, X_test, y_train, y_test, _, df_test = train_test_split(
            train_df[feature_cols], y_all, train_df,
            test_size=args.test_size, random_state=42,
            stratify=y_all if len(set(y_all)) > 1 else None,
        )

    clf = RandomForestClassifier(
        n_estimators=200, max_depth=15, random_state=42, class_weight="balanced"
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)

    print("\n=== Random Forest results ===")
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print(classification_report(y_test, y_pred, target_names=label_encoder.classes_))
    print("Confusion matrix (rows=actual, cols=predicted):")
    print(pd.DataFrame(
        confusion_matrix(y_test, y_pred),
        index=label_encoder.classes_, columns=label_encoder.classes_,
    ))

    print("\nFeature importances:")
    importances = pd.Series(clf.feature_importances_, index=feature_cols).sort_values(ascending=False)
    print(importances.to_string())

    # Rule-based comparison -- only runs for flow-capture data (has syn_count/ack_count)
    baseline_preds = rule_based_baseline(df_test)
    if baseline_preds is not None:
        print("\n=== Rule-based baseline (SYN-rate heuristic) for comparison ===")
        print(pd.Series(baseline_preds).value_counts())
        print("(Compare this crude split against the ML model's precision/recall above")
        print(" to show quantitatively how much the ML approach improves detection.)")

    joblib.dump(
        {"model": clf, "label_encoder": label_encoder, "encoders": encoders, "features": feature_cols},
        args.model,
    )
    print(f"\nSaved trained model to {args.model}")


if __name__ == "__main__":
    main()
