import joblib
import pandas as pd
from pathlib import Path
from sklearn.metrics import (
    accuracy_score, balanced_accuracy_score,
    precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)

bundle = joblib.load("nids_model.pkl")
model = bundle["model"]
features = bundle["features"]
encoders = bundle.get("encoders", {})
label_encoder = bundle.get("label_encoder") or bundle.get("encoder")

files = [
    ("new_attack1.csv", "portscan"),
    ("new_attack2.csv", "portscan"),
    ("new_attack3.csv", "portscan"),
    ("new_normal1.csv", "normal"),
    ("new_normal2.csv", "normal"),
    ("new_normal3.csv", "normal"),
]

def encode_features(X):
    X = X.copy()
    for col, encoder in encoders.items():
        if col in X.columns:
            known = set(encoder.classes_)
            X[col] = X[col].map(
                lambda v: encoder.transform([v])[0]
                if v in known else -1
            )
    return X

def normalize_label(value):
    value = str(value).strip().lower()
    if value in {"normal", "benign", "0"}:
        return 0
    if value in {"portscan", "port_scan", "attack", "1"}:
        return 1
    return None

all_true, all_pred = [], []
print("MODEL:", type(model).__name__)
print("FEATURE COUNT:", len(features))

for filename, expected_class in files:
    path = Path(filename)
    if not path.exists():
        print(f"\nERROR: Missing file: {filename}")
        continue

    df = pd.read_csv(path)
    missing = [f for f in features if f not in df.columns]
    print(f"\n{filename}: {len(df)} rows")

    if missing:
        print("Missing model features:", missing)
        print("Available columns:", list(df.columns))
        continue

    X = encode_features(df[features])
    pred = model.predict(X).astype(int)

    # These files are treated as single-class sessions based on
    # their filenames. Verify this against the actual capture labels.
    true_class = 1 if expected_class == "portscan" else 0
    y = [true_class] * len(pred)

    print("Expected class:", expected_class)
    print("Predicted counts:", pd.Series(pred).value_counts().sort_index().to_dict())
    print("Accuracy:", round(accuracy_score(y, pred), 4))
    print("Balanced accuracy:", round(
        balanced_accuracy_score(y, pred), 4
    ))
    print("Confusion matrix [[TN, FP], [FN, TP]]:")
    print(confusion_matrix(y, pred, labels=[0, 1]))

    all_true.extend(y)
    all_pred.extend(pred)

if all_true:
    print("\n" + "=" * 45)
    print("COMBINED SESSION RESULTS")
    print("Flows evaluated:", len(all_true))
    print("Accuracy:", round(accuracy_score(all_true, all_pred), 4))
    print("Balanced accuracy:", round(
        balanced_accuracy_score(all_true, all_pred), 4
    ))
    print("Precision:", round(
        precision_score(all_true, all_pred, zero_division=0), 4
    ))
    print("Recall:", round(
        recall_score(all_true, all_pred, zero_division=0), 4
    ))
    print("F1-score:", round(
        f1_score(all_true, all_pred, zero_division=0), 4
    ))
    print("Confusion matrix [[TN, FP], [FN, TP]]:")
    print(confusion_matrix(all_true, all_pred, labels=[0, 1]))
    print("\nClassification report:")
    print(classification_report(
        all_true, all_pred,
        labels=[0, 1], target_names=["normal", "portscan"],
        zero_division=0
    ))
