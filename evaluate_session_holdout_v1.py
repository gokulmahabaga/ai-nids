from pathlib import Path
import json

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)

ROOT = Path("experiments/mixed_capture_v4")
OUT = ROOT / "session_holdout_v1"

FEATURES = [
    "duration",
    "packet_count",
    "byte_count",
    "avg_packet_size",
    "avg_inter_arrival_time",
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "bytes_per_second",
]

LABELS = ["normal", "portscan"]

if OUT.exists():
    raise SystemExit(
        f"Output directory already exists: {OUT}\n"
        "Refusing to overwrite. Choose a new output directory."
    )

# Find exactly one labeled CSV per session.
sessions = []
for session_dir in sorted(ROOT.glob("session_*")):
    candidates = sorted((session_dir / "flows").glob("*labeled.csv"))
    if len(candidates) == 1:
        sessions.append((session_dir.name, candidates[0]))
    elif len(candidates) > 1:
        raise SystemExit(
            f"Multiple labeled CSVs in {session_dir}; "
            "select the correct one explicitly."
        )

if len(sessions) < 3:
    raise SystemExit(
        f"Need at least 3 labeled sessions; found {len(sessions)}."
    )

data = {}
for name, path in sessions:
    df = pd.read_csv(path)

    required = set(FEATURES + ["label"])
    missing = required - set(df.columns)
    if missing:
        raise SystemExit(f"{path} missing columns: {sorted(missing)}")

    df = df[df["label"].isin(LABELS)].copy()
    if set(df["label"].unique()) != set(LABELS):
        raise SystemExit(f"{path} does not contain both classes.")

    X = df[FEATURES].apply(pd.to_numeric, errors="coerce")
    if X.isna().any().any():
        raise SystemExit(f"Missing/nonnumeric feature values in {path}")

    data[name] = (X, df["label"].copy(), str(path))
    print(f"{name}: {len(df)} flows")
    print(df["label"].value_counts().to_dict())

if len(data) != len(sessions):
    raise SystemExit("Session loading mismatch.")

# Create output only after input validation.
OUT.mkdir(parents=True)
fold_results = []
all_predictions = []

for test_name, (X_test, y_test, test_path) in data.items():
    train_names = [name for name in data if name != test_name]
    X_train = pd.concat([data[name][0] for name in train_names])
    y_train = pd.concat([data[name][1] for name in train_names])

    model = RandomForestClassifier(
        n_estimators=200,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)
    pred = model.predict(X_test)

    cm = confusion_matrix(y_test, pred, labels=LABELS)
    result = {
        "test_session": test_name,
        "test_file": test_path,
        "training_sessions": train_names,
        "train_rows": int(len(y_train)),
        "test_rows": int(len(y_test)),
        "train_class_counts": {
            str(k): int(v) for k, v in y_train.value_counts().items()
        },
        "test_class_counts": {
            str(k): int(v) for k, v in y_test.value_counts().items()
        },
        "accuracy": float(accuracy_score(y_test, pred)),
        "balanced_accuracy": float(
            balanced_accuracy_score(y_test, pred)
        ),
        "precision_portscan": float(
            precision_score(
                y_test, pred, pos_label="portscan", zero_division=0
            )
        ),
        "recall_portscan": float(
            recall_score(
                y_test, pred, pos_label="portscan", zero_division=0
            )
        ),
        "f1_portscan": float(
            f1_score(
                y_test, pred, pos_label="portscan", zero_division=0
            )
        ),
        "confusion_matrix_labels": LABELS,
        "confusion_matrix_rows_true_columns_predicted": cm.tolist(),
        "classification_report": classification_report(
            y_test, pred, labels=LABELS, output_dict=True,
            zero_division=0
        ),
    }
    fold_results.append(result)

    print(f"\n=== Held-out session: {test_name} ===")
    print("Training sessions:", ", ".join(train_names))
    print("Train rows:", len(y_train), "| Test rows:", len(y_test))
    print("Confusion matrix (normal, portscan):")
    print(cm)
    print(f"Accuracy:          {result['accuracy']:.4f}")
    print(f"Balanced accuracy: {result['balanced_accuracy']:.4f}")
    print(f"Portscan precision:{result['precision_portscan']:.4f}")
    print(f"Portscan recall:   {result['recall_portscan']:.4f}")
    print(f"Portscan F1:       {result['f1_portscan']:.4f}")

    for idx, (truth, prediction) in enumerate(zip(y_test, pred)):
        all_predictions.append({
            "test_session": test_name,
            "row_index_in_session": int(idx),
            "true_label": truth,
            "predicted_label": prediction,
        })

# Persist the per-session results and predictions.
with open(OUT / "metrics.json", "x") as f:
    json.dump(fold_results, f, indent=2)

pd.DataFrame(all_predictions).to_csv(
    OUT / "predictions.csv", index=False
)

summary = pd.DataFrame([
    {
        "test_session": r["test_session"],
        "train_rows": r["train_rows"],
        "test_rows": r["test_rows"],
        "accuracy": r["accuracy"],
        "balanced_accuracy": r["balanced_accuracy"],
        "precision_portscan": r["precision_portscan"],
        "recall_portscan": r["recall_portscan"],
        "f1_portscan": r["f1_portscan"],
    }
    for r in fold_results
])
summary.to_csv(OUT / "summary.csv", index=False)

print("\n=== Fold summary ===")
print(summary.to_string(index=False))
print("\nSaved results to:", OUT)
print(
    "\nLIMITATION: Labels are procedure-derived and sessions share "
    "the same loopback capture design. Treat these results as "
    "exploratory, not as evidence of real-world generalization."
)
