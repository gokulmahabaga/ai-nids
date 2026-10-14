from pathlib import Path

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
)

TRAIN_FILES = {
    "attack_flows4.csv": "portscan",
    "normal_flows4.csv": "normal",
}

TEST_FILES = {
    "new_attack1.csv": "portscan",
    "new_attack2.csv": "portscan",
    "new_attack3.csv": "portscan",
    "new_normal1.csv": "normal",
    "new_normal2.csv": "normal",
    "new_normal3.csv": "normal",
}

CORE_FEATURES = [
    "protocol",
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

FANOUT_FEATURES = [
    "src_distinct_ports",
    "src_distinct_hosts",
    "src_conn_rate",
]

FEATURE_SETS = {
    "Flow-only": CORE_FEATURES,
    "Fan-out-only": FANOUT_FEATURES,
    "Combined": CORE_FEATURES + FANOUT_FEATURES,
}

LABELS = ["normal", "portscan"]


def load_sessions(file_labels):
    frames = []

    for filename, label in file_labels.items():
        path = Path(filename)

        if not path.is_file():
            raise FileNotFoundError(f"Required dataset missing: {path}")

        frame = pd.read_csv(path)

        if frame.empty:
            raise ValueError(f"Dataset is empty: {filename}")

        frame["label"] = label
        frame["session"] = path.name
        frames.append(frame)

    return pd.concat(frames, ignore_index=True)


train = load_sessions(TRAIN_FILES)
test = load_sessions(TEST_FILES)

print("Training rows:", len(train))
print("Training labels:")
print(train["label"].value_counts().to_string())

print("\nTest rows:", len(test))
print("Test labels:")
print(test["label"].value_counts().to_string())

print("\nTest sessions:")
print(test.groupby(["session", "label"]).size().to_string())

all_features = CORE_FEATURES + FANOUT_FEATURES

for name, frame in [("training", train), ("test", test)]:
    missing = [c for c in all_features if c not in frame.columns]
    if missing:
        raise ValueError(f"{name} data is missing columns: {missing}")

    for col in all_features:
        frame[col] = pd.to_numeric(frame[col], errors="raise")

    if frame[all_features].isna().any().any():
        raise ValueError(f"Missing feature values in {name} data")

print("\nFeature-set comparison")
print("All models use the same training and held-out test sessions.")

for name, features in FEATURE_SETS.items():
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        class_weight="balanced",
        random_state=42,
    )

    model.fit(train[features], train["label"])
    predictions = model.predict(test[features])
    truth = test["label"]

    print(f"\n{'=' * 16} {name} {'=' * 16}")
    print("Feature count:", len(features))
    print("Accuracy:", round(accuracy_score(truth, predictions), 4))
    print(
        "Balanced accuracy:",
        round(balanced_accuracy_score(truth, predictions), 4),
    )
    print(
        "Precision:",
        round(
            precision_score(
                truth, predictions, pos_label="portscan", zero_division=0
            ),
            4,
        ),
    )
    print(
        "Recall:",
        round(
            recall_score(
                truth, predictions, pos_label="portscan", zero_division=0
            ),
            4,
        ),
    )
    print(
        "F1-score:",
        round(
            f1_score(
                truth, predictions, pos_label="portscan", zero_division=0
            ),
            4,
        ),
    )

    print("\nConfusion matrix (rows=true, columns=predicted):")
    print("Label order:", LABELS)
    print(confusion_matrix(truth, predictions, labels=LABELS))

    print("\nClassification report:")
    print(
        classification_report(
            truth,
            predictions,
            labels=LABELS,
            target_names=LABELS,
            zero_division=0,
        )
    )

    print("Per-session results:")
    results = test[["session", "label"]].copy()
    results["prediction"] = predictions
    results["correct"] = results["label"] == results["prediction"]

    print(
        results.groupby("session")
        .agg(
            rows=("correct", "size"),
            correct=("correct", "sum"),
            accuracy=("correct", "mean"),
        )
        .to_string()
    )

print(
    "\nCaution: the test sessions are held out by filename, but the "
    "results still depend on verified labels, capture independence, "
    "and consistent feature-generation methods."
)
