import os
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, balanced_accuracy_score

TRAIN_FILES = ["attack_flows4.csv", "normal_flows4.csv"]
TEST_FILES = [
    "new_attack1.csv",
    "new_normal1.csv",
    "new_attack2.csv",
    "new_normal2.csv",
    "new_attack3.csv",
    "new_normal3.csv",
]

DROP_COLUMNS = {
    "label", "difficulty", "src_ip", "dst_ip",
    "src_port", "dst_port", "session",
}
FANOUT = [
    "src_distinct_ports",
    "src_distinct_hosts",
    "src_conn_rate",
]
SEEDS = [0, 1, 2, 3, 4]


def load_files(paths):
    frames = []
    for path in paths:
        if not os.path.exists(path):
            raise FileNotFoundError(path)

        df = pd.read_csv(path)
        name = os.path.basename(path).lower()

        # These are filename-derived labels, not independently verified labels.
        if "attack" in name:
            df["label"] = "portscan"
        elif "normal" in name:
            df["label"] = "normal"
        else:
            raise ValueError(f"Cannot infer label from {path}")

        frames.append(df)

    return pd.concat(frames, ignore_index=True)


def main():
    train = load_files(TRAIN_FILES)
    test = load_files(TEST_FILES)

    features = [
        c for c in train.columns
        if c not in DROP_COLUMNS and c in test.columns
    ]

    missing = [c for c in FANOUT if c not in features]
    if missing:
        raise ValueError(f"Missing fan-out features: {missing}")

    for col in features:
        train[col] = pd.to_numeric(train[col], errors="raise")
        test[col] = pd.to_numeric(test[col], errors="raise")

    if train[features].isna().any().any():
        raise ValueError("Missing values in training features")
    if test[features].isna().any().any():
        raise ValueError("Missing values in test features")

    feature_sets = {
        "All features (baseline)": features,
        "Without duration and bytes_per_second": [
            c for c in features
            if c not in {"duration", "bytes_per_second"}
        ],
        "Fan-out features only": FANOUT,
    }

    X_train = train
    y_train = train["label"]
    X_test = test
    y_test = test["label"]

    print("Training rows:", len(train), y_train.value_counts().to_dict())
    print("Test rows:", len(test), y_test.value_counts().to_dict())
    print("\nNOTE: test labels are assigned from filenames.")
    print("These results are exploratory, not independent validation.")

    results = []

    for name, cols in feature_sets.items():
        missing_cols = [
            c for c in cols
            if c not in X_train.columns or c not in X_test.columns
        ]
        if missing_cols:
            raise ValueError(f"{name}: missing columns {missing_cols}")

        accuracies = []
        balanced = []

        for seed in SEEDS:
            model = RandomForestClassifier(
                n_estimators=200,
                max_depth=15,
                random_state=seed,
                class_weight="balanced",
            )
            model.fit(X_train[cols], y_train)
            pred = model.predict(X_test[cols])

            accuracies.append(accuracy_score(y_test, pred))
            balanced.append(balanced_accuracy_score(y_test, pred))

        results.append({
            "experiment": name,
            "feature_count": len(cols),
            "accuracy_mean": np.mean(accuracies),
            "accuracy_std": np.std(accuracies),
            "balanced_accuracy_mean": np.mean(balanced),
            "balanced_accuracy_std": np.std(balanced),
        })

    print("\n--- Ablation results across seeds ---")
    print(pd.DataFrame(results).to_string(
        index=False,
        formatters={
            "accuracy_mean": "{:.4f}".format,
            "accuracy_std": "{:.4f}".format,
            "balanced_accuracy_mean": "{:.4f}".format,
            "balanced_accuracy_std": "{:.4f}".format,
        },
    ))


if __name__ == "__main__":
    main()
