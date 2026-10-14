import os
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split

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
    "src_port", "dst_port", "session"
}
FANOUT_FEATURES = [
    "src_distinct_ports",
    "src_distinct_hosts",
    "src_conn_rate",
]
SEEDS = [0, 1, 2, 3, 4]


def load_files(paths):
    frames = []
    for path in paths:
        if not os.path.exists(path):
            raise FileNotFoundError(f"File not found: {path}")
        df = pd.read_csv(path)
        filename = os.path.basename(path).lower()
        if "attack" in filename:
            df["label"] = "portscan"
        elif "normal" in filename:
            df["label"] = "normal"
        else:
            raise ValueError(f"Cannot determine label from {path}")
        df["session"] = filename
        frames.append(df)
    return pd.concat(frames, ignore_index=True)


def main():
    train = load_files(TRAIN_FILES)
    test = load_files(TEST_FILES)

    features = [
        col for col in train.columns
        if col not in DROP_COLUMNS and col in test.columns
    ]
    missing_fanout = [c for c in FANOUT_FEATURES if c not in features]
    if missing_fanout:
        raise ValueError(f"Missing fan-out features: {missing_fanout}")

    per_flow_features = [c for c in features if c not in FANOUT_FEATURES]
    full_features = per_flow_features + [
        c for c in FANOUT_FEATURES if c in features
    ]

    for col in full_features:
        train[col] = pd.to_numeric(train[col], errors="raise")
        test[col] = pd.to_numeric(test[col], errors="raise")

    if train[full_features].isna().any().any():
        raise ValueError("Training features contain missing values.")
    if test[full_features].isna().any().any():
        raise ValueError("Test features contain missing values.")

    print("TRAIN:", len(train), train["label"].value_counts().to_dict())
    print("TEST: ", len(test), test["label"].value_counts().to_dict())
    overlap = set(train["session"]) & set(test["session"])
    print("Train/test session overlap:", overlap if overlap else "none")

    y_test = test["label"]
    summary_rows, session_rows, importance_frames = [], [], []

    # Tune the simple threshold using only a validation split of training data.
    _, X_val, _, y_val = train_test_split(
        train[full_features],
        train["label"],
        test_size=0.25,
        random_state=42,
        stratify=train["label"],
    )
    port_values = np.sort(X_val["src_distinct_ports"].dropna().unique())
    if len(port_values) == 0:
        raise ValueError("No validation values for src_distinct_ports.")
    if len(port_values) == 1:
        thresholds = [float(port_values[0])]
    else:
        thresholds = (
            (port_values[:-1] + port_values[1:]) / 2
        ).tolist()

    best_threshold, best_val_score = None, -1.0
    for threshold in thresholds:
        val_pred = np.where(
            X_val["src_distinct_ports"] > threshold,
            "portscan",
            "normal",
        )
        score = balanced_accuracy_score(y_val, val_pred)
        if score > best_val_score:
            best_val_score = score
            best_threshold = float(threshold)

    print("\nVALIDATION-TUNED RULE")
    print("Selected threshold:", best_threshold)
    print(f"Validation balanced accuracy: {best_val_score:.4f}")

    for model_name, model_features in [
        ("RF per-flow", per_flow_features),
        ("RF with fan-out", full_features),
    ]:
        seed_accuracies, seed_balanced_accuracies = [], []
        seed_predictions = {}

        for seed in SEEDS:
            model = RandomForestClassifier(
                n_estimators=200,
                max_depth=15,
                random_state=seed,
                class_weight="balanced",
            )
            model.fit(train[model_features], train["label"])
            predictions = model.predict(test[model_features])
            seed_predictions[seed] = predictions
            seed_accuracies.append(accuracy_score(y_test, predictions))
            seed_balanced_accuracies.append(
                balanced_accuracy_score(y_test, predictions)
            )

            importance_frames.append(pd.DataFrame({
                "model": model_name,
                "seed": seed,
                "feature": model_features,
                "importance": model.feature_importances_,
            }))

            for session_name in test["session"].unique():
                mask = test["session"] == session_name
                session_rows.append({
                    "model": model_name,
                    "seed": seed,
                    "session": session_name,
                    "rows": int(mask.sum()),
                    "accuracy": accuracy_score(
                        y_test[mask], predictions[mask]
                    ),
                })

        print("\n" + "=" * 60)
        print(model_name)
        print("Features:", len(model_features))
        print(
            f"Accuracy across {len(SEEDS)} seeds: "
            f"{np.mean(seed_accuracies):.4f} +/- "
            f"{np.std(seed_accuracies):.4f}"
        )
        print(
            f"Balanced accuracy across seeds: "
            f"{np.mean(seed_balanced_accuracies):.4f} +/- "
            f"{np.std(seed_balanced_accuracies):.4f}"
        )

        # Classification report and confusion matrix explicitly use seed 0.
        pred0 = seed_predictions[0]
        print("\nSeed 0 classification report:")
        print(classification_report(
            y_test, pred0,
            labels=["normal", "portscan"],
            digits=3, zero_division=0,
        ))
        print("Seed 0 confusion matrix (actual rows):")
        print(confusion_matrix(
            y_test, pred0, labels=["normal", "portscan"]
        ))

        summary_rows.append({
            "model": model_name,
            "features": len(model_features),
            "mean_accuracy": np.mean(seed_accuracies),
            "std_accuracy": np.std(seed_accuracies),
            "mean_balanced_accuracy": np.mean(seed_balanced_accuracies),
            "std_balanced_accuracy": np.std(seed_balanced_accuracies),
        })

    rule_predictions = np.where(
        test["src_distinct_ports"] > best_threshold,
        "portscan",
        "normal",
    )
    rule_accuracy = accuracy_score(y_test, rule_predictions)
    rule_balanced_accuracy = balanced_accuracy_score(
        y_test, rule_predictions
    )

    print("\n" + "=" * 60)
    print("Validation-tuned src_distinct_ports rule")
    print("Threshold:", best_threshold)
    print(f"Test accuracy: {rule_accuracy:.4f}")
    print(f"Test balanced accuracy: {rule_balanced_accuracy:.4f}")
    print(classification_report(
        y_test, rule_predictions,
        labels=["normal", "portscan"],
        digits=3, zero_division=0,
    ))
    print("Confusion matrix (actual rows):")
    print(confusion_matrix(
        y_test, rule_predictions, labels=["normal", "portscan"]
    ))

    summary_rows.append({
        "model": "Validation-tuned port threshold",
        "features": 1,
        "mean_accuracy": rule_accuracy,
        "std_accuracy": 0.0,
        "mean_balanced_accuracy": rule_balanced_accuracy,
        "std_balanced_accuracy": 0.0,
    })

    for session_name in test["session"].unique():
        mask = test["session"] == session_name
        session_rows.append({
            "model": "Validation-tuned port threshold",
            "seed": "validation_tuned",
            "session": session_name,
            "rows": int(mask.sum()),
            "accuracy": accuracy_score(y_test[mask], rule_predictions[mask])
        })

    pd.DataFrame(summary_rows).to_csv(
        "session_model_comparison.csv", index=False
    )
    pd.DataFrame(session_rows).to_csv(
        "session_accuracies.csv", index=False
    )
    mean_importance = (
        pd.concat(importance_frames, ignore_index=True)
        .groupby(["model", "feature"], as_index=False)["importance"]
        .mean()
        .sort_values(["model", "importance"], ascending=[True, False])
    )
    mean_importance.to_csv("mean_feature_importances.csv", index=False)

    print("\nSaved:")
    print("  session_model_comparison.csv")
    print("  session_accuracies.csv")
    print("  mean_feature_importances.csv")


if __name__ == "__main__":
    main()
