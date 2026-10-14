from pathlib import Path
import itertools
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    precision_score,
    recall_score,
    confusion_matrix,
)

ATTACK_FILES = [
    "attack_flows4.csv",
    "new_attack1.csv",
    "new_attack2.csv",
    "new_attack3.csv",
]
NORMAL_FILES = [
    "normal_flows4.csv",
    "new_normal1.csv",
    "new_normal2.csv",
    "new_normal3.csv",
]

FANOUT = [
    "src_distinct_ports",
    "src_distinct_hosts",
    "src_conn_rate",
]
DROP = {
    "label", "difficulty", "src_ip", "dst_ip",
    "src_port", "dst_port", "initiator_ip",
    "initiator_port", "session",
}

def load_session(filename, label):
    df = pd.read_csv(filename)
    df["label"] = label
    df["session"] = Path(filename).name
    return df

def main():
    files = ATTACK_FILES + NORMAL_FILES
    missing = [f for f in files if not Path(f).exists()]
    if missing:
        raise FileNotFoundError(f"Missing CSVs: {missing}")

    sessions = {}
    for f in ATTACK_FILES:
        sessions[f] = load_session(f, "portscan")
    for f in NORMAL_FILES:
        sessions[f] = load_session(f, "normal")

    all_data = pd.concat(sessions.values(), ignore_index=True)
    features = [
        c for c in all_data.columns
        if c not in DROP and c not in {"session"}
    ]
    features = [
        c for c in features
        if pd.api.types.is_numeric_dtype(
            pd.to_numeric(all_data[c], errors="coerce")
        )
    ]
    for c in features:
        all_data[c] = pd.to_numeric(all_data[c], errors="coerce")

    if all_data[features].isna().any().any():
        bad = all_data[features].columns[
            all_data[features].isna().any()
        ].tolist()
        raise ValueError(f"Missing/non-numeric feature values: {bad}")

    missing_fanout = [c for c in FANOUT if c not in features]
    if missing_fanout:
        raise ValueError(f"Missing fan-out columns: {missing_fanout}")

    per_flow = [c for c in features if c not in FANOUT]
    feature_sets = {
        "RF per-flow": per_flow,
        "RF with fan-out": features,
        "RF without distinct ports": [
            c for c in features if c != "src_distinct_ports"
        ],
    }

    # Four folds: each holds out one attack session and one normal session.
    # Every fold's training data contains both classes.
    results = []
    predictions_out = []
    fold_pairs = list(zip(ATTACK_FILES, NORMAL_FILES))

    for fold, (attack_holdout, normal_holdout) in enumerate(fold_pairs, 1):
        heldout_names = {attack_holdout, normal_holdout}
        test_parts = [
            sessions[attack_holdout],
            sessions[normal_holdout],
        ]
        train_parts = [
            df for name, df in sessions.items()
            if name not in heldout_names
        ]
        train = pd.concat(train_parts, ignore_index=True)
        test = pd.concat(test_parts, ignore_index=True)

        if train["label"].nunique() != 2 or test["label"].nunique() != 2:
            raise ValueError(f"Fold {fold} does not contain both classes.")

        print(
            f"\nFold {fold}: held out "
            f"{Path(attack_holdout).name} + "
            f"{Path(normal_holdout).name}"
        )
        print(f"  Train rows: {len(train)}; test rows: {len(test)}")

        for model_name, cols in feature_sets.items():
            model = RandomForestClassifier(
                n_estimators=200,
                max_depth=15,
                class_weight="balanced",
                random_state=42,
            )
            model.fit(train[cols], train["label"])
            pred = model.predict(test[cols])
            y = test["label"]

            cm = confusion_matrix(
                y, pred, labels=["normal", "portscan"]
            )
            tn, fp, fn, tp = cm.ravel()

            row = {
                "fold": fold,
                "heldout_attack_session": Path(attack_holdout).name,
                "heldout_normal_session": Path(normal_holdout).name,
                "model": model_name,
                "features": len(cols),
                "train_rows": len(train),
                "test_rows": len(test),
                "accuracy": accuracy_score(y, pred),
                "balanced_accuracy": balanced_accuracy_score(y, pred),
                "precision_portscan": precision_score(
                    y, pred, pos_label="portscan", zero_division=0
                ),
                "recall_portscan": recall_score(
                    y, pred, pos_label="portscan", zero_division=0
                ),
                "tn": int(tn), "fp": int(fp),
                "fn": int(fn), "tp": int(tp),
            }
            results.append(row)

            fold_predictions = test[["session", "label"]].copy()
            fold_predictions["fold"] = fold
            fold_predictions["model"] = model_name
            fold_predictions["prediction"] = pred
            predictions_out.append(fold_predictions)

            print(
                f"  {model_name}: accuracy={row['accuracy']:.3f}, "
                f"balanced_accuracy={row['balanced_accuracy']:.3f}, "
                f"precision={row['precision_portscan']:.3f}, "
                f"recall={row['recall_portscan']:.3f}"
            )

    result_df = pd.DataFrame(results)
    pred_df = pd.concat(predictions_out, ignore_index=True)

    result_path = "leave_one_session_out_results_v1.csv"
    pred_path = "leave_one_session_out_predictions_v1.csv"
    if Path(result_path).exists() or Path(pred_path).exists():
        raise FileExistsError(
            "Output already exists; rename the output paths in the script "
            "before rerunning to avoid overwriting results."
        )

    result_df.to_csv(result_path, index=False)
    pred_df.to_csv(pred_path, index=False)

    print("\n=== Mean across four held-out session pairs ===")
    print(
        result_df.groupby("model")[
            ["accuracy", "balanced_accuracy",
             "precision_portscan", "recall_portscan"]
        ].mean().round(4)
    )
    print("\nSaved:")
    print(f"  {result_path}")
    print(f"  {pred_path}")
    print(
        "\nCaution: labels are inferred from filenames, and the "
        "source-activity features are constant within sessions. "
        "Treat these results as exploratory, not independent validation."
    )

if __name__ == "__main__":
    main()
