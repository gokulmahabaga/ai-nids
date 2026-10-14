from pathlib import Path
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, balanced_accuracy_score,
    precision_score, recall_score, f1_score, confusion_matrix
)

ATTACK = [
    "attack_flows4.csv", "new_attack1.csv",
    "new_attack2.csv", "new_attack3.csv"
]
NORMAL = [
    "normal_flows4.csv", "new_normal1.csv",
    "new_normal2.csv", "new_normal3.csv"
]

PER_FLOW = [
    "protocol", "duration", "packet_count", "byte_count",
    "avg_packet_size", "avg_inter_arrival_time",
    "syn_count", "ack_count", "fin_count", "rst_count",
    "bytes_per_second"
]
FANOUT = ["src_distinct_ports", "src_distinct_hosts", "src_conn_rate"]
GROUPS = {
    "Per-flow only": PER_FLOW,
    "Per-flow + fan-out": PER_FLOW + FANOUT,
    "Fan-out only": FANOUT,
}
OUTPUT = Path("rapid_comparison_results_20261014.csv")

if OUTPUT.exists():
    raise FileExistsError(f"{OUTPUT} exists; refusing to overwrite it.")

sessions = {}
for filename in ATTACK + NORMAL:
    if not Path(filename).is_file():
        raise FileNotFoundError(filename)
    df = pd.read_csv(filename)
    df["label"] = "portscan" if filename in ATTACK else "normal"
    df["session"] = filename
    sessions[filename] = df

required = set(PER_FLOW + FANOUT)
for filename, df in sessions.items():
    missing = sorted(required - set(df.columns))
    if missing:
        raise ValueError(f"{filename} missing features: {missing}")
    df[list(required)] = df[list(required)].apply(
        pd.to_numeric, errors="raise"
    )
    if df[list(required)].isna().any().any():
        raise ValueError(f"Missing feature values in {filename}")

results = []
for fold, (attack_file, normal_file) in enumerate(zip(ATTACK, NORMAL), 1):
    test = pd.concat(
        [sessions[attack_file], sessions[normal_file]],
        ignore_index=True
    )
    train = pd.concat(
        [df for name, df in sessions.items()
         if name not in {attack_file, normal_file}],
        ignore_index=True
    )

    print(f"\nFOLD {fold}: held out {attack_file} + {normal_file}")
    print(f"Training rows: {len(train)} | Test rows: {len(test)}")

    for name, columns in GROUPS.items():
        model = RandomForestClassifier(
            n_estimators=200,
            max_depth=15,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1
        )
        model.fit(train[columns], train["label"])
        pred = model.predict(test[columns])
        y = test["label"]
        tn, fp, fn, tp = confusion_matrix(
            y, pred, labels=["normal", "portscan"]
        ).ravel()

        row = {
            "fold": fold,
            "heldout_attack": attack_file,
            "heldout_normal": normal_file,
            "model": name,
            "feature_count": len(columns),
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
            "f1_portscan": f1_score(
                y, pred, pos_label="portscan", zero_division=0
            ),
            "tn": int(tn), "fp": int(fp),
            "fn": int(fn), "tp": int(tp),
        }
        results.append(row)
        print(
            f"{name}: accuracy={row['accuracy']:.4f}, "
            f"balanced_acc={row['balanced_accuracy']:.4f}, "
            f"precision={row['precision_portscan']:.4f}, "
            f"recall={row['recall_portscan']:.4f}, "
            f"F1={row['f1_portscan']:.4f}, "
            f"TN={tn} FP={fp} FN={fn} TP={tp}"
        )

result = pd.DataFrame(results)
result.to_csv(OUTPUT, index=False)

print("\n=== Mean metrics across four folds ===")
print(result.groupby("model")[
    ["accuracy", "balanced_accuracy", "precision_portscan",
     "recall_portscan", "f1_portscan"]
].mean().round(4).to_string())

print(f"\nSaved new results to: {OUTPUT}")
print("Caution: labels are inferred from filenames; results are exploratory.")
