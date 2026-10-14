from pathlib import Path
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, balanced_accuracy_score

attack_files = [
    "attack_flows4.csv",
    "new_attack1.csv",
    "new_attack2.csv",
    "new_attack3.csv",
]
normal_files = [
    "normal_flows4.csv",
    "new_normal1.csv",
    "new_normal2.csv",
    "new_normal3.csv",
]

fanout = [
    "src_distinct_ports",
    "src_distinct_hosts",
    "src_conn_rate",
]

drop = {
    "label", "difficulty", "src_ip", "dst_ip",
    "src_port", "dst_port", "initiator_ip",
    "initiator_port", "session",
}

sessions = {}
for filename in attack_files + normal_files:
    if not Path(filename).exists():
        raise FileNotFoundError(filename)

    df = pd.read_csv(filename)
    df["label"] = "scan" if filename in attack_files else "normal"
    df["session"] = filename
    sessions[filename] = df

data = pd.concat(sessions.values(), ignore_index=True)
features = [
    c for c in data.columns
    if c not in drop and c != "session"
    and pd.api.types.is_numeric_dtype(data[c])
]

groups = {
    "All per-flow features": [c for c in features if c not in fanout],
    "Packet count only": [c for c in features if c == "packet_count"],
    "Duration only": [c for c in features if c == "duration"],
    "Byte count only": [c for c in features if c == "byte_count"],
    "Per-flow minus duration": [
        c for c in features if c not in fanout and c != "duration"
    ],
    "Per-flow minus packet count": [
        c for c in features if c not in fanout and c != "packet_count"
    ],
    "Fan-out only": [c for c in fanout if c in features],
}

results = []
for fold, (attack_holdout, normal_holdout) in enumerate(
    zip(attack_files, normal_files), start=1
):
    test = pd.concat(
        [sessions[attack_holdout], sessions[normal_holdout]],
        ignore_index=True,
    )
    train = pd.concat(
        [
            df for name, df in sessions.items()
            if name not in {attack_holdout, normal_holdout}
        ],
        ignore_index=True,
    )

    for group_name, cols in groups.items():
        if not cols:
            continue

        model = RandomForestClassifier(
            n_estimators=200,
            max_depth=15,
            class_weight="balanced",
            random_state=42,
        )
        model.fit(train[cols], train["label"])
        pred = model.predict(test[cols])

        results.append({
            "fold": fold,
            "heldout_attack": attack_holdout,
            "heldout_normal": normal_holdout,
            "feature_group": group_name,
            "features": ", ".join(cols),
            "accuracy": accuracy_score(test["label"], pred),
            "balanced_accuracy": balanced_accuracy_score(
                test["label"], pred
            ),
        })

result = pd.DataFrame(results)
output = "feature_ablation_results_v1.csv"

if Path(output).exists():
    raise FileExistsError(
        f"{output} already exists; rename the output before rerunning."
    )

result.to_csv(output, index=False)

print("\nMean results across folds:")
print(
    result.groupby("feature_group")[
        ["accuracy", "balanced_accuracy"]
    ].mean().sort_values("balanced_accuracy", ascending=False).round(4)
)
print(f"\nSaved {output}")
