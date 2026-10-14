from pathlib import Path
import pandas as pd
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, balanced_accuracy_score

ROOT = Path("experiments/mixed_capture_v4")
OUT = ROOT / "single_feature_check_v1"

if OUT.exists():
    raise SystemExit(f"Refusing to overwrite {OUT}")

features = [
    "byte_count",
    "packet_count",
    "duration",
    "avg_packet_size",
    "syn_count",
]

sessions = {}
for folder in sorted(ROOT.glob("session_*")):
    files = list((folder / "flows").glob("*labeled.csv"))
    if len(files) != 1:
        continue
    df = pd.read_csv(files[0])
    df = df[df["label"].isin(["normal", "portscan"])].copy()
    sessions[folder.name] = df

if len(sessions) != 3:
    raise SystemExit(f"Expected 3 sessions; found {len(sessions)}")

rows = []
for feature in features:
    for test_name, test_df in sessions.items():
        train_df = pd.concat([
            df for name, df in sessions.items() if name != test_name
        ], ignore_index=True)

        model = DecisionTreeClassifier(
            max_depth=2, class_weight="balanced", random_state=42
        )
        model.fit(train_df[[feature]], train_df["label"])
        pred = model.predict(test_df[[feature]])

        rows.append({
            "feature": feature,
            "test_session": test_name,
            "accuracy": accuracy_score(test_df["label"], pred),
            "balanced_accuracy": balanced_accuracy_score(
                test_df["label"], pred
            ),
        })

OUT.mkdir(parents=True)
result = pd.DataFrame(rows)
result.to_csv(OUT / "results.csv", index=False)

print(result.to_string(index=False))
print("\nMean results by feature:")
print(
    result.groupby("feature")[["accuracy", "balanced_accuracy"]]
    .mean().sort_values("balanced_accuracy", ascending=False)
)
print("\nSaved:", OUT / "results.csv")
