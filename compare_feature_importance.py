import pandas as pd
import matplotlib.pyplot as plt

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)

DATA = "flows_labeled_v4.csv"
SEED = 42

df = pd.read_csv(DATA)
df = df[df["label"].isin(["normal", "portscan"])].copy()

# Identifier and label columns must not be used as model features.
excluded = {"src_ip", "src_port", "dst_ip", "dst_port", "label"}

# Stage 1: per-flow statistics and TCP flags.
per_flow = [
    c for c in df.columns
    if c not in excluded
    and c not in {
        "src_distinct_ports",
        "src_distinct_hosts",
        "src_conn_rate",
    }
]

# Stage 2: per-flow features plus source-level fan-out features.
with_fanout = per_flow + [
    "src_distinct_ports",
    "src_distinct_hosts",
    "src_conn_rate",
]

X_train_df, X_test_df, y_train, y_test = train_test_split(
    df,
    df["label"],
    test_size=0.25,
    random_state=SEED,
    stratify=df["label"],
)

results = {}

for name, features in [
    ("Stage 1: Per-flow", per_flow),
    ("Stage 2: With fan-out", with_fanout),
]:
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        random_state=SEED,
        class_weight="balanced",
    )

    model.fit(X_train_df[features], y_train)
    predictions = model.predict(X_test_df[features])

    print(f"\n{'=' * 60}")
    print(name)
    print("Features:", features)
    print(f"Accuracy: {accuracy_score(y_test, predictions):.4f}")
    print("\nClassification report:")
    print(classification_report(
        y_test, predictions, labels=["normal", "portscan"], zero_division=0
    ))
    print("Confusion matrix (rows=actual, columns=predicted):")
    print(pd.DataFrame(
        confusion_matrix(y_test, predictions, labels=["normal", "portscan"]),
        index=["actual normal", "actual portscan"],
        columns=["predicted normal", "predicted portscan"],
    ))

    importance = pd.Series(
        model.feature_importances_, index=features
    ).sort_values(ascending=False)

    results[name] = importance
    print("\nFeature importances:")
    print(importance.round(4).to_string())

# Save exact importance values for reporting.
importance_df = pd.concat(results, axis=1).fillna(0)
importance_df.to_csv("feature_importance_comparison.csv")

# Plot both experiments on a shared feature-importance scale.
fig, axes = plt.subplots(1, 2, figsize=(14, 7))

for ax, (name, importance) in zip(axes, results.items()):
    importance.sort_values().plot.barh(ax=ax)
    ax.set_title(name)
    ax.set_xlabel("Random Forest feature importance")
    ax.set_ylabel("Feature")

fig.suptitle(
    "Feature Importance: Per-Flow vs. Per-Flow + Fan-Out\n"
    "Current 581-row dataset; newly run experiment"
)
fig.tight_layout()
fig.savefig("figure2_regenerated.png", dpi=300, bbox_inches="tight")

print("\nSaved:")
print("  feature_importance_comparison.csv")
print("  figure2_regenerated.png")
