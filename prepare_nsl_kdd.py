#!/usr/bin/env python3
"""
prepare_nsl_kdd.py

Downloads/prepares the NSL-KDD dataset for the NIDS project.
NSL-KDD is already a labeled, feature-engineered dataset (41 features per
connection), so it's used as a standalone alternative to
capture_and_extract.py's flow features -- it does NOT need packet capture.

This script:
  1. Loads the raw KDDTrain+_20Percent.txt / KDDTest+.txt files (no headers)
  2. Adds the official 41 NSL-KDD column names + label + difficulty
  3. Collapses the 20+ specific attack labels into a binary
     "normal" / "attack" label
  4. Saves as nsl_kdd_train.csv / nsl_kdd_test.csv

Get the raw files first (already plain text, no registration needed):
  curl -sL -o KDDTrain_20Percent.txt \
    "https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/KDDTrain%2B_20Percent.txt"
  curl -sL -o KDDTest.txt \
    "https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/KDDTest%2B.txt"

Usage:
    python3 prepare_nsl_kdd.py
"""

import pandas as pd

COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
    "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    "label", "difficulty",
]


def main():
    train = pd.read_csv("KDDTrain_20Percent.txt", names=COLUMNS)
    test = pd.read_csv("KDDTest.txt", names=COLUMNS)

    # Collapse specific attack types (neptune, smurf, satan, ...) into "attack"
    for df in (train, test):
        df["label"] = df["label"].apply(lambda x: "normal" if x == "normal" else "attack")

    train.to_csv("nsl_kdd_train.csv", index=False)
    test.to_csv("nsl_kdd_test.csv", index=False)

    print("Train:", train.shape, train["label"].value_counts().to_dict())
    print("Test: ", test.shape, test["label"].value_counts().to_dict())
    print("\nSaved nsl_kdd_train.csv and nsl_kdd_test.csv")


if __name__ == "__main__":
    main()
