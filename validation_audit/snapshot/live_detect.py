#!/usr/bin/env python3
"""
live_detect.py

Step 5 of the AI-based NIDS project: real-time detection using a model
trained by train_model.py on flow-capture data (e.g. demo_model.joblib).

Continuously captures short windows of live traffic, builds flows the same
way capture_and_extract.py does, extracts the same features, and classifies
each flow with the trained model -- printing an alert line per flow.

Usage:
    sudo python3 live_detect.py --iface eth0 --model demo_model.joblib

    # Adjust how often it re-checks traffic (default 5 seconds per window)
    sudo python3 live_detect.py --iface eth0 --model demo_model.joblib --window 5

Requires: pip install scapy scikit-learn pandas joblib --break-system-packages
Must be run in the same folder as capture_and_extract.py, and with a model
trained on flow-capture data (NOT the NSL-KDD model -- different feature set).
"""

import argparse
import signal

import joblib
import pandas as pd
from scapy.all import sniff

from capture_and_extract import build_flows

_stop_requested = False


def _handle_sigint(signum, frame):
    global _stop_requested
    _stop_requested = True
    print("\nStopping after this window (Ctrl+C again to force-quit)...")


def classify_flows(flows, activity, bundle):
    """Turns the live flows dict into feature rows and runs the model on them."""
    model = bundle["model"]
    features = bundle["features"]
    label_encoder = bundle.get("label_encoder") or bundle.get("encoder")

    rows = []
    keys = []
    for key, stats in flows.items():
        rows.append(stats.to_row(key, source_activity=activity))
        keys.append(key)

    if not rows:
        return []

    df = pd.DataFrame(rows)
    X = df[features]
    preds = model.predict(X)
    labels = label_encoder.inverse_transform(preds)

    return list(zip(keys, rows, labels))


def print_alert(key, row, label):
    src_ip, src_port, dst_ip, dst_port, proto = key
    tag = "ALERT" if label != "normal" else "info "
    print(
        f"[{tag}] {src_ip}:{src_port} <-> {dst_ip}:{dst_port} "
        f"proto={proto} pkts={row['packet_count']} bytes={row['byte_count']} "
        f"=> {label}"
    )


def main():
    parser = argparse.ArgumentParser(description="Real-time NIDS detection from live traffic")
    parser.add_argument("--iface", required=True, help="Network interface to sniff (e.g. eth0)")
    parser.add_argument("--model", required=True, help="Path to a model saved by train_model.py")
    parser.add_argument("--window", type=int, default=5, help="Seconds per capture window (default 5)")
    parser.add_argument("--rounds", type=int, default=0, help="Number of windows to run, 0 = run forever")
    args = parser.parse_args()

    bundle = joblib.load(args.model)
    print(f"Loaded model with features: {bundle['features']}")
    print(f"Sniffing on {args.iface} in {args.window}s windows. Ctrl+C to stop.\n")

    signal.signal(signal.SIGINT, _handle_sigint)

    round_num = 0
    while True:
        round_num += 1
        if args.rounds and round_num > args.rounds:
            break
        if _stop_requested:
            print("Stopped.")
            break

        packets = sniff(iface=args.iface, timeout=args.window)

        if _stop_requested:
            print("Stopped.")
            break

        if not packets:
            print(f"[window {round_num}] no packets captured")
            continue

        flows, activity = build_flows(packets)
        results = classify_flows(flows, activity, bundle)

        print(f"--- window {round_num}: {len(packets)} packets, {len(flows)} flows ---")
        for key, row, label in results:
            print_alert(key, row, label)
        print()


if __name__ == "__main__":
    main()
