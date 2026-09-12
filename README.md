# AI-Based Network Intrusion Detection System

A lightweight, flow-based Network Intrusion Detection System (NIDS) that captures live traffic, engineers statistical + fan-out features per flow, and classifies traffic as **normal** or **portscan** using a Random Forest classifier — with both an offline benchmark (NSL-KDD) and a real-time live detection mode.

Built as a course project for Computer Networks (BCSE308L/P), but usable as a general-purpose learning/demo NIDS.

## Features

- 📡 **Live packet capture** via Scapy, grouped into bidirectional flows
- 🧮 **Flow-level feature extraction** — duration, packet/byte counts, inter-arrival time, TCP flag counts
- 🎯 **Fan-out (scan-signature) features** — distinct destination ports/hosts and connection rate per source IP, computed from genuine new-connection attempts (SYN-only) so normal server replies aren't mistaken for a scan
- 🌲 **Random Forest classifier** (scikit-learn) with automatic feature/column detection — the same training script works on your own captured data *or* the NSL-KDD benchmark
- 📊 **NSL-KDD benchmark support** — reproducible offline evaluation against a standard, published intrusion detection dataset
- 🔴 **Real-time detection mode** — classifies live traffic in rolling time windows and prints alerts as they happen
- ⚖️ **Rule-based baseline comparison** — see how much the ML approach improves over a simple SYN-rate heuristic

## Architecture

```
Live Network Traffic
        │
        ▼
capture_and_extract.py  ──►  Flow grouping + feature extraction
        │                     (per-flow stats + per-source fan-out)
        ▼
   flows.csv (label manually, or use prepare_nsl_kdd.py for a
              ready-made labeled benchmark instead)
        │
        ▼
  train_model.py  ──►  Random Forest classifier + evaluation
        │                (accuracy, precision/recall, confusion matrix,
        │                 feature importances, baseline comparison)
        ▼
  model.joblib
        │
        ▼
  live_detect.py  ──►  Real-time classification of live traffic
                         ([ALERT] / [info] per flow)
```

## Repository Structure

```
.
├── capture_and_extract.py   # Packet capture + flow/feature extraction
├── prepare_nsl_kdd.py       # NSL-KDD benchmark dataset preprocessing
├── train_model.py           # Train + evaluate the Random Forest classifier
├── live_detect.py           # Real-time detection on live traffic
├── requirements.txt
├── LICENSE
└── README.md
```

## Installation

Requires Python 3.9+ on Linux, macOS, or WSL (Windows Subsystem for Linux). Live packet capture requires root/administrator privileges.

```bash
git clone https://github.com/gokulmahabaga/ai-nids.git
cd ai-nids
pip install -r requirements.txt --break-system-packages
```

> **WSL users:** if `sudo python3 ...` fails with `ModuleNotFoundError`, root uses a separate environment from your user — install again with `sudo python3 -m pip install -r requirements.txt --break-system-packages`.

## Usage

### 1. Benchmark on NSL-KDD (no packet capture needed)

```bash
curl -sL -o KDDTrain_20Percent.txt "https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/KDDTrain%2B_20Percent.txt"
curl -sL -o KDDTest.txt "https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/KDDTest%2B.txt"
python3 prepare_nsl_kdd.py

python3 train_model.py --data nsl_kdd_train.csv --test-data nsl_kdd_test.csv --model nids_model.joblib
```

### 2. Capture and label your own traffic

```bash
# Capture (needs root for live sniffing)
sudo python3 capture_and_extract.py --iface eth0 --duration 60 --out flows.csv
# or, from an existing pcap file:
python3 capture_and_extract.py --pcap sample.pcap --out flows.csv
```

Open `flows.csv` and replace `unknown` in the `label` column with `normal` or an attack name (e.g. `portscan`) for each row — or use `sed` for a quick bulk pass:

```bash
sed -i 's/unknown/normal/g' flows.csv
```

### 3. Train on your own captured data

```bash
python3 train_model.py --data flows_labeled.csv --model demo_model.joblib
```

`train_model.py` auto-detects feature columns and encodes any categorical ones, so the same command works whether your CSV came from `capture_and_extract.py` or `prepare_nsl_kdd.py`.

### 4. Real-time detection

```bash
sudo python3 live_detect.py --iface eth0 --model demo_model.joblib --window 10
```

Runs indefinitely in rolling windows, printing a line per detected flow:

```
[info ] 10.0.0.2:53210 <-> 10.0.0.1:80  proto=6 pkts=24 bytes=14112 => normal
[ALERT] 10.0.0.5:40001 <-> 10.0.0.1:22  proto=6 pkts=2  bytes=116   => portscan
```

Add `--rounds N` to stop automatically after N windows instead of running forever. Press `Ctrl+C` to stop manually at any time.

## How the fan-out detection works

A single port-scan probe looks almost identical to a normal short connection attempt when you only look at *one flow in isolation* — both are short, low-packet TCP exchanges. The real signature of a scan is **one source contacting many different destination ports in a short time window**, which only shows up when you look *across* flows.

To capture this, `capture_and_extract.py` tracks, per source IP, over the whole capture window:

- `src_distinct_ports` — how many different destination ports this source has probed
- `src_distinct_hosts` — how many different destination hosts this source has contacted
- `src_conn_rate` — connection attempts per second from this source

These are computed only from genuine **new connection attempts** (a TCP `SYN` without a matching `ACK`) — not every packet — so that a busy server's normal replies to many different client ports aren't mistaken for a scan.

## Results

| Dataset | Accuracy | Notes |
|---|---|---|
| NSL-KDD (official test set, unseen attack types included) | 78.2% | Realistic benchmark — precision 0.97 / recall 0.64 on the attack class |
| Custom live capture (with fan-out features) | 100% | Small, controlled demo dataset (SYN port scan vs. real HTTP traffic) |

See [`docs/NIDS_Project_Report.docx`](docs/NIDS_Project_Report.docx) for the full write-up, including the diagnostic process behind the fan-out feature fix.

## Limitations

- Currently detects one attack type (TCP SYN port scanning) — extending to DoS/flood detection or the full NSL-KDD multiclass labels is a natural next step
- Fixed-window batch classification rather than per-packet streaming
- Small custom dataset; NSL-KDD is used for the more rigorous benchmark numbers

Contributions extending attack coverage or adding a proper streaming classifier are welcome.

## License

MIT — see [LICENSE](LICENSE).
