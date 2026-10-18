# Mixed Capture v5: Timestamped Capture and Label Validation

This version adds a timestamped, loopback-only capture pipeline and read-only
label audit tools. It creates new session directories and does not modify the
existing v1-v4 datasets. Captured flow labels remain `unknown` until reviewed
against independent evidence.

## 1. Requirements

Run inside Linux/WSL. Install the dependencies if needed:

```bash
sudo apt update
sudo apt install tcpdump nmap
python3 -m pip install scapy
```

Capture requires sudo for packet capture. Use only the explicitly configured
local loopback target (`127.0.0.1`) in this script.

## 2. Capture a new session

From the repository root:

```bash
sudo python3 experiments/mixed_capture_v5/capture_mixed_session_v5.py
```

The script creates a unique directory under
`experiments/mixed_capture_v5/sessions/` containing:

- `pcap/loopback_mixed.pcap`: packet capture with packet timestamps.
- `metadata/activity_events.csv`: event IDs, UTC start/end timestamps, epoch
  timestamps, activity types, intended labels, targets, and evidence references.
- `metadata/http_requests.csv`: request intervals, paths, HTTP status and sizes.
- `metadata/nmap_output.txt`: scan output for the local test host.
- `metadata/tcpdump.log`: capture diagnostics, including drop statistics when
  reported by tcpdump.
- `metadata/capture_summary.json`: session metadata and counts.

The activity log records the planned activity and evidence locations; it does
not by itself prove every extracted flow's label. Do not treat its
`intended_label` as an automatically verified flow label.

## 3. Extract flows while preserving timestamps

Use the PCAP path printed by the capture script. Choose a new output path:

```bash
python3 experiments/mixed_capture_v5/extract_timestamped_flows.py \
  --pcap experiments/mixed_capture_v5/sessions/SESSION_ID/pcap/loopback_mixed.pcap \
  --out experiments/mixed_capture_v5/sessions/SESSION_ID/flows_timestamped.csv
```

Replace `SESSION_ID` with the actual generated directory name. The extractor
includes `flow_start_epoch`, `flow_end_epoch`, `flow_start_utc`, and
`flow_end_utc`. It writes labels as `unknown` and refuses to overwrite an
existing output. It does not perform event-to-flow matching.

## 4. Audit labels and schema

```bash
python3 experiments/mixed_capture_v5/validate_labels.py \
  experiments/mixed_capture_v5/sessions/SESSION_ID/flows_timestamped.csv \
  --activity-log experiments/mixed_capture_v5/sessions/SESSION_ID/metadata/activity_events.csv \
  --json-out experiments/mixed_capture_v5/sessions/SESSION_ID/label_audit.json
```

The validator checks structural quality and label/port associations. It is a
diagnostic, not proof that labels are correct. The timestamped extractor and
event log provide evidence for a later matcher; ambiguous matches must remain
`unknown`, rather than being guessed from destination port alone.

## 5. Important limitations

- This is a loopback-only exploratory capture, not representative of a real
  production network.
- The scan and HTTP activities share the same host, so traffic may overlap.
- Flow boundaries and timestamps need careful review; one activity interval can
  contain multiple flows, and a flow can be ambiguous when events overlap.
- Check tcpdump drop statistics and compare event times with PCAP packets before
  using a session for evaluation.
- Split model evaluation by complete capture session and keep final test
  sessions untouched during tuning.

See [dataset_methodology.md](dataset_methodology.md) for the evaluation protocol.
