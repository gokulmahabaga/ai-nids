# Mixed Capture v5: Label Audit Starter

This folder adds a read-only dataset audit and a template for recording activity
ground truth. It does not modify existing datasets or relabel flows.

## 1. Run the validator

From the repository root:

```bash
python3 experiments/mixed_capture_v5/validate_labels.py path/to/flows.csv
```

To also inspect an activity log:

```bash
python3 experiments/mixed_capture_v5/validate_labels.py path/to/flows.csv \
  --activity-log experiments/mixed_capture_v5/activity_log_template.csv
```

To save a JSON report, choose a new output path. The script refuses to overwrite
an existing report:

```bash
python3 experiments/mixed_capture_v5/validate_labels.py path/to/flows.csv \
  --json-out experiments/mixed_capture_v5/audit_report.json
```

Do not use the example rows in the template as real ground truth. Copy the
template to a new filename and replace the examples with events actually
recorded during your own authorized captures.

## 2. What the validator checks

- Row/column counts, blank cells, and duplicate complete rows.
- Recognizable label column and counts, including unknown/blank labels.
- Destination-port/label associations that may deserve leakage investigation.
- Whether an activity log was provided and whether expected columns exist.

The validator is diagnostic only. It does not prove labels are correct, infer
labels, or change source files.

## 3. Next step

After the activity log has real entries and the flow CSV schema is confirmed,
implement and test a separate flow-to-event matcher. Ambiguous matches should
remain unknown rather than being guessed from destination port alone.

See [dataset_methodology.md](dataset_methodology.md) for the proposed protocol.
