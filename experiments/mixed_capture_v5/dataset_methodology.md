# Dataset diversity and independent labeling protocol

## Purpose

Improve the credibility of the NIDS evaluation by diversifying traffic, recording
ground truth independently of model features, and testing on held-out sessions.
This document is a protocol; it does not claim that these steps have already
been completed.

## Data collection

Collect traffic only on systems and networks that you own or are explicitly
authorized to test. Preserve each capture as a separate session and record the
capture interface, timezone, software/configuration, start/end time, and any
capture-drop counters.

Include a range of benign activity rather than relying on a single scripted HTTP
workload. Examples include varied HTTP request/response sizes, repeated and
persistent connections, authorized file transfers, DNS lookups, idle periods,
and ordinary connectivity checks where visible on the chosen interface. Vary
authorized scan sessions in a controlled lab and document each configuration.
Do not deliberately alter data to force a desired model score.

## Independent activity log

Use `activity_log_template.csv` as a starting template. Create one row per
planned/observed activity event and record timestamps with an explicit timezone,
activity type, intended label, target, protocol, and evidence path (for example,
application/server logs, authorized scan output, and the corresponding PCAP).

The log is evidence about what was run, not automatic proof that every flow
belongs to that event. Match flows to events using documented timestamps,
protocol, endpoints, and packet-level evidence. Do not use destination port as
the sole label rule. A benign flow occurring during a scan remains benign when
independent evidence supports that interpretation. Mark ambiguous flows
`unknown` and exclude them from primary supervised training/evaluation; report
how many were excluded and why.

Keep ground-truth annotations separate from model feature CSVs. Record who or
what produced each label and retain a review trail for corrections.

## Validation

Run `validate_labels.py` to check CSV structure, blank cells, duplicate rows,
label counts, unknown labels, and label/port associations. The script is
read-only and cannot verify that an event log is truthful or that flow-to-event
matching is correct. Review warnings against the original capture and logs.

Before model evaluation, confirm that labels were not generated from the same
feature used by the model. If a feature is intrinsically part of the labeling
rule, exclude it from the feature set and document the rationale. Association
between a port and a label is a warning to investigate, not by itself proof of
leakage.

## Evaluation design

Split by complete capture session, never randomly by flow when flows from the
same session could appear in both train and test. Use separate training,
validation, and final-test sessions. Do not tune on the final test set. Report
per-session confusion matrices and class-wise precision, recall, F1, false
positive rate, class counts, and the number of sessions. Compare against simple
baselines such as byte count alone to identify possible shortcuts.

## Limitations to disclose

Generated traffic in a controlled environment may have systematic differences
between classes. A high score within this environment does not establish
performance on independently collected network traffic. Report class imbalance,
unknown/excluded flows, capture environment, label provenance, and any remaining
limitations explicitly.
