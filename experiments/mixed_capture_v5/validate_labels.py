#!/usr/bin/env python3
"""Read-only CSV label audit for NIDS experiments.

This tool reports dataset quality and possible label-feature shortcuts. It never
changes, relabels, or overwrites the input CSV. It is a diagnostic, not proof
that labels are correct or independent.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

LABEL_NAMES = ("label", "class", "target", "category", "traffic_label")
PORT_NAMES = ("target_port", "dst_port", "destination_port", "dport")
TIME_NAMES = (
    "flow_start_epoch", "flow_start_utc", "timestamp", "time", "start_time",
    "start_time_utc", "flow_start", "start_timestamp",
)
FLOW_START_EPOCH_NAMES = ("flow_start_epoch", "start_epoch", "start_time_epoch")
FLOW_END_EPOCH_NAMES = ("flow_end_epoch", "end_epoch", "end_time_epoch")
FLOW_START_UTC_NAMES = ("flow_start_utc", "start_time_utc", "start_time", "timestamp")
FLOW_END_UTC_NAMES = ("flow_end_utc", "end_time_utc", "end_time")
EVENT_START_EPOCH_NAMES = ("start_epoch", "start_time_epoch")
EVENT_END_EPOCH_NAMES = ("end_epoch", "end_time_epoch")
EVENT_START_UTC_NAMES = ("start_time_utc", "start_time")
EVENT_END_UTC_NAMES = ("end_time_utc", "end_time")
UNKNOWN_LABELS = {"", "unknown", "uncertain", "unlabelled", "unlabeled", "null", "none", "nan"}


def find_column(fieldnames: list[str], candidates: tuple[str, ...]) -> str | None:
    by_lower = {name.strip().lower(): name for name in fieldnames}
    for candidate in candidates:
        if candidate in by_lower:
            return by_lower[candidate]
    return None


def load_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError("CSV is empty or has no header row")
        rows = list(reader)
        return list(reader.fieldnames), rows

def parse_epoch(value: str | None) -> float | None:
    """Parse a Unix timestamp without guessing units."""
    if value is None or not value.strip():
        return None
    try:
        return float(value.strip())
    except (TypeError, ValueError):
        return None


def parse_utc(value: str | None) -> float | None:
    """Parse an ISO-8601 timestamp and return Unix seconds."""
    if value is None or not value.strip():
        return None
    from datetime import datetime, timezone

    text = value.strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        # Naive timestamps are not safe to compare across time zones.
        return None
    return parsed.astimezone(timezone.utc).timestamp()


def interval_for_row(
    row: dict[str, str],
    fields: list[str],
    epoch_start_names: tuple[str, ...],
    epoch_end_names: tuple[str, ...],
    utc_start_names: tuple[str, ...],
    utc_end_names: tuple[str, ...],
) -> tuple[float, float] | None:
    """Get an interval from epoch fields first, then timezone-aware ISO fields."""
    start = parse_epoch(row.get(find_column(fields, epoch_start_names) or ""))
    end = parse_epoch(row.get(find_column(fields, epoch_end_names) or ""))
    if start is None:
        start = parse_utc(row.get(find_column(fields, utc_start_names) or ""))
    if end is None:
        end = parse_utc(row.get(find_column(fields, utc_end_names) or ""))
    if start is None or end is None or end < start:
        return None
    return start, end


def audit_event_overlaps(
    flow_fields: list[str],
    flow_rows: list[dict[str, str]],
    activity_log: Path | None,
) -> dict:
    """Summarize timestamp interval overlap; this does not prove causal attribution."""
    if activity_log is None:
        return {"performed": False, "reason": "No activity log supplied."}

    event_fields, event_rows = load_csv(activity_log)
    events = []
    skipped_events = 0
    for index, event in enumerate(event_rows, start=2):
        interval = interval_for_row(
            event, event_fields,
            EVENT_START_EPOCH_NAMES, EVENT_END_EPOCH_NAMES,
            EVENT_START_UTC_NAMES, EVENT_END_UTC_NAMES,
        )
        if interval is None:
            skipped_events += 1
            continue
        type_col = find_column(event_fields, ("activity_type",))
        label_col = find_column(event_fields, ("intended_label", "label"))
        id_col = find_column(event_fields, ("event_id",))
        events.append({
            "row": index,
            "start": interval[0],
            "end": interval[1],
            "activity_type": (event.get(type_col or "") or "").strip() or "unknown",
            "intended_label": (event.get(label_col or "") or "").strip() or "unknown",
            "event_id": (event.get(id_col or "") or "").strip() or f"row-{index}",
        })

    overlap_counts: Counter = Counter()
    overlap_by_type: dict[str, Counter] = defaultdict(Counter)
    overlap_by_label: dict[str, Counter] = defaultdict(Counter)
    flows_with_no_overlap = 0
    flows_with_multiple_events = 0
    flows_without_valid_interval = 0
    examples_no_overlap = []
    examples_multiple = []

    for index, flow in enumerate(flow_rows, start=2):
        interval = interval_for_row(
            flow, flow_fields,
            FLOW_START_EPOCH_NAMES, FLOW_END_EPOCH_NAMES,
            FLOW_START_UTC_NAMES, FLOW_END_UTC_NAMES,
        )
        if interval is None:
            flows_without_valid_interval += 1
            continue
        start, end = interval
        # Inclusive interval overlap; zero-duration flows can still match an event.
        matches = [event for event in events if start <= event["end"] and event["start"] <= end]
        overlap_counts[str(len(matches))] += 1
        if not matches:
            flows_with_no_overlap += 1
            if len(examples_no_overlap) < 5:
                examples_no_overlap.append({"csv_row": index, "flow_start_epoch": start, "flow_end_epoch": end})
        if len(matches) > 1:
            flows_with_multiple_events += 1
            if len(examples_multiple) < 5:
                examples_multiple.append({
                    "csv_row": index,
                    "event_ids": [event["event_id"] for event in matches],
                })
        for event in matches:
            overlap_by_type[event["activity_type"]]["overlapping_flows"] += 1
            overlap_by_type[event["activity_type"]]["distinct_events"] += 0
            overlap_by_label[event["intended_label"]]["overlapping_flows"] += 1

    for event in events:
        event["overlapping_flow_count"] = 0
        for flow in flow_rows:
            interval = interval_for_row(
                flow, flow_fields,
                FLOW_START_EPOCH_NAMES, FLOW_END_EPOCH_NAMES,
                FLOW_START_UTC_NAMES, FLOW_END_UTC_NAMES,
            )
            if interval and interval[0] <= event["end"] and event["start"] <= interval[1]:
                event["overlapping_flow_count"] += 1

    return {
        "performed": True,
        "method": "Inclusive overlap between flow start/end intervals and activity-event start/end intervals.",
        "flow_interval_columns": {
            "start": find_column(flow_fields, FLOW_START_EPOCH_NAMES) or find_column(flow_fields, FLOW_START_UTC_NAMES),
            "end": find_column(flow_fields, FLOW_END_EPOCH_NAMES) or find_column(flow_fields, FLOW_END_UTC_NAMES),
        },
        "event_interval_columns": {
            "start": find_column(event_fields, EVENT_START_EPOCH_NAMES) or find_column(event_fields, EVENT_START_UTC_NAMES),
            "end": find_column(event_fields, EVENT_END_EPOCH_NAMES) or find_column(event_fields, EVENT_END_UTC_NAMES),
        },
        "events_with_valid_intervals": len(events),
        "events_without_valid_intervals": skipped_events,
        "flows_with_valid_intervals": len(flow_rows) - flows_without_valid_interval,
        "flows_without_valid_intervals": flows_without_valid_interval,
        "flows_with_no_overlapping_event": flows_with_no_overlap,
        "flows_with_multiple_overlapping_events": flows_with_multiple_events,
        "flow_overlap_count_distribution": dict(overlap_counts),
        "overlapping_flows_by_activity_type": {key: dict(value) for key, value in overlap_by_type.items()},
        "overlapping_flows_by_intended_label": {key: dict(value) for key, value in overlap_by_label.items()},
        "event_overlap_counts": [
            {
                "event_id": event["event_id"],
                "activity_type": event["activity_type"],
                "intended_label": event["intended_label"],
                "overlapping_flows": event["overlapping_flow_count"],
            }
            for event in events
        ],
        "examples_flows_without_overlap": examples_no_overlap,
        "examples_flows_with_multiple_events": examples_multiple,
        "warning": (
            "Time overlap is evidence for review, not proof of causal attribution or correct labels. "
            "Check endpoints, protocol, target fields, and the original packet capture."
        ),
    }


def audit_activity_log(path: Path | None) -> dict:
    if path is None:
        return {"provided": False, "note": "No independent activity log supplied."}
    fields, rows = load_csv(path)
    lower_fields = {field.strip().lower() for field in fields}
    aliases = {
        "event_id": {"event_id"},
        "start_time": {"start_time", "start_time_utc"},
        "end_time": {"end_time", "end_time_utc"},
        "activity_type": {"activity_type"},
        "label": {"label", "intended_label"},
        "evidence": {"evidence"},
    }
    missing = sorted(
        logical for logical, accepted in aliases.items()
        if not (accepted & lower_fields)
    )
    return {
        "provided": True,
        "path": str(path),
        "rows": len(rows),
        "missing_required_columns": missing,
        "event_types": dict(Counter(
            (row.get(find_column(fields, ("activity_type",)) or "", "") or "").strip()
            for row in rows
        )),
        "warning": (
            "Presence of a log does not prove flow labels were correctly matched; "
            "verify timestamps and evidence against the original capture."
        ),
    }


def audit_dataset(path: Path, activity_log: Path | None = None) -> dict:
    fields, rows = load_csv(path)
    normalized_fields = [field.strip().lower() for field in fields]
    label_col = find_column(fields, LABEL_NAMES)
    port_col = find_column(fields, PORT_NAMES)

    blank_cells = 0
    missing_by_column = Counter()
    duplicate_rows = 0
    seen = set()
    for row in rows:
        for field in fields:
            value = (row.get(field) or "").strip()
            if not value:
                blank_cells += 1
                missing_by_column[field] += 1
        key = tuple((row.get(field) or "").strip() for field in fields)
        if key in seen:
            duplicate_rows += 1
        seen.add(key)

    result = {
        "input_file": str(path),
        "rows": len(rows),
        "columns": len(fields),
        "column_names": fields,
        "blank_cells": blank_cells,
        "blank_cells_by_column": dict(missing_by_column),
        "duplicate_complete_rows_after_first_occurrence": duplicate_rows,
        "label_column": label_col,
        "port_column": port_col,
        "read_only": True,
        "activity_log": audit_activity_log(activity_log),
        "warnings": [],
    }

    if label_col:
        labels = [(row.get(label_col) or "").strip() for row in rows]
        result["label_counts_including_unknown"] = dict(Counter(labels))
        result["unknown_or_blank_label_rows"] = sum(
            label.lower() in UNKNOWN_LABELS for label in labels
        )
    else:
        result["warnings"].append(
            "No recognizable label column found; use a column named label, class, "
            "target, category, or traffic_label."
        )

    if port_col and label_col:
        # This is a diagnostic association table only. It cannot establish how
        # labels were assigned, and it does not automatically remove any feature.
        crosstab: dict[str, Counter] = defaultdict(Counter)
        for row in rows:
            port = (row.get(port_col) or "").strip() or "<blank>"
            label = (row.get(label_col) or "").strip() or "<blank>"
            crosstab[port][label] += 1
        result["label_by_port"] = {
            port: dict(counts) for port, counts in sorted(
                crosstab.items(), key=lambda item: item[0]
            )
        }
        single_label_ports = [
            port for port, counts in crosstab.items()
            if len(counts) == 1 and port != "<blank>"
        ]
        if single_label_ports:
            result["warnings"].append(
                f"{len(single_label_ports)} destination-port values occur with only "
                "one label. If labels were assigned using ports, this is potential "
                "label leakage; inspect the labeling procedure and do not treat this "
                "association alone as proof of leakage."
            )

    start_col = find_column(fields, FLOW_START_EPOCH_NAMES) or find_column(fields, FLOW_START_UTC_NAMES)
    end_col = find_column(fields, FLOW_END_EPOCH_NAMES) or find_column(fields, FLOW_END_UTC_NAMES)
    time_col = find_column(fields, TIME_NAMES)
    if start_col and end_col:
        result["timestamp_columns"] = {"start": start_col, "end": end_col}
    elif time_col:
        result["timestamp_column"] = time_col
        result["warnings"].append(
            "Only a single timestamp column was found; interval-overlap checks need "
            "both a flow start and end time."
        )
    else:
        result["warnings"].append(
            "No recognizable timestamp column found. Independent event-to-flow "
            "matching may be difficult without timestamps."
        )

    result["event_overlap_audit"] = audit_event_overlaps(fields, rows, activity_log)
    overlap_audit = result["event_overlap_audit"]
    if overlap_audit.get("performed"):
        if overlap_audit.get("flows_without_valid_intervals", 0):
            result["warnings"].append(
                f"{overlap_audit['flows_without_valid_intervals']} flows have no valid start/end interval."
            )
        if overlap_audit.get("events_without_valid_intervals", 0):
            result["warnings"].append(
                f"{overlap_audit['events_without_valid_intervals']} activity events have no valid start/end interval."
            )
        if overlap_audit.get("flows_with_multiple_overlapping_events", 0):
            result["warnings"].append(
                "Some flows overlap multiple activity events; review these rows before using event-based labels."
            )

    if activity_log is None:
        result["warnings"].append(
            "No activity log was supplied. This audit cannot verify label provenance."
        )
    elif result["activity_log"].get("missing_required_columns"):
        result["warnings"].append(
            "The activity log is missing required columns; see activity_log details."
        )

    result["interpretation"] = (
        "This report checks structural quality and possible shortcuts only. "
        "Independent labels require traceable event evidence matched to captured "
        "flows, review of ambiguous cases, and evaluation on separate sessions."
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read-only audit of a NIDS flow CSV and optional activity log."
    )
    parser.add_argument("flows_csv", type=Path, help="Existing flow CSV to inspect")
    parser.add_argument(
        "--activity-log", type=Path, default=None,
        help="Optional CSV activity log based on independently recorded events",
    )
    parser.add_argument(
        "--json-out", type=Path, default=None,
        help="Optional new JSON output path (refuses to overwrite an existing file)",
    )
    args = parser.parse_args()

    if not args.flows_csv.is_file():
        parser.error(f"flow CSV not found: {args.flows_csv}")
    if args.activity_log is not None and not args.activity_log.is_file():
        parser.error(f"activity log not found: {args.activity_log}")
    if args.json_out is not None and args.json_out.exists():
        parser.error(f"refusing to overwrite existing output: {args.json_out}")

    try:
        report = audit_dataset(args.flows_csv, args.activity_log)
    except (OSError, UnicodeError, csv.Error, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    rendered = json.dumps(report, indent=2, ensure_ascii=False)
    print(rendered)
    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        # Exclusive create prevents accidental overwrite.
        with args.json_out.open("x", encoding="utf-8") as handle:
            handle.write(rendered + "\n")
        print(f"\nReport written to: {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
