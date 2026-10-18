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
TIME_NAMES = ("timestamp", "time", "start_time", "flow_start", "start_timestamp")
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


def audit_activity_log(path: Path | None) -> dict:
    if path is None:
        return {"provided": False, "note": "No independent activity log supplied."}
    fields, rows = load_csv(path)
    required = {"event_id", "start_time", "end_time", "activity_type", "label", "evidence"}
    lower_fields = {field.strip().lower() for field in fields}
    missing = sorted(required - lower_fields)
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

    time_col = find_column(fields, TIME_NAMES)
    if time_col:
        result["timestamp_column"] = time_col
        result["note"] = (
            "Timestamp format is not assumed or parsed automatically. Normalize "
            "timestamps to a documented timezone before matching to activity logs."
        )
    else:
        result["warnings"].append(
            "No recognizable timestamp column found. Independent event-to-flow "
            "matching may be difficult without timestamps."
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
