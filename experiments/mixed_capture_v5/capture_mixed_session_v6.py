#!/usr/bin/env python3
"""Capture timestamped mixed HTTP and SYN-scan traffic on loopback only.

This v6 experiment deliberately sends benign HTTP requests before, during, and
after a local Nmap SYN scan. The default scan range includes the HTTP server's
port so target-port range alone is not a reliable class identifier. It records
activity intervals but does not assign flow labels.

Requires Linux/WSL, tcpdump, nmap, and Scapy. Run with sudo for packet capture.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import random
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from scapy.all import IP, TCP, rdpcap

ROOT = Path(__file__).resolve().parent
DEFAULT_HTTP_PORT = 8765
DEFAULT_SCAN_FIRST_PORT = 8000
DEFAULT_SCAN_LAST_PORT = 9000


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def write_csv(path: Path, fields: list[str], rows: list[dict]) -> None:
    with path.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Varied but deterministic response sizes for repeatable benign traffic.
        body = ("Local benign test response.\n" + ("sample-" * (1 + len(self.path) % 80))).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out-root", type=Path, default=ROOT / "sessions",
        help="Root for unique session directories (default: this script's sessions/)",
    )
    parser.add_argument("--http-port", type=int, default=DEFAULT_HTTP_PORT)
    parser.add_argument("--scan-first-port", type=int, default=DEFAULT_SCAN_FIRST_PORT)
    parser.add_argument("--scan-last-port", type=int, default=DEFAULT_SCAN_LAST_PORT)
    parser.add_argument("--scan-delay", default="5ms", help="Nmap scan delay (default: 5ms)")
    parser.add_argument("--http-timeout", type=float, default=5.0)
    parser.add_argument("--during-interval", type=float, default=0.30,
                        help="Approximate interval between benign requests during scan")
    parser.add_argument("--pre-requests", type=int, default=5)
    parser.add_argument("--post-requests", type=int, default=5)
    parser.add_argument("--seed", type=int, default=None,
                        help="Optional random seed for request timing and paths")
    args = parser.parse_args()

    if not sys.platform.startswith("linux"):
        parser.error("Run inside Linux/WSL.")
    if os.geteuid() != 0:
        parser.error("Run with sudo so tcpdump can capture packets.")
    if not (1 <= args.http_port <= 65535):
        parser.error("--http-port must be between 1 and 65535")
    if not (1 <= args.scan_first_port <= args.scan_last_port <= 65535):
        parser.error("Invalid scan port range")
    if args.http_timeout <= 0 or args.during_interval <= 0:
        parser.error("--http-timeout and --during-interval must be positive")
    if args.pre_requests < 0 or args.post_requests < 0:
        parser.error("--pre-requests and --post-requests cannot be negative")
    if not (args.scan_first_port <= args.http_port <= args.scan_last_port):
        parser.error(
            "For this experiment, the scan range must include --http-port "
            "to reduce the target-port shortcut. Adjust the range or HTTP port."
        )
    for executable in ("tcpdump", "nmap"):
        if shutil.which(executable) is None:
            parser.error(f"Required executable not found: {executable}")

    rng = random.Random(args.seed)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")
    session = args.out_root / f"session_{stamp}_{uuid.uuid4().hex[:6]}"
    session.mkdir(parents=True, exist_ok=False)
    pcap_dir, metadata_dir = session / "pcap", session / "metadata"
    pcap_dir.mkdir()
    metadata_dir.mkdir()
    pcap_path = pcap_dir / "loopback_mixed.pcap"
    tcpdump_log = metadata_dir / "tcpdump.log"
    events_path = metadata_dir / "activity_events.csv"
    requests_path = metadata_dir / "http_requests.csv"
    summary_path = metadata_dir / "capture_summary.json"
    nmap_path = metadata_dir / "nmap_output.txt"

    events: list[dict] = []
    requests: list[dict] = []
    scan_state: dict = {"return_code": None, "error": ""}
    event_lock = threading.Lock()
    request_lock = threading.Lock()
    stop_during_http = threading.Event()
    during_http_state = {"attempted": 0, "successful": 0, "errors": 0}

    def record(event_type: str, intended_label: str, target_port: str, evidence: str) -> str:
        event_id = uuid.uuid4().hex
        now_iso, now_epoch = utc_now(), f"{time.time():.6f}"
        row = {
            "event_id": event_id,
            "start_time_utc": now_iso,
            "end_time_utc": "",
            "start_epoch": now_epoch,
            "end_epoch": "",
            "activity_type": event_type,
            "intended_label": intended_label,
            "target_ip": "127.0.0.1",
            "target_port": str(target_port),
            "protocol": "tcp",
            "status": "started",
            "evidence": evidence,
        }
        with event_lock:
            events.append(row)
        return event_id

    def finish_event(event_id: str, status: str) -> tuple[str, str]:
        end_iso, end_epoch = utc_now(), f"{time.time():.6f}"
        with event_lock:
            event = next(e for e in events if e["event_id"] == event_id)
            event["end_time_utc"] = end_iso
            event["end_epoch"] = end_epoch
            event["status"] = status
        return end_iso, end_epoch

    def send_http_request(path: str, phase: str) -> dict:
        event_id = record("http_request", "normal", args.http_port,
                          f"local HTTP client/server; phase={phase}")
        with event_lock:
            event = next(e for e in events if e["event_id"] == event_id)
            start_iso, start_epoch = event["start_time_utc"], event["start_epoch"]
        status, response_bytes, error = "", 0, ""
        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{args.http_port}/{path}",
                headers={"User-Agent": "mixed-capture-v6/1.0"},
            )
            with urllib.request.urlopen(request, timeout=args.http_timeout) as response:
                payload = response.read()
                status, response_bytes = str(response.status), len(payload)
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
        end_iso, end_epoch = finish_event(event_id, status or "error")
        row = {
            "event_id": event_id, "phase": phase,
            "start_time_utc": start_iso, "end_time_utc": end_iso,
            "start_epoch": start_epoch, "end_epoch": end_epoch,
            "path": path, "target_ip": "127.0.0.1",
            "target_port": args.http_port, "http_status": status,
            "response_bytes": response_bytes, "error": error,
        }
        with request_lock:
            requests.append(row)
        return row

    paths = [
        "health", "status?detail=short", "report?size=medium",
        "catalog?category=books", "search?q=network+security",
        "metrics?format=text", "help", "health?repeat=2",
        "report?size=large&section=summary", "status?detail=full",
        "items?limit=3", "profile?view=compact", "summary?format=plain",
    ]

    def during_scan_http_worker() -> None:
        index = 0
        while not stop_during_http.is_set():
            path = paths[index % len(paths)]
            row = send_http_request(path, "during_scan")
            with request_lock:
                during_http_state["attempted"] += 1
                if row["http_status"] == "200":
                    during_http_state["successful"] += 1
                else:
                    during_http_state["errors"] += 1
            index += 1
            # Jitter helps avoid a fixed request cadence; this is not a traffic model.
            stop_during_http.wait(args.during_interval * rng.uniform(0.65, 1.35))

    server = ThreadingHTTPServer(("127.0.0.1", args.http_port), Handler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    tcpdump_proc = None
    tcpdump_file = tcpdump_log.open("x", encoding="utf-8")
    capture_started = utc_now()
    scan_started = False
    try:
        tcpdump_proc = subprocess.Popen(
            ["tcpdump", "-i", "lo", "-nn", "-s", "0", "-B", "4096", "-U",
             "-w", str(pcap_path), "tcp and host 127.0.0.1"],
            stdout=tcpdump_file, stderr=subprocess.STDOUT,
        )
        time.sleep(1.0)
        if tcpdump_proc.poll() is not None:
            raise RuntimeError(f"tcpdump exited early; inspect {tcpdump_log}")

        # Benign activity before the scan.
        for index in range(args.pre_requests):
            send_http_request(paths[index % len(paths)], "before_scan")
            time.sleep(rng.uniform(0.08, 0.25))

        scan_cmd = [
            "nmap", "-sS", "-Pn", "-n", "-p",
            f"{args.scan_first_port}-{args.scan_last_port}",
            "--scan-delay", args.scan_delay, "127.0.0.1",
        ]
        scan_event_id = record(
            "authorized_local_syn_scan", "portscan",
            f"{args.scan_first_port}-{args.scan_last_port}",
            "nmap stdout/stderr saved in metadata/nmap_output.txt",
        )
        with event_lock:
            scan_event = next(e for e in events if e["event_id"] == scan_event_id)
            scan_start_iso, scan_start_epoch = scan_event["start_time_utc"], scan_event["start_epoch"]
        scan_started = True

        worker = threading.Thread(target=during_scan_http_worker, daemon=True)
        worker.start()
        try:
            result = subprocess.run(scan_cmd, capture_output=True, text=True, timeout=120)
            scan_state["return_code"] = result.returncode
            scan_state["command"] = scan_cmd
            nmap_path.write_text(
                result.stdout + "\n--- STDERR ---\n" + result.stderr, encoding="utf-8"
            )
            scan_status = f"return_code={result.returncode}"
        except Exception as exc:
            scan_state["error"] = f"{type(exc).__name__}: {exc}"
            scan_state["command"] = scan_cmd
            scan_status = f"error={type(exc).__name__}: {exc}"
            nmap_path.write_text(scan_state["error"] + "\n", encoding="utf-8")
        finally:
            stop_during_http.set()
            worker.join(timeout=args.http_timeout + 2.0)

        scan_end_iso, scan_end_epoch = finish_event(scan_event_id, scan_status)
        scan_state.update({
            "start_time_utc": scan_start_iso, "end_time_utc": scan_end_iso,
            "start_epoch": scan_start_epoch, "end_epoch": scan_end_epoch,
        })

        # More benign traffic after the scan.
        for index in range(args.post_requests):
            send_http_request(paths[(index + args.pre_requests) % len(paths)], "after_scan")
            time.sleep(rng.uniform(0.08, 0.25))

    finally:
        stop_during_http.set()
        if tcpdump_proc is not None and tcpdump_proc.poll() is None:
            tcpdump_proc.send_signal(signal.SIGINT)
            try:
                tcpdump_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                tcpdump_proc.terminate()
                tcpdump_proc.wait(timeout=5)
        tcpdump_file.close()
        server.shutdown()
        server.server_close()

    capture_ended = utc_now()
    write_csv(events_path, [
        "event_id", "start_time_utc", "end_time_utc", "start_epoch", "end_epoch",
        "activity_type", "intended_label", "target_ip", "target_port", "protocol",
        "status", "evidence",
    ], events)
    write_csv(requests_path, [
        "event_id", "phase", "start_time_utc", "end_time_utc", "start_epoch", "end_epoch",
        "path", "target_ip", "target_port", "http_status", "response_bytes", "error",
    ], requests)

    packets = rdpcap(str(pcap_path)) if pcap_path.exists() else []
    initial_syns = scan_range_syns = http_related_packets = 0
    for pkt in packets:
        if IP not in pkt or TCP not in pkt:
            continue
        tcp = pkt[TCP]
        flags = int(tcp.flags)
        if flags & 0x02 and not flags & 0x10:
            initial_syns += 1
            if args.scan_first_port <= int(tcp.dport) <= args.scan_last_port:
                scan_range_syns += 1
        if int(tcp.sport) == args.http_port or int(tcp.dport) == args.http_port:
            http_related_packets += 1

    tcpdump_text = tcpdump_log.read_text(encoding="utf-8", errors="replace") if tcpdump_log.exists() else ""
    summary = {
        "session_directory": str(session),
        "capture_started_utc": capture_started,
        "capture_ended_utc": capture_ended,
        "interface": "lo",
        "host": "127.0.0.1",
        "pcap": str(pcap_path),
        "activity_log": str(events_path),
        "http_request_log": str(requests_path),
        "packet_count": len(packets),
        "initial_tcp_syn_packets_observed": initial_syns,
        "initial_syn_packets_to_scan_port_range": scan_range_syns,
        "http_related_packets_observed": http_related_packets,
        "http_requests_attempted": len(requests),
        "http_requests_successful": sum(r["http_status"] == "200" for r in requests),
        "http_requests_by_phase": {
            phase: {
                "attempted": sum(r["phase"] == phase for r in requests),
                "successful": sum(r["phase"] == phase and r["http_status"] == "200" for r in requests),
            }
            for phase in ("before_scan", "during_scan", "after_scan")
        },
        "scan": scan_state,
        "tcpdump_drop_statistics_reported": any(
            phrase in tcpdump_text.lower()
            for phrase in ("packets dropped by kernel", "packets dropped by interface")
        ),
        "tcpdump_log_tail": tcpdump_text.strip().splitlines()[-5:],
        "labeling_policy": "Capture script records intended activities only; flow labels are not assigned here.",
        "warning": (
            "Loopback-only exploratory data. The scan range includes the HTTP server port and "
            "benign requests run during the scan, but event-interval overlap can be ambiguous. "
            "Review packet-level evidence and use whole-session evaluation; do not infer labels "
            "from target ports or timestamps alone."
        ),
    }
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    print(f"\nNew session saved to: {session}")
    print("Existing sessions and flow CSVs were not modified.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("Interrupted. Inspect the new session's metadata and PCAP before use.", file=sys.stderr)
        raise SystemExit(130)
