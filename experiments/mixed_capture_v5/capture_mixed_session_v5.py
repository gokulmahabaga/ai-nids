#!/usr/bin/env python3
"""Timestamped, local-only mixed-traffic capture for NIDS research.

Captures TCP loopback traffic while issuing benign HTTP requests to a local
test server and an authorized Nmap SYN scan against 127.0.0.1 only.
Creates a new session directory and never overwrites a prior session.

Requires Linux/WSL, tcpdump, nmap, and Scapy. Run with sudo so tcpdump can
capture packets. This script intentionally does not assign flow labels.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
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
HTTP_PORT = 8765
SCAN_FIRST_PORT = 1
SCAN_LAST_PORT = 1000


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def write_csv(path: Path, fields: list[str], rows: list[dict]) -> None:
    with path.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
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
    parser.add_argument("--out-root", type=Path, default=ROOT / "experiments" / "mixed_capture_v5" / "sessions",
                        help="Root for new timestamped session directories")
    parser.add_argument("--http-port", type=int, default=HTTP_PORT)
    parser.add_argument("--scan-first-port", type=int, default=SCAN_FIRST_PORT)
    parser.add_argument("--scan-last-port", type=int, default=SCAN_LAST_PORT)
    parser.add_argument("--scan-delay", default="5ms", help="Nmap scan delay (default: 5ms)")
    parser.add_argument("--http-timeout", type=float, default=5.0)
    args = parser.parse_args()

    if not sys.platform.startswith("linux"):
        parser.error("Run inside Linux/WSL.")
    if os.geteuid() != 0:
        parser.error("Run with sudo so tcpdump can capture packets.")
    if not (1 <= args.http_port <= 65535):
        parser.error("--http-port must be between 1 and 65535")
    if not (1 <= args.scan_first_port <= args.scan_last_port <= 65535):
        parser.error("Invalid scan port range")
    for executable in ("tcpdump", "nmap"):
        if shutil.which(executable) is None:
            parser.error(f"Required executable not found: {executable}")

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

    events: list[dict] = []
    requests: list[dict] = []
    scan_state: dict = {"return_code": None, "error": ""}
    event_lock = threading.Lock()

    def record(event_type: str, label_intended: str, target_ip: str,
               target_port: str, protocol: str, evidence: str, status: str = "") -> str:
        event_id = uuid.uuid4().hex
        row = {
            "event_id": event_id,
            "start_time_utc": utc_now(),
            "end_time_utc": "",
            "start_epoch": f"{time.time():.6f}",
            "end_epoch": "",
            "activity_type": event_type,
            "intended_label": label_intended,
            "target_ip": target_ip,
            "target_port": target_port,
            "protocol": protocol,
            "status": status,
            "evidence": evidence,
        }
        with event_lock:
            events.append(row)
        return event_id

    server = ThreadingHTTPServer(("127.0.0.1", args.http_port), Handler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    tcpdump_proc = None
    tcpdump_file = tcpdump_log.open("x", encoding="utf-8")
    capture_started = utc_now()
    try:
        tcpdump_proc = subprocess.Popen(
            ["tcpdump", "-i", "lo", "-nn", "-s", "0", "-B", "4096", "-U",
             "-w", str(pcap_path), "tcp and host 127.0.0.1"],
            stdout=tcpdump_file, stderr=subprocess.STDOUT,
        )
        time.sleep(1.0)
        if tcpdump_proc.poll() is not None:
            raise RuntimeError(f"tcpdump exited early; inspect {tcpdump_log}")

        # Benign local HTTP requests with varied paths and response sizes.
        paths = [
            "health", "status?detail=short", "report?size=medium",
            "catalog?category=books", "search?q=network+security",
            "metrics?format=text", "help", "health?repeat=2",
            "report?size=large&section=summary", "status?detail=full",
        ]
        for index, path in enumerate(paths, start=1):
            event_id = record("http_request", "normal", "127.0.0.1",
                              str(args.http_port), "tcp", "local HTTP client and server log")
            start_iso, start_epoch = events[-1]["start_time_utc"], events[-1]["start_epoch"]
            status, response_bytes, error = "", 0, ""
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{args.http_port}/{path}", timeout=args.http_timeout
                ) as response:
                    payload = response.read()
                    status, response_bytes = str(response.status), len(payload)
            except Exception as exc:
                error = str(exc)
            end_iso, end_epoch = utc_now(), f"{time.time():.6f}"
            with event_lock:
                event = next(e for e in events if e["event_id"] == event_id)
                event["end_time_utc"], event["end_epoch"] = end_iso, end_epoch
                event["status"] = status or "error"
            requests.append({
                "event_id": event_id, "start_time_utc": start_iso, "end_time_utc": end_iso,
                "start_epoch": start_epoch, "end_epoch": end_epoch, "path": path,
                "target_ip": "127.0.0.1", "target_port": args.http_port,
                "http_status": status, "response_bytes": response_bytes, "error": error,
            })
            time.sleep(0.15 + (index % 4) * 0.12)

        # Scan only the local loopback host. The event log records the exact
        # interval and command used; flow labels remain unknown until reviewed.
        scan_cmd = [
            "nmap", "-sS", "-Pn", "-n", "-p",
            f"{args.scan_first_port}-{args.scan_last_port}",
            "--scan-delay", args.scan_delay, "127.0.0.1",
        ]
        scan_event_id = record(
            "authorized_local_syn_scan", "portscan", "127.0.0.1",
            f"{args.scan_first_port}-{args.scan_last_port}", "tcp",
            "nmap stdout/stderr saved in metadata/nmap_output.txt",
        )
        scan_start_iso, scan_start_epoch = events[-1]["start_time_utc"], events[-1]["start_epoch"]
        try:
            result = subprocess.run(scan_cmd, capture_output=True, text=True, timeout=120)
            scan_state["return_code"] = result.returncode
            scan_state["command"] = scan_cmd
            (metadata_dir / "nmap_output.txt").write_text(
                result.stdout + "\n--- STDERR ---\n" + result.stderr, encoding="utf-8"
            )
            scan_status = f"return_code={result.returncode}"
        except Exception as exc:
            scan_state["error"] = str(exc)
            scan_status = f"error={exc}"
        scan_end_iso, scan_end_epoch = utc_now(), f"{time.time():.6f}"
        with event_lock:
            event = next(e for e in events if e["event_id"] == scan_event_id)
            event["end_time_utc"], event["end_epoch"], event["status"] = scan_end_iso, scan_end_epoch, scan_status

    finally:
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
        "event_id", "start_time_utc", "end_time_utc", "start_epoch", "end_epoch",
        "path", "target_ip", "target_port", "http_status", "response_bytes", "error",
    ], requests)

    packets = rdpcap(str(pcap_path)) if pcap_path.exists() else []
    initial_syns = 0
    scan_syns = 0
    http_related_packets = 0
    for pkt in packets:
        if IP not in pkt or TCP not in pkt:
            continue
        tcp = pkt[TCP]
        flags = int(tcp.flags)
        if flags & 0x02 and not flags & 0x10:
            initial_syns += 1
            if args.scan_first_port <= int(tcp.dport) <= args.scan_last_port:
                scan_syns += 1
        if int(tcp.sport) == args.http_port or int(tcp.dport) == args.http_port:
            http_related_packets += 1

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
        "initial_syn_packets_to_scan_port_range": scan_syns,
        "http_related_packets_observed": http_related_packets,
        "http_requests_attempted": len(requests),
        "http_requests_successful": sum(r["http_status"] == "200" for r in requests),
        "scan": scan_state,
        "labeling_policy": "Capture script records intended activities only; flow labels are not assigned here.",
        "warning": "Loopback-only exploratory data. Validate event-to-flow matches and inspect tcpdump drop statistics before evaluation.",
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
        print("Interrupted. Check the new session's metadata and PCAP before using it.", file=sys.stderr)
        raise SystemExit(130)
