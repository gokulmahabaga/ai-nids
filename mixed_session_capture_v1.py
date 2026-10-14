import csv
import json
import os
import subprocess
import threading
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from scapy.all import AsyncSniffer, wrpcap

ROOT = Path.home() / "ai-nids"
BASE = ROOT / "experiments" / "mixed_capture_v2"
STAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
OUT = BASE / f"session_{STAMP}"

# Never overwrite an existing experiment.
OUT.mkdir(parents=True, exist_ok=False)
(OUT / "pcap").mkdir()
(OUT / "metadata").mkdir()

PCAP = OUT / "pcap" / "mixed_session_v1.pcap"
EVENTS = OUT / "metadata" / "activity_log.csv"
SCAN_LOG = OUT / "metadata" / "nmap_output.txt"
SUMMARY = OUT / "metadata" / "capture_summary.json"

events = []
server = None
sniffer = None
packets = []
errors = []

def log_event(activity, detail):
    events.append({
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - start_time, 3),
        "activity": activity,
        "detail": detail,
    })

start_time = time.monotonic()

try:
    # Start a local HTTP server on loopback only.
    server = subprocess.Popen(
        ["python3", "-m", "http.server", "8765", "--bind", "127.0.0.1"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Wait for the server to become ready.
    ready = False
    for _ in range(30):
        try:
            with urllib.request.urlopen(
                "http://127.0.0.1:8765/", timeout=1
            ) as response:
                if response.status == 200:
                    ready = True
                    break
        except Exception:
            time.sleep(0.2)

    if not ready:
        raise RuntimeError("Local HTTP server did not become ready.")

    # Capture only on loopback. No external host is scanned.
    sniffer = AsyncSniffer(iface="lo")
    sniffer.start()
    time.sleep(1)

    def make_http_request(i):
        url = f"http://127.0.0.1:8765/?mixed_session_request={i}"
        log_event("normal_http_start", f"GET {url}")
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                status = response.status
                response.read()
            log_event("normal_http_result", f"request={i}, status={status}")
        except Exception as exc:
            errors.append(f"HTTP request {i}: {exc}")
            log_event("normal_http_error", f"request={i}, error={exc}")

    # Normal traffic before the scan.
    for i in range(1, 4):
        make_http_request(i)
        time.sleep(0.3)

    # Run the scan concurrently with more normal HTTP traffic.
    def run_scan():
        cmd = [
            "nmap", "-sS", "-Pn", "-n", "-T4",
            "-p", "1-1000", "--exclude-ports", "8765",
            "127.0.0.1",
        ]
        log_event("scan_start", "Authorized SYN scan of 127.0.0.1 ports 1-1000, excluding 8765")
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120
            )
            SCAN_LOG.write_text(
                result.stdout + "\n--- STDERR ---\n" + result.stderr
            )
            log_event("scan_result", f"return_code={result.returncode}")
            if result.returncode != 0:
                errors.append(f"Nmap exited with code {result.returncode}")
        except Exception as exc:
            errors.append(f"Nmap: {exc}")
            SCAN_LOG.write_text(str(exc))
            log_event("scan_error", str(exc))

    scan_thread = threading.Thread(target=run_scan)
    scan_thread.start()

    for i in range(4, 11):
        make_http_request(i)
        time.sleep(0.5)

    scan_thread.join()
    time.sleep(2)

finally:
    if sniffer is not None:
        try:
            packets = sniffer.stop()
        except Exception as exc:
            errors.append(f"Capture stop: {exc}")

    if server is not None:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()

    wrpcap(str(PCAP), packets)

    with EVENTS.open("w", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=[
                "timestamp_utc", "elapsed_seconds", "activity", "detail"
            ]
        )
        writer.writeheader()
        writer.writerows(events)

    summary = {
        "capture_directory": str(OUT),
        "interface": "lo",
        "capture_filter": "none; loopback interface only",
        "pcap": str(PCAP),
        "packet_count": len(packets),
        "normal_http_target_port": 8765,
        "scan_target": "127.0.0.1",
        "scan_ports": "1-1000 excluding 8765",
        "ground_truth_basis": (
            "Recorded HTTP request outcomes and Nmap scan log; "
            "verify extracted flows against these records before labeling."
        ),
        "errors": errors,
    }
    SUMMARY.write_text(json.dumps(summary, indent=2))

print(json.dumps(summary, indent=2))
