#!/usr/bin/env python3
import csv
import json
import subprocess
import sys
import threading
import time
import urllib.request
from datetime import datetime
from pathlib import Path

from scapy.all import rdpcap, IP, TCP

ROOT = Path(__file__).resolve().parent
BASE = ROOT / "experiments" / "mixed_capture_v3"
SESSION = BASE / ("session_" + datetime.now().strftime("%Y%m%d_%H%M%S"))
PCAP_DIR = SESSION / "pcap"
META_DIR = SESSION / "metadata"
FLOW_DIR = SESSION / "flows"

for directory in (PCAP_DIR, META_DIR, FLOW_DIR):
    directory.mkdir(parents=True, exist_ok=False)

PCAP = PCAP_DIR / "mixed_session_v2.pcap"
NMAP_LOG = META_DIR / "nmap_output.txt"
ACTIVITY_LOG = META_DIR / "activity_log.csv"
SUMMARY = META_DIR / "capture_summary.json"
TCPDUMP_LOG = META_DIR / "tcpdump.log"

PORT = 8765
URL_BASE = f"http://127.0.0.1:{PORT}/?mixed_session_request="
events = []
start_time = time.monotonic()
scan_result = {"return_code": None, "error": None}
server = None
tcpdump = None

def log(activity, detail):
    elapsed = round(time.monotonic() - start_time, 3)
    events.append({
        "elapsed_seconds": elapsed,
        "activity": activity,
        "detail": str(detail),
    })
    print(f"[{elapsed:7.3f}s] {activity}: {detail}", flush=True)

def request_http(number):
    url = URL_BASE + str(number)
    log("normal_http_start", f"GET {url}")
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            status = response.status
            log("normal_http_result", f"request={number}, status={status}")
            return status == 200
    except Exception as exc:
        log("normal_http_error", f"request={number}, error={exc}")
        return False

def run_scan():
    cmd = [
        "nmap", "-sS", "-Pn", "-n",
        "-p", "1-1000",
        "--scan-delay", "5ms",
        "127.0.0.1",
    ]
    log("scan_start", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60
        )
        scan_result["return_code"] = result.returncode
        scan_result["stdout"] = result.stdout
        scan_result["stderr"] = result.stderr
        log("scan_result", f"return_code={result.returncode}")
    except Exception as exc:
        scan_result["error"] = str(exc)
        log("scan_error", exc)

def main():
    global server, tcpdump

    if sys.platform != "linux":
        raise RuntimeError("Run this script inside Linux/WSL.")

    if __import__("os").geteuid() != 0:
        raise RuntimeError(
            "Run with sudo: sudo python3 mixed_session_capture_v2.py"
        )

    for command in ("tcpdump", "nmap"):
        if subprocess.run(
            ["bash", "-lc", f"command -v {command}"],
            capture_output=True
        ).returncode != 0:
            raise RuntimeError(f"{command} is not installed.")

    log("session_start", SESSION)

    server = subprocess.Popen(
        [
            sys.executable, "-m", "http.server", str(PORT),
            "--bind", "127.0.0.1",
            "--directory", str(ROOT),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    ready = False
    for _ in range(30):
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{PORT}/", timeout=1
            ):
                ready = True
                break
        except Exception:
            time.sleep(0.2)

    if not ready:
        raise RuntimeError("Local HTTP server did not become ready.")

    # Start tcpdump before generating experiment traffic.
    with open(TCPDUMP_LOG, "w") as tcpdump_file:
        tcpdump = subprocess.Popen(
            [
                "tcpdump", "-i", "lo", "-nn", "-s", "0",
                "-B", "4096", "-U",
                "-w", str(PCAP),
                "tcp and host 127.0.0.1",
            ],
            stdout=tcpdump_file,
            stderr=subprocess.STDOUT,
        )

        try:
            time.sleep(1)
            if tcpdump.poll() is not None:
                raise RuntimeError(
                    "tcpdump exited early; inspect metadata/tcpdump.log"
                )

            # Three normal requests before the scan.
            successes = []
            for number in range(1, 4):
                successes.append(request_http(number))
                time.sleep(0.3)

            # Run the slower scan while normal HTTP requests continue.
            scan_thread = threading.Thread(target=run_scan)
            scan_thread.start()

            for number in range(4, 11):
                time.sleep(0.5)
                successes.append(request_http(number))

            scan_thread.join(timeout=65)
            if scan_thread.is_alive():
                raise RuntimeError("Nmap thread did not finish in time.")

            # Capture responses that may arrive just after the scan.
            time.sleep(2)

        finally:
            if tcpdump.poll() is None:
                tcpdump.send_signal(__import__("signal").SIGINT)
            try:
                tcpdump.wait(timeout=10)
            except subprocess.TimeoutExpired:
                tcpdump.terminate()
                tcpdump.wait(timeout=5)

    if server is not None:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()

    with open(ACTIVITY_LOG, "w", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=["elapsed_seconds", "activity", "detail"]
        )
        writer.writeheader()
        writer.writerows(events)

    with open(NMAP_LOG, "w") as f:
        f.write(scan_result.get("stdout", ""))
        f.write("\n--- STDERR ---\n")
        f.write(scan_result.get("stderr", ""))
        if scan_result.get("error"):
            f.write("\n--- ERROR ---\n" + scan_result["error"])

    packets = rdpcap(str(PCAP))
    scan_ports = set()
    scan_syn_count = 0
    http_packets = 0

    for pkt in packets:
        if IP not in pkt or TCP not in pkt:
            continue
        tcp = pkt[TCP]
        flags = int(tcp.flags)

        if flags & 0x02 and not flags & 0x10:
            if 1 <= int(tcp.dport) <= 1000:
                scan_ports.add(int(tcp.dport))
                scan_syn_count += 1

        if int(tcp.sport) == PORT or int(tcp.dport) == PORT:
            http_packets += 1

    summary = {
        "capture_directory": str(SESSION),
        "interface": "lo",
        "capture_method": "tcpdump",
        "pcap": str(PCAP),
        "packet_count": len(packets),
        "scan_target": "127.0.0.1",
        "scan_ports_requested": "1-1000",
        "scan_initial_syn_count": scan_syn_count,
        "scan_unique_destination_ports_observed": len(scan_ports),
        "scan_missing_destination_ports": 1000 - len(scan_ports),
        "http_target_port": PORT,
        "http_packets_observed": http_packets,
        "http_requests_returning_200": sum(successes),
        "http_requests_attempted": len(successes),
        "nmap_return_code": scan_result["return_code"],
        "nmap_error": scan_result["error"],
        "tcpdump_return_code": tcpdump.returncode,
        "notes": (
            "Loopback diagnostic capture. Verify tcpdump drop statistics, "
            "HTTP/scan overlap, and flow extraction before assigning labels."
        ),
    }

    SUMMARY.write_text(json.dumps(summary, indent=2))
    print("\n=== EXPERIMENT SUMMARY ===")
    print(json.dumps(summary, indent=2))
    print("\nInspect tcpdump statistics in:", TCPDUMP_LOG)
    print("Experiment directory:", SESSION)

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
