#!/usr/bin/env python3
"""Extract timestamped bidirectional IP flows from a PCAP without assigning labels.

This v5 extractor keeps packet-derived start/end times (Unix epoch and UTC ISO
8601) so flows can later be compared with the independent activity log created
by capture_mixed_session_v5.py. It writes a new CSV and refuses to overwrite an
existing output file. It does not infer labels from ports or event timing.
"""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
from pathlib import Path

from scapy.all import IP, TCP, UDP, rdpcap


def utc_iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def packet_endpoints(packet):
    if IP not in packet:
        return None
    ip = packet[IP]
    if TCP in packet:
        transport, sport, dport = "tcp", int(packet[TCP].sport), int(packet[TCP].dport)
    elif UDP in packet:
        transport, sport, dport = "udp", int(packet[UDP].sport), int(packet[UDP].dport)
    else:
        return None
    return ip.src, sport, ip.dst, dport, int(ip.proto), transport


def flow_key(endpoints):
    src_ip, src_port, dst_ip, dst_port, proto, transport = endpoints
    a = (src_ip, src_port)
    b = (dst_ip, dst_port)
    low, high = sorted((a, b))
    return (low[0], low[1], high[0], high[1], proto, transport)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", required=True, type=Path, help="Input PCAP file")
    parser.add_argument("--out", required=True, type=Path, help="New output CSV path")
    args = parser.parse_args()

    if not args.pcap.is_file():
        parser.error(f"PCAP not found: {args.pcap}")
    if args.out.exists():
        parser.error(f"refusing to overwrite existing output: {args.out}")

    packets = rdpcap(str(args.pcap))
    flows = {}

    for packet in sorted(packets, key=lambda p: float(p.time)):
        endpoints = packet_endpoints(packet)
        if endpoints is None:
            continue
        ts = float(packet.time)
        key = flow_key(endpoints)
        src_ip, src_port, dst_ip, dst_port, proto, transport = endpoints
        size = len(packet)

        if key not in flows:
            low_ip, low_port, high_ip, high_port, _, _ = key
            flows[key] = {
                "src_ip": low_ip, "src_port": low_port,
                "dst_ip": high_ip, "dst_port": high_port,
                "protocol": proto, "transport": transport,
                "flow_start_epoch": ts, "flow_end_epoch": ts,
                "flow_start_utc": utc_iso(ts), "flow_end_utc": utc_iso(ts),
                "packet_count": 0, "byte_count": 0,
                "syn_count": 0, "ack_count": 0, "fin_count": 0, "rst_count": 0,
                "initiator_ip": "", "initiator_port": "",
                "target_ip": "", "target_port": "",
            }

        row = flows[key]
        row["flow_end_epoch"] = ts
        row["flow_end_utc"] = utc_iso(ts)
        row["packet_count"] += 1
        row["byte_count"] += size

        if TCP in packet:
            flags = int(packet[TCP].flags)
            syn, ack = bool(flags & 0x02), bool(flags & 0x10)
            row["syn_count"] += int(syn)
            row["ack_count"] += int(ack)
            row["fin_count"] += int(bool(flags & 0x01))
            row["rst_count"] += int(bool(flags & 0x04))
            if syn and not ack and not row["initiator_ip"]:
                row["initiator_ip"] = src_ip
                row["initiator_port"] = src_port
                row["target_ip"] = dst_ip
                row["target_port"] = dst_port
        elif UDP in packet and not row["initiator_ip"]:
            row["initiator_ip"] = src_ip
            row["initiator_port"] = src_port
            row["target_ip"] = dst_ip
            row["target_port"] = dst_port

    fields = [
        "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "transport",
        "flow_start_epoch", "flow_end_epoch", "flow_start_utc", "flow_end_utc",
        "duration_seconds", "packet_count", "byte_count", "avg_packet_size",
        "bytes_per_second", "syn_count", "ack_count", "fin_count", "rst_count",
        "initiator_ip", "initiator_port", "target_ip", "target_port", "label",
    ]

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in flows.values():
            duration = max(float(row["flow_end_epoch"]) - float(row["flow_start_epoch"]), 0.0)
            row["duration_seconds"] = round(duration, 6)
            row["avg_packet_size"] = round(row["byte_count"] / row["packet_count"], 2)
            row["bytes_per_second"] = round(row["byte_count"] / duration, 2) if duration > 0 else 0.0
            row["label"] = "unknown"
            writer.writerow(row)

    print(f"Packets read: {len(packets)}")
    print(f"Flows written: {len(flows)}")
    print(f"Output: {args.out}")
    print("Labels are unknown by design; use activity evidence and review before labeling.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
