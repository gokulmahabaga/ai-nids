#!/usr/bin/env python3
"""
capture_and_extract.py

Step 1-2 of the AI-based NIDS project:
  1. Capture live packets (or read from an existing .pcap file)
  2. Group packets into flows (5-tuple: src_ip, dst_ip, src_port, dst_port, proto)
  3. Extract flow-level features and write them to a CSV, ready for ML training

Usage:
    # Live capture on an interface for 60 seconds
    sudo python3 capture_and_extract.py --iface eth0 --duration 60 --out flows.csv

    # Read from an existing pcap file instead of live capture
    python3 capture_and_extract.py --pcap sample.pcap --out flows.csv

Requires: pip install scapy --break-system-packages
"""

import argparse
import csv
import time
from collections import defaultdict

from scapy.all import sniff, rdpcap, IP, TCP, UDP


def flow_key(pkt):
    """5-tuple flow identifier. Same key regardless of packet direction."""
    if IP not in pkt:
        return None
    ip = pkt[IP]
    proto = ip.proto  # 6=TCP, 17=UDP
    sport = dport = 0
    if TCP in pkt:
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
    elif UDP in pkt:
        sport, dport = pkt[UDP].sport, pkt[UDP].dport

    # Normalize direction so A->B and B->A packets land in the same flow
    endpoints = sorted([(ip.src, sport), (ip.dst, dport)])
    return (endpoints[0][0], endpoints[0][1], endpoints[1][0], endpoints[1][1], proto)


def raw_endpoints(pkt):
    """Un-normalized (src_ip, dst_ip, dst_port) for the packet as actually sent --
    used for fan-out tracking, where direction matters (unlike flow_key)."""
    if IP not in pkt:
        return None
    ip = pkt[IP]
    dport = None
    if TCP in pkt:
        dport = pkt[TCP].dport
    elif UDP in pkt:
        dport = pkt[UDP].dport
    return ip.src, ip.dst, dport


class SourceActivity:
    """Track source activity within the preceding five seconds."""

    WINDOW_SECONDS = 5.0

    def __init__(self):
        self.events = defaultdict(list)

    def update(self, pkt, ts):
        endpoints = raw_endpoints(pkt)
        if endpoints is None:
            return

        src, dst, dport = endpoints

        if TCP in pkt:
            flags = int(pkt[TCP].flags)
            syn = bool(flags & 0x02)
            ack = bool(flags & 0x10)

            # Count only initial TCP SYN packets.
            if not syn or ack:
                return
        elif UDP not in pkt:
            return

        self.events[src].append((float(ts), dst, dport))

    def features_for(self, src_ip, ts):
        cutoff = float(ts) - self.WINDOW_SECONDS

        events = [
            (event_ts, dst, dport)
            for event_ts, dst, dport in self.events.get(src_ip, [])
            if cutoff < event_ts <= float(ts)
        ]

        ports = {
            dport for _, _, dport in events
            if dport is not None
        }
        hosts = {dst for _, dst, _ in events}

        return {
            "src_distinct_ports": len(ports),
            "src_distinct_hosts": len(hosts),
            "src_conn_rate": round(
                len(events) / self.WINDOW_SECONDS, 2
            ),
        }


class FlowStats:
    """Accumulates per-packet info for a single flow."""

    def __init__(self, first_ts):
        self.start_time = first_ts
        self.last_time = first_ts
        self.packet_count = 0
        self.byte_count = 0
        self.pkt_sizes = []
        self.inter_arrival_times = []
        self.tcp_flags_seen = defaultdict(int)  # e.g. {'S':2, 'A':10, 'F':1}
        self.protocols = set()
        self.orig_src = None
        self.orig_sport = None
        self.target_ip = None
        self.target_port = None
        self.source_feature_snapshot = None

    def update(self, pkt, ts):

        if IP in pkt and TCP in pkt:
            flags = int(pkt[TCP].flags)
            is_initial_syn = (flags & 0x02) and not (flags & 0x10)

            if is_initial_syn and self.orig_src is None:
                self.orig_src = pkt[IP].src
                self.orig_sport = int(pkt[TCP].sport)
                self.target_ip = pkt[IP].dst
                self.target_port = int(pkt[TCP].dport)

        elif IP in pkt and UDP in pkt and self.orig_src is None:
            self.orig_src = pkt[IP].src
            self.orig_sport = int(pkt[UDP].sport)
            self.target_ip = pkt[IP].dst
            self.target_port = int(pkt[UDP].dport)

        if self.packet_count > 0:
            self.inter_arrival_times.append(ts - self.last_time)

        self.last_time = ts
        self.packet_count += 1

        size = len(pkt)
        self.byte_count += size
        self.pkt_sizes.append(size)

        if IP in pkt:
            self.protocols.add(pkt[IP].proto)

        if TCP in pkt:
            flags = pkt[TCP].sprintf("%TCP.flags%")
            for f in flags:
                self.tcp_flags_seen[f] += 1

    def to_row(self, key, source_activity=None):
        duration = max(self.last_time - self.start_time, 1e-6)
        avg_size = sum(self.pkt_sizes) / len(self.pkt_sizes)
        avg_iat = (
            sum(self.inter_arrival_times) / len(self.inter_arrival_times)
            if self.inter_arrival_times
            else 0.0
        )
        proto = 6 if 6 in self.protocols else (17 if 17 in self.protocols else 0)

        row = {
            "src_ip": key[0],
            "src_port": key[1],
            "dst_ip": key[2],
            "dst_port": key[3],
            "protocol": proto,
            "initiator_ip": self.orig_src,
            "initiator_port": self.orig_sport,
            "target_ip": self.target_ip,
            "target_port": self.target_port,
            "duration": round(duration, 6),
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "avg_packet_size": round(avg_size, 2),
            "avg_inter_arrival_time": round(avg_iat, 6),
            "syn_count": self.tcp_flags_seen.get("S", 0),
            "ack_count": self.tcp_flags_seen.get("A", 0),
            "fin_count": self.tcp_flags_seen.get("F", 0),
            "rst_count": self.tcp_flags_seen.get("R", 0),
            "bytes_per_second": round(self.byte_count / duration, 2),
        }

        # Fan-out features: the real port-scan signature, computed across
        # ALL flows from this flow's originating source IP, not just this one

        if self.source_feature_snapshot is not None:
            row.update(self.source_feature_snapshot)
        else:
            row.update({
                "src_distinct_ports": 0,
                "src_distinct_hosts": 0,
                "src_conn_rate": 0.0,
            })


        row["label"] = "unknown"  # fill in manually or via known-attack IP/port rules
        return row


def build_flows(packets):
    # Process packets chronologically so duration and inter-arrival
    # features do not depend on the input packet order.
    packets = sorted(packets, key=lambda pkt: float(pkt.time))

    flows = {}
    activity = SourceActivity()

    for pkt in packets:
        ts = float(pkt.time)
        activity.update(pkt, ts)

        key = flow_key(pkt)
        if key is None:
            continue

        if key not in flows:
            flows[key] = FlowStats(ts)

        stats = flows[key]
        stats.update(pkt, ts)

        # Snapshot once, after the initiator is known.
        # Later packets must not change this snapshot.
        if (
            stats.source_feature_snapshot is None
            and stats.orig_src is not None
        ):
            stats.source_feature_snapshot = activity.features_for(
                stats.orig_src, ts
            )

    return flows, activity


def write_csv(flows, activity, out_path):
    fieldnames = [
        "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
        "initiator_ip", "initiator_port", "target_ip", "target_port",
        "duration", "packet_count", "byte_count", "avg_packet_size",
        "avg_inter_arrival_time", "syn_count", "ack_count", "fin_count",
        "rst_count", "bytes_per_second",
        "src_distinct_ports", "src_distinct_hosts", "src_conn_rate",
        "label",
    ]
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for key, stats in flows.items():
            writer.writerow(stats.to_row(key, source_activity=activity))
    print(f"Wrote {len(flows)} flows to {out_path}")


def main():
    parser = argparse.ArgumentParser(description="Capture traffic and extract flow features for NIDS")
    parser.add_argument("--iface", help="Network interface for live capture (e.g. eth0, wlan0)")
    parser.add_argument("--pcap", help="Path to an existing .pcap file to read instead of live capture")
    parser.add_argument("--duration", type=int, default=60, help="Live capture duration in seconds (default 60)")
    parser.add_argument("--out", default="flows.csv", help="Output CSV path (default flows.csv)")
    args = parser.parse_args()

    if args.pcap:
        print(f"Reading packets from {args.pcap} ...")
        packets = rdpcap(args.pcap)
    elif args.iface:
        print(f"Capturing on {args.iface} for {args.duration}s ... (Ctrl+C to stop early)")
        packets = sniff(iface=args.iface, timeout=args.duration)
    else:
        parser.error("Provide either --iface (live capture) or --pcap (read from file)")
        return

    print(f"Captured {len(packets)} packets. Building flows ...")
    flows, activity = build_flows(packets)
    write_csv(flows, activity, args.out)


if __name__ == "__main__":
    main()
