
import unittest
from scapy.all import IP, TCP, UDP
from capture_and_extract_v2 import flow_key, build_flows


CLIENT = "203.0.113.10"
SERVER = "192.0.2.20"


def tcp_packet(src, dst, sport, dport, flags, ts):
    pkt = IP(src=src, dst=dst) / TCP(
        sport=sport,
        dport=dport,
        flags=flags
    )
    pkt.time = ts
    return pkt


def udp_packet(src, dst, sport, dport, ts):
    pkt = IP(src=src, dst=dst) / UDP(
        sport=sport,
        dport=dport
    )
    pkt.time = ts
    return pkt


class TestFlowDirection(unittest.TestCase):

    def test_reverse_packets_share_one_canonical_key(self):
        outgoing = tcp_packet(
            CLIENT, SERVER, 50000, 443, "S", 1.0
        )
        incoming = tcp_packet(
            SERVER, CLIENT, 443, 50000, "SA", 1.1
        )

        self.assertEqual(
            flow_key(outgoing),
            flow_key(incoming)
        )

    def test_exported_source_is_canonical_not_initiator(self):
        outgoing = tcp_packet(
            CLIENT, SERVER, 50000, 443, "S", 1.0
        )
        incoming = tcp_packet(
            SERVER, CLIENT, 443, 50000, "SA", 1.1
        )

        flows, activity = build_flows([outgoing, incoming])

        self.assertEqual(len(flows), 1)

        key, stats = next(iter(flows.items()))
        row = stats.to_row(key, source_activity=activity)

        self.assertEqual(row["src_ip"], min(CLIENT, SERVER))
        self.assertEqual(stats.orig_src, CLIENT)
        self.assertNotEqual(row["src_ip"], stats.orig_src)

    def test_initial_syn_sets_initiator(self):
        outgoing = tcp_packet(
            CLIENT, SERVER, 50000, 443, "S", 1.0
        )
        incoming = tcp_packet(
            SERVER, CLIENT, 443, 50000, "SA", 1.1
        )

        flows, _ = build_flows([outgoing, incoming])

        self.assertEqual(len(flows), 1)

        key, stats = next(iter(flows.items()))

        self.assertEqual(stats.orig_src, CLIENT)
        self.assertEqual(stats.orig_sport, 50000)

        row = stats.to_row(
            key,
            source_activity=None
        )

        self.assertEqual(row["initiator_ip"], CLIENT)
        self.assertEqual(row["initiator_port"], 50000)

    def test_reverse_packet_does_not_overwrite_initiator(self):
        outgoing = tcp_packet(
            CLIENT, SERVER, 50000, 443, "S", 1.0
        )
        incoming = tcp_packet(
            SERVER, CLIENT, 443, 50000, "SA", 1.1
        )

        flows, _ = build_flows([outgoing, incoming])
        _, stats = next(iter(flows.items()))

        self.assertEqual(stats.orig_src, CLIENT)
        self.assertEqual(stats.orig_sport, 50000)

    def test_tcp_without_initial_syn_keeps_initiator_unknown(self):
        later_packet = tcp_packet(
            SERVER, CLIENT, 443, 50000, "A", 2.0
        )

        flows, _ = build_flows([later_packet])
        _, stats = next(iter(flows.items()))

        self.assertIsNone(stats.orig_src)
        self.assertIsNone(stats.orig_sport)

    def test_udp_records_observed_source(self):
        outgoing = udp_packet(
            CLIENT, SERVER, 53000, 53, 1.0
        )

        flows, activity = build_flows([outgoing])

        self.assertEqual(len(flows), 1)

        _, stats = next(iter(flows.items()))

        self.assertEqual(stats.orig_src, CLIENT)
        self.assertEqual(stats.orig_sport, 53000)

        features = activity.features_for(CLIENT, 1.0)

        self.assertEqual(features["src_distinct_ports"], 1)
        self.assertEqual(features["src_distinct_hosts"], 1)
        self.assertGreater(features["src_conn_rate"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)

