import unittest
from scapy.all import IP, TCP, UDP
from capture_and_extract_v2 import SourceActivity


class TestFanoutWindow(unittest.TestCase):
    def setUp(self):
        self.activity = SourceActivity()
        self.client = "192.0.2.10"
        self.server = "198.51.100.20"

    def tcp_syn(self, src, dst, dport, ts):
        pkt = IP(src=src, dst=dst) / TCP(
            sport=40000, dport=dport, flags="S"
        )
        self.activity.update(pkt, ts)

    def test_distinct_ports_and_rate(self):
        self.tcp_syn(self.client, self.server, 80, 1.0)
        self.tcp_syn(self.client, self.server, 443, 2.0)
        result = self.activity.features_for(self.client, 2.0)

        self.assertEqual(result["src_distinct_ports"], 2)
        self.assertEqual(result["src_distinct_hosts"], 1)
        self.assertEqual(result["src_conn_rate"], 0.4)

    def test_event_older_than_window_expires(self):
        self.tcp_syn(self.client, self.server, 80, 1.0)
        self.tcp_syn(self.client, self.server, 443, 7.0)
        result = self.activity.features_for(self.client, 7.0)

        self.assertEqual(result["src_distinct_ports"], 1)
        self.assertEqual(result["src_conn_rate"], 0.2)

    def test_tcp_non_initial_packet_is_ignored(self):
        pkt = IP(src=self.client, dst=self.server) / TCP(
            sport=40000, dport=80, flags="SA"
        )
        self.activity.update(pkt, 1.0)
        result = self.activity.features_for(self.client, 1.0)

        self.assertEqual(result["src_distinct_ports"], 0)
        self.assertEqual(result["src_conn_rate"], 0.0)

    def test_udp_events_are_counted(self):
        pkt = IP(src=self.client, dst=self.server) / UDP(
            sport=40000, dport=53
        )
        self.activity.update(pkt, 1.0)
        result = self.activity.features_for(self.client, 1.0)

        self.assertEqual(result["src_distinct_ports"], 1)
        self.assertEqual(result["src_distinct_hosts"], 1)
        self.assertEqual(result["src_conn_rate"], 0.2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
