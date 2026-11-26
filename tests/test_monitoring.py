#!/usr/bin/env python3
"""Test del Network Security Monitoring: aggregazione degli eventi Suricata, filtri di cattura, riepilogo PCAP.

    python3 tests/test_monitoring.py          (dalla cartella del repo, non serve root)
"""
import json
import os
import struct
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.join(REPO, "config", "includes.chroot")
sys.path.insert(0, os.path.join(ROOT, "opt", "nefi", "netmon"))
sys.path.insert(0, os.path.join(ROOT, "usr", "lib", "nefi", "modules"))
import netlib as nl          # noqa: E402
import pcap_summary as ps    # noqa: E402

TS = "2026-11-15T10:20:30.000000+0100"


def flow(src, dst, dport, up, down, proto="TCP", app="tls"):
    return {"timestamp": TS, "event_type": "flow", "src_ip": src, "dest_ip": dst, "src_port": 40000,
            "dest_port": dport, "proto": proto, "app_proto": app,
            "flow": {"bytes_toserver": up, "bytes_toclient": down, "pkts_toserver": 3, "pkts_toclient": 4}}


def dns(name, rtype="A", v3=False):
    if v3:
        return {"timestamp": TS, "event_type": "dns", "src_ip": "192.168.1.5",
                "dns": {"type": "request", "queries": [{"rrname": name, "rrtype": rtype}]}}
    return {"timestamp": TS, "event_type": "dns", "src_ip": "192.168.1.5",
            "dns": {"type": "query", "rrname": name, "rrtype": rtype}}


class EveTest(unittest.TestCase):
    def test_flow_direction_and_counters(self):
        b = nl.new_bucket("2026-11-15T10")
        nl.add_event(b, flow("192.168.1.5", "93.184.216.34", 443, 1000, 9000))       # in uscita
        nl.add_event(b, flow("45.33.32.156", "192.168.1.5", 22, 500, 700, app="ssh"))  # in entrata
        self.assertEqual(b["flows"], 2)
        self.assertEqual(b["bytes_out"], 1000 + 700)
        self.assertEqual(b["bytes_in"], 9000 + 500)
        self.assertEqual(b["talkers"]["93.184.216.34"], [10000, 1])
        self.assertEqual(b["talkers"]["45.33.32.156"], [1200, 1])
        self.assertEqual(b["ports"]["443/TCP"], [10000, 1])
        self.assertEqual(b["app"]["ssh"], [1200, 1])
        self.assertEqual(nl.event_hour(flow("1.1.1.1", "2.2.2.2", 1, 1, 1)), "2026-11-15T10")

    def test_dns_formats_and_flags(self):
        b = nl.new_bucket("h")
        nl.add_event(b, dns("www.Example.org."))
        nl.add_event(b, dns("www.example.org", v3=True))
        nl.add_event(b, {"timestamp": TS, "event_type": "dns", "dns": {"type": "answer", "rrname": "nope.example",
                                                                    "rcode": "NXDOMAIN"}})
        self.assertEqual(b["dns"]["www.example.org"], 2)
        self.assertEqual(b["dns_total"], 2)                    # le risposte non sono richieste
        self.assertEqual(b["nxdomain"], 1)
        self.assertEqual(b["dns_flags"], [])
        nl.add_event(b, dns("a9f3kq0zx7vbn2m4c8d1e6g5h3j2k1l0.evil.example"))
        self.assertEqual(len(b["dns_flags"]), 1)
        self.assertIn("random-looking", b["dns_flags"][0]["why"])
        self.assertEqual(nl.dns_flags("mail.google.com"), [])
        self.assertEqual(nl.base_domain("a.b.example.co.uk"), "example.co.uk")
        self.assertEqual(nl.base_domain("a.b.example.com"), "example.com")

    def test_many_subdomains_flag(self):
        b = nl.new_bucket("2026-11-15T10")
        for i in range(70):
            nl.add_event(b, dns(f"h{i}.tunnel.example"))
        nl.finish_bucket(b)
        nl.finish_bucket(b)                                    # due volte: una segnalazione sola
        self.assertEqual([f["name"] for f in b["dns_flags"]], ["*.tunnel.example"])

    def test_alert_row_and_merge(self):
        b1, b2 = nl.new_bucket("2026-11-15T10"), nl.new_bucket("2026-11-15T11")
        alert = {"timestamp": TS, "event_type": "alert", "src_ip": "45.33.32.156", "dest_ip": "192.168.1.5",
                 "src_port": 4444, "dest_port": 22, "proto": "TCP",
                 "alert": {"signature_id": 2001219, "signature": "ET SCAN Potential SSH Scan", "severity": 1,
                           "category": "Attempted Information Leak", "action": "allowed"}}
        row = nl.add_event(b1, alert)
        nl.add_event(b2, alert)
        nl.add_event(b2, flow("192.168.1.5", "8.8.8.8", 53, 100, 200, "UDP", "dns"))
        self.assertEqual(row["remote"], "45.33.32.156")
        self.assertEqual(row["sid"], 2001219)
        m = nl.merge([b2, b1])
        self.assertEqual(m["alert_total"], 2)
        self.assertEqual(m["alert_high"], 2)
        self.assertEqual([h["hour"] for h in m["hours"]], ["2026-11-15T10", "2026-11-15T11"])
        (key, n), = nl.top(m["alerts"])
        self.assertEqual((json.loads(key)[1], n), ("ET SCAN Potential SSH Scan", 2))
        self.assertEqual(m["alert_src"], {"45.33.32.156": 2})
        self.assertEqual(m["bytes_out"], 100)

    def test_prune_keeps_the_biggest(self):
        b = nl.new_bucket("h")
        for i in range(nl.CAP["talkers"] * 2 + 50):
            nl.add_event(b, flow("192.168.1.5", f"151.101.{i // 250}.{i % 250 + 1}", 443, i + 1, 0))
        self.assertLessEqual(len(b["talkers"]), nl.CAP["talkers"] * 2)
        self.assertIn("151.101.2.150", b["talkers"])            # l'ultimo e' il piu' grande

    def test_is_local(self):
        self.assertTrue(nl.is_local("192.168.1.1"))
        self.assertTrue(nl.is_local("fe80::1"))
        self.assertFalse(nl.is_local("8.8.8.8"))


class ConfigTest(unittest.TestCase):
    YAML = ("%YAML 1.1\n---\nvars:\n  x: 1\n\naf-packet:\n  - interface: eth0\n    cluster-id: 99\n"
            "  - interface: default\n\npcap:\n  - interface: eth0\n")

    def test_read_and_change_interface(self):
        self.assertEqual(nl.suricata_interface(self.YAML), "eth0")
        new, changed = nl.set_suricata_interface(self.YAML, "enp1s0")
        self.assertTrue(changed)
        self.assertEqual(nl.suricata_interface(new), "enp1s0")
        self.assertIn("pcap:\n  - interface: eth0", new)       # le altre sezioni non si toccano
        self.assertIn("  - interface: default", new)
        self.assertEqual(nl.set_suricata_interface("nothing: here\n", "x"), ("nothing: here\n", False))

    def test_capture_filter_only_from_validated_parts(self):
        self.assertEqual(nl.capture_filter(), "")
        self.assertEqual(nl.capture_filter("10.0.0.7", "443", "tcp"), "tcp and host 10.0.0.7 and port 443")
        self.assertEqual(nl.capture_filter(host="2001:db8::1"), "host 2001:db8::1")
        for bad in (dict(host="10.0.0.7 or 1=1"), dict(host="$(reboot)"), dict(port="80; rm"), dict(port="70000"),
                    dict(proto="ip6 and (tcp"), dict(proto="icmp", port="80")):
            with self.assertRaises(ValueError):
                nl.capture_filter(**bad)


def pcap_file(packets, path):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        for i, pkt in enumerate(packets):
            f.write(struct.pack("<IIII", 1763200000 + i, 0, len(pkt), len(pkt)) + pkt)


def ipv4(src, dst, proto, l4):
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 0, 0, 64, proto, 0, bytes(src), bytes(dst))
    return b"\x00" * 12 + b"\x08\x00" + hdr + l4


def udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def tcp(sport, dport, payload):
    return struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 0x50, 0x18, 1024, 0, 0) + payload


def dns_q(name):
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", 1, 1)


def client_hello(name):
    sni = struct.pack("!HBH", len(name) + 3, 0, len(name)) + name.encode()
    ext = struct.pack("!HH", 0, len(sni)) + sni
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00" \
        + struct.pack("!H", len(ext)) + ext
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


class PcapTest(unittest.TestCase):
    def test_summary(self):
        me, dnssrv, web = (192, 168, 1, 5), (192, 168, 1, 1), (93, 184, 216, 34)
        pkts = [ipv4(me, dnssrv, 17, udp(40000, 53, dns_q("www.example.org"))),
                ipv4(me, web, 6, tcp(40001, 443, client_hello("www.example.org"))),
                ipv4(me, web, 6, tcp(40002, 80, b"GET / HTTP/1.1\r\nHost: plain.example.org\r\n\r\n")),
                ipv4(web, me, 6, tcp(443, 40001, b"\x17\x03\x03\x00\x10" + b"x" * 16)),
                b"\xff" * 12 + b"\x08\x06" + b"\x00" * 28]                       # ARP
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "t.pcap")
            pcap_file(pkts, path)
            s = ps.summarize(path)
            self.assertEqual((s["packets"], s["non_ip"], s["error"]), (5, 1, ""))
            self.assertEqual(s["dns"], [("www.example.org", 1)])
            self.assertEqual(s["tls"], [("www.example.org", 1)])
            self.assertEqual(s["http"], [("plain.example.org", 1)])
            self.assertEqual(dict(s["protocols"]), {"TCP": 3, "UDP": 1})
            self.assertEqual(s["conversations"][0][:4], ("192.168.1.5", "93.184.216.34", "TCP", 3))
            self.assertIn("443/TCP", dict(s["ports"]))
            self.assertIn("www.example.org", ps.as_text(s))
            # cattura interrotta a meta' pacchetto: si legge quello che c'e', senza errori
            with open(path, "ab") as f:
                f.write(struct.pack("<IIII", 1, 0, 500, 500) + b"abc")
            s = ps.summarize(path)
            self.assertEqual((s["packets"], s["truncated"]), (5, True))
            # file vuoto e file che non e' un pcap
            open(path, "wb").close()
            self.assertIn("no packets", ps.summarize(path)["error"])
            with open(path, "wb") as f:
                f.write(b"this is not a capture file at all......")
            self.assertEqual(ps.summarize(path)["error"], "not a pcap file")

    def test_garbage_payloads_do_not_crash(self):
        self.assertIsNone(ps.tls_sni(b"\x16\x03\x01\x00\x05\x01" + b"\xff" * 60))
        self.assertIsNone(ps.dns_query(b"\x00" * 5))
        self.assertIsNone(ps.dns_query(struct.pack("!HHHHHH", 1, 0x8180, 1, 1, 0, 0) + b"\x03www\x00\x00\x01\x00\x01"))


if __name__ == "__main__":
    unittest.main(verbosity=1)
