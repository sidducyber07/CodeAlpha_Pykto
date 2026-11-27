#!/usr/bin/env python3
"""
Automated unit & UI integration tests for Pykto.

Tests packet decoding across raw Ethernet/IPv4/IPv6/TCP/UDP/ICMP/ARP bytes,
Scapy packet parsing, interface discovery, bounded UI row updates, filtering,
inspector updates, and Reset behavior.
"""

from pathlib import Path
import socket
import struct
import sys
import tkinter as tk
import unittest

# Ensure Snifx/ modules can be imported when running tests from the repo root.
SNIFX_DIR = Path(__file__).resolve().parent
if str(SNIFX_DIR) not in sys.path:
    sys.path.insert(0, str(SNIFX_DIR))

from app import MAX_VISIBLE_ROWS, SnifxApp  # noqa: E402
from capture_engine import CaptureEngine, is_scapy_available, list_interfaces  # noqa: E402
from packet_parser import (  # noqa: E402
    PacketRecord,
    format_payload_hexdump,
    parse_raw_ethernet_frame,
    parse_raw_ipv4_packet,
    parse_scapy_packet,
)


def _eth_header(ether_type: int) -> bytes:
    """Build a synthetic 14-byte Ethernet II header for unit tests."""
    dst = b"\xaa\xbb\xcc\xdd\xee\xff"
    src = b"\x11\x22\x33\x44\x55\x66"
    return struct.pack("! 6s 6s H", dst, src, ether_type)


def _ipv4_header(proto: int, src_ip: str, dst_ip: str, total_len: int = 40) -> bytes:
    """Build a synthetic 20-byte IPv4 header (IHL=5, TTL=64) for unit tests."""
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    return struct.pack(
        "! B B H H H B B H 4s 4s",
        0x45, 0, total_len, 1, 0, 64, proto, 0, src, dst
    )


class TestPacketParser(unittest.TestCase):
    """Verify Layer 2/3/4 binary decoding and payload formatting."""

    def test_ipv4_tcp_frame(self):
        """Ensure IPv4 + TCP flags, ports, HTTPS hint, and payload parse accurately."""
        tcp = struct.pack("! H H L L H H H H", 54321, 443, 100, 200, (5 << 12) | 0x18, 65535, 0, 0)
        payload = b"GET / HTTP/1.1\r\n"
        frame = _eth_header(0x0800) + _ipv4_header(6, "192.168.1.10", "93.184.216.34") + tcp + payload

        rec = parse_raw_ethernet_frame(frame, index=1)
        self.assertIsNotNone(rec)
        self.assertEqual(rec.protocol, "TCP")
        self.assertEqual(rec.src_ip, "192.168.1.10")
        self.assertEqual(rec.dst_ip, "93.184.216.34")
        self.assertEqual(rec.src_port, 54321)
        self.assertEqual(rec.dst_port, 443)
        self.assertIn("PSH", rec.tcp_flags)
        self.assertIn("ACK", rec.tcp_flags)
        self.assertIn("HTTPS", rec.info)
        self.assertEqual(rec.payload, payload)
        self.assertFalse(rec.is_loopback)

    def test_ipv4_udp_dns_and_loopback(self):
        """Ensure UDP DNS (port 53) and 127.0.0.1 loopback detection work."""
        udp = struct.pack("! H H H H", 55555, 53, 16, 0)
        payload = b"\x12\x34dnsquery"
        frame = _eth_header(0x0800) + _ipv4_header(17, "127.0.0.1", "127.0.0.53") + udp + payload

        rec = parse_raw_ethernet_frame(frame, index=2)
        self.assertIsNotNone(rec)
        self.assertEqual(rec.protocol, "UDP")
        self.assertEqual(rec.dst_port, 53)
        self.assertIn("DNS", rec.info)
        self.assertTrue(rec.is_loopback)

    def test_ipv4_icmp(self):
        """Ensure ICMP Echo Request (type=8, code=0) is decoded."""
        icmp = struct.pack("! B B H", 8, 0, 0x1234) + b"pingdata"
        frame = _eth_header(0x0800) + _ipv4_header(1, "10.0.0.2", "8.8.8.8") + icmp

        rec = parse_raw_ethernet_frame(frame, index=3)
        self.assertIsNotNone(rec)
        self.assertEqual(rec.protocol, "ICMP")
        self.assertIn("Echo Request", rec.info)

    def test_ipv6_tcp(self):
        """Ensure IPv6 (EtherType 0x86DD) and ::1 loopback detection work."""
        src6 = socket.inet_pton(socket.AF_INET6, "::1")
        dst6 = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
        ipv6 = struct.pack("! I H B B 16s 16s", 0x60000000, 20, 6, 64, src6, dst6)
        tcp = struct.pack("! H H L L H H H H", 1234, 80, 1, 0, (5 << 12) | 0x02, 1024, 0, 0)
        frame = _eth_header(0x86DD) + ipv6 + tcp

        rec = parse_raw_ethernet_frame(frame, index=4)
        self.assertIsNotNone(rec)
        self.assertEqual(rec.protocol, "TCP")
        self.assertEqual(rec.ip_version, 6)
        self.assertTrue(rec.is_loopback)

    def test_arp_frame(self):
        """Ensure ARP request frames (EtherType 0x0806) map to OTHER with IP summary."""
        arp = struct.pack(
            "! H H B B H 6s 4s 6s 4s",
            1, 0x0800, 6, 4, 1,
            b"\x11\x22\x33\x44\x55\x66", socket.inet_aton("192.168.1.1"),
            b"\x00\x00\x00\x00\x00\x00", socket.inet_aton("192.168.1.5"),
        )
        frame = _eth_header(0x0806) + arp
        rec = parse_raw_ethernet_frame(frame, index=5)
        self.assertIsNotNone(rec)
        self.assertEqual(rec.protocol, "OTHER")
        self.assertIn("ARP Request", rec.info)

    def test_short_or_malformed_frames(self):
        """Truncated packets should return None rather than raising struct errors."""
        self.assertIsNone(parse_raw_ethernet_frame(b"\x00\x01\x02", index=1))
        self.assertIsNone(parse_raw_ipv4_packet(b"\x45\x00", index=1))

    def test_hexdump_truncation(self):
        """Payloads larger than max_bytes should be truncated cleanly."""
        dump = format_payload_hexdump(b"A" * 600, max_bytes=64)
        self.assertIn("more bytes omitted", dump)
        self.assertEqual(format_payload_hexdump(b""), "(no payload)")

    @unittest.skipUnless(is_scapy_available(), "scapy not installed in this Python")
    def test_scapy_packet_parser(self):
        """Ensure scapy Ether/IP/TCP/Raw packets convert cleanly into PacketRecord."""
        from scapy.layers.inet import IP, TCP
        from scapy.layers.l2 import Ether
        from scapy.packet import Raw

        pkt = Ether() / IP(src="10.1.1.1", dst="10.1.1.2") / TCP(sport=1111, dport=80, flags="PA") / Raw(load=b"hello")
        rec = parse_scapy_packet(pkt, index=9)
        self.assertEqual(rec.protocol, "TCP")
        self.assertEqual(rec.src_ip, "10.1.1.1")
        self.assertEqual(rec.dst_port, 80)
        self.assertEqual(rec.payload, b"hello")


class TestSnifxUIAndEngine(unittest.TestCase):
    """Verify Tkinter GUI bounded table, filtering, inspector, and reset behavior."""

    def test_list_interfaces_non_empty(self):
        """At least one OS network interface (such as 'lo') should be discovered."""
        ifaces = list_interfaces()
        self.assertIsInstance(ifaces, list)
        self.assertGreaterEqual(len(ifaces), 1)

    def test_ui_bounded_rows_filter_inspector_and_reset(self):
        """Pushing >300 packets should keep the UI table capped at MAX_VISIBLE_ROWS."""
        root = tk.Tk()
        root.withdraw()  # Keep test window hidden during automated checks.
        try:
            app = SnifxApp(root)
            total_to_push = MAX_VISIBLE_ROWS + 120
            for i in range(1, total_to_push + 1):
                proto = "TCP" if i % 2 == 0 else "UDP"
                app.packet_queue.put_nowait(
                    PacketRecord(
                        index=i,
                        timestamp="12:00:00.000",
                        protocol=proto,
                        src_ip="10.0.0.1" if i % 3 else "127.0.0.1",
                        dst_ip="10.0.0.2",
                        src_port=40000 + i,
                        dst_port=443 if proto == "TCP" else 53,
                        length=128,
                        info=f"pkt {i}",
                        payload=b"payload-" + str(i).encode(),
                        detail_lines=(f"Packet #{i}", f"Protocol: {proto}"),
                    )
                )

            # Drain via _poll_loop twice (since _poll_loop drains 300 per tick)
            app._poll_loop()
            app._poll_loop()

            self.assertEqual(app.total_packets, total_to_push)
            self.assertEqual(len(app.visible_iids), MAX_VISIBLE_ROWS)
            self.assertEqual(len(app.tree.get_children()), MAX_VISIBLE_ROWS)

            # Select first visible row and verify inspector updates
            first_iid = app.visible_iids[0]
            app.tree.selection_set(first_iid)
            app._on_packet_selected()
            details = app.details_text.get("1.0", "end").strip()
            payload = app.payload_text.get("1.0", "end").strip()
            self.assertIn("Protocol:", details)
            self.assertIn("payload-", payload)

            # Protocol filter -> TCP only
            app.proto_filter_var.set("TCP")
            app._rebuild_table()
            for iid in app.visible_iids:
                self.assertEqual(app.row_records[iid].protocol, "TCP")

            # Reset clears everything cleanly
            app.reset_capture()
            self.assertEqual(app.total_packets, 0)
            self.assertEqual(len(app.visible_iids), 0)
            self.assertEqual(len(app.tree.get_children()), 0)
            self.assertEqual(app.proto_counts["TCP"], 0)
        finally:
            app.engine.stop()
            root.destroy()

    def test_capture_engine_stop_is_safe_when_idle(self):
        import queue
        q = queue.Queue()
        eng = CaptureEngine(q)
        eng.stop()
        self.assertFalse(eng.is_running)


class TestEnvBootstrap(unittest.TestCase):
    """Verify automatic venv creation and requirements installation logic."""

    def test_parse_requirement_names(self):
        import tempfile
        import env_bootstrap

        with tempfile.TemporaryDirectory() as tmp:
            req = Path(tmp) / "requirements.txt"
            req.write_text(
                "# comment\n\nscapy==2.8.0  # inline comment\n-r base.txt\npytest>=7.0\n",
                encoding="utf-8",
            )
            self.assertEqual(
                env_bootstrap._parse_requirement_names(req),
                ["scapy", "pytest"],
            )

    def test_ensure_environment_creates_venv_and_installs_requirements(self):
        import os
        import tempfile
        from unittest import mock
        import env_bootstrap

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            fake_venv = tmp_path / "venv"
            fake_req = tmp_path / "requirements.txt"
            fake_req.write_text("scapy==2.8.0\n", encoding="utf-8")
            fake_marker = fake_venv / ".requirements.sha256"
            fake_python = env_bootstrap.get_venv_python(fake_venv)
            calls = []

            def fake_run(cmd, **_kwargs):
                calls.append(cmd)
                if len(cmd) >= 3 and cmd[1:3] == ["-m", "venv"]:
                    fake_python.parent.mkdir(parents=True, exist_ok=True)
                    fake_python.write_text("", encoding="utf-8")
                    return mock.Mock(returncode=0)
                if "-c" in cmd:
                    # Simulate package not yet installed before pip runs.
                    return mock.Mock(returncode=1)
                if len(cmd) >= 4 and cmd[1:4] == ["-m", "pip", "install"]:
                    return mock.Mock(returncode=0)
                return mock.Mock(returncode=0)

            with (
                mock.patch.object(env_bootstrap, "VENV_DIR", fake_venv),
                mock.patch.object(env_bootstrap, "REQ_FILE", fake_req),
                mock.patch.object(env_bootstrap, "MARKER_FILE", fake_marker),
                mock.patch.object(env_bootstrap.subprocess, "run", side_effect=fake_run),
                mock.patch.object(env_bootstrap.os, "execv") as mock_execv,
                mock.patch.dict(os.environ, {}, clear=False),
            ):
                os.environ.pop("PYKTO_NO_AUTO_VENV", None)
                os.environ.pop("PYKTO_BOOTSTRAPPED", None)
                env_bootstrap.ensure_environment(script_path=tmp_path / "app.py")

            self.assertTrue(any(c[1:3] == ["-m", "venv"] for c in calls))
            self.assertTrue(any(c[1:4] == ["-m", "pip", "install"] for c in calls))
            self.assertTrue(fake_marker.is_file())
            if os.name != "nt":
                mock_execv.assert_called_once()


if __name__ == "__main__":
    unittest.main(verbosity=2)
