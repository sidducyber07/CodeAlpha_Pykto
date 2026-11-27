#!/usr/bin/env python3
"""
CodeAlpha - Cyber Security Internship - Task 1
Basic Network Sniffer (scapy version)

This is a shorter, alternative implementation using the `scapy` library
instead of raw sockets. scapy does the header-parsing for you, which is
why task instructions mention it as an option.

INSTALL FIRST:
    pip install scapy

RUN (needs admin/root privileges to open a raw socket):
    sudo python3 scapy_version.py
    sudo python3 scapy_version.py -c 20 -i eth0     # limit + interface
"""

import argparse
from pathlib import Path
import sys

SNIFX_DIR = Path(__file__).resolve().parent
if str(SNIFX_DIR) not in sys.path:
    sys.path.insert(0, str(SNIFX_DIR))

from env_bootstrap import ensure_environment  # noqa: E402

if __name__ == "__main__":
    ensure_environment(Path(__file__))

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw  # noqa: E402


def handle_packet(packet):
    """Callback invoked by scapy for every captured packet."""
    if IP not in packet:
        return  # skip non-IP frames (ARP, IPv6, etc.)

    ip_layer = packet[IP]
    proto = ip_layer.proto  # 1=ICMP, 6=TCP, 17=UDP

    print(f"\nIPv4 Packet: {ip_layer.src} -> {ip_layer.dst}  (TTL={ip_layer.ttl})")

    if TCP in packet:
        tcp_layer = packet[TCP]
        print(f"  TCP  {tcp_layer.sport} -> {tcp_layer.dport}  Flags={tcp_layer.flags}")
    elif UDP in packet:
        udp_layer = packet[UDP]
        print(f"  UDP  {udp_layer.sport} -> {udp_layer.dport}")
    elif ICMP in packet:
        icmp_layer = packet[ICMP]
        print(f"  ICMP Type={icmp_layer.type} Code={icmp_layer.code}")
    else:
        print(f"  [Other protocol #{proto}]")

    if Raw in packet:
        payload = bytes(packet[Raw].load)
        preview = payload[:48]
        print(f"  Payload preview ({len(payload)} bytes): {preview}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Basic Network Sniffer (scapy) - CodeAlpha Task 1")
    parser.add_argument('-c', '--count', type=int, default=0,
                         help="Number of packets to capture (default: 0 = unlimited, Ctrl+C to stop)")
    parser.add_argument('-i', '--interface', type=str, default=None,
                         help="Network interface to sniff on, e.g. eth0 (default: scapy's default)")
    args = parser.parse_args()

    print("[*] Starting scapy sniffer. Press Ctrl+C to stop.")
    sniff(prn=handle_packet, count=args.count, iface=args.interface, store=False)
