#!/usr/bin/env python3
"""
CodeAlpha - Cyber Security Internship - Task 1
Basic Network Sniffer

Captures live network packets, unpacks their headers (Ethernet -> IP ->
TCP/UDP/ICMP) and prints source/destination addresses, ports, protocol
and a preview of the payload.

Built with Python's built-in `socket` module (no third-party library
needed). An equivalent scapy version is notably shorter - see the
"scapy_version.py" file alongside this one if your environment allows
`pip install scapy`.

REQUIREMENTS TO RUN:
  - Linux (uses AF_PACKET raw sockets; on Windows use AF_INET +
    socket.IPPROTO_IP with ioctl RCVALL instead - see note at bottom)
  - root / administrator privileges (raw sockets need elevated access)
  - Run as:  sudo python3 sniffer.py
"""

import socket
import struct
import textwrap
from datetime import datetime

# ---------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------

def mac_addr(raw_bytes):
    """Convert 6 raw bytes into a human-readable MAC address."""
    byte_str = map('{:02x}'.format, raw_bytes)
    return ':'.join(byte_str).upper()


def ipv4_addr(raw_bytes):
    """Convert 4 raw bytes into a human-readable dotted IPv4 address."""
    return '.'.join(map(str, raw_bytes))


def format_payload(data, max_bytes=64):
    """Return a short, safe preview of the payload (hex + printable ascii)."""
    snippet = data[:max_bytes]
    hex_part = ' '.join(f'{b:02x}' for b in snippet)
    ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in snippet)
    wrapped_hex = textwrap.fill(hex_part, width=48)
    return f"{wrapped_hex}\n        ascii: {ascii_part}"


# ---------------------------------------------------------------------
# Header unpacking functions
# ---------------------------------------------------------------------

def unpack_ethernet_frame(raw_data):
    """
    Ethernet II header = 14 bytes:
        6 bytes dest MAC | 6 bytes src MAC | 2 bytes EtherType
    """
    dest_mac, src_mac, eth_type = struct.unpack('! 6s 6s H', raw_data[:14])
    return mac_addr(dest_mac), mac_addr(src_mac), socket.htons(eth_type), raw_data[14:]


def unpack_ipv4_packet(raw_data):
    """
    IPv4 header (minimum 20 bytes):
        byte0: version(4 bits) + header length (4 bits, in 32-bit words)
        byte1: DSCP/ECN
        bytes2-3: total length
        bytes4-5: identification
        bytes6-7: flags + fragment offset
        byte8: TTL
        byte9: protocol  (1=ICMP, 6=TCP, 17=UDP)
        bytes10-11: header checksum
        bytes12-15: source IP
        bytes16-19: destination IP
    """
    version_header_len = raw_data[0]
    version = version_header_len >> 4
    header_len = (version_header_len & 15) * 4  # low nibble * 4 bytes
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
    return version, header_len, ttl, proto, ipv4_addr(src), ipv4_addr(target), raw_data[header_len:]


def unpack_tcp_segment(raw_data):
    """
    TCP header (minimum 20 bytes):
        bytes0-1: source port
        bytes2-3: destination port
        bytes4-7: sequence number
        bytes8-11: acknowledgment number
        byte12: data offset (top 4 bits) + reserved
        byte13: flags (URG, ACK, PSH, RST, SYN, FIN)
    """
    (src_port, dest_port, sequence, ack, offset_reserved_flags) = struct.unpack(
        '! H H L L H', raw_data[:14]
    )
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    flags = {
        'URG': flag_urg, 'ACK': flag_ack, 'PSH': flag_psh,
        'RST': flag_rst, 'SYN': flag_syn, 'FIN': flag_fin,
    }
    return src_port, dest_port, sequence, ack, flags, raw_data[offset:]


def unpack_udp_segment(raw_data):
    """
    UDP header = 8 bytes:
        bytes0-1: source port | bytes2-3: dest port
        bytes4-5: length      | bytes6-7: checksum
    """
    src_port, dest_port, length = struct.unpack('! H H 2x H', raw_data[:8])
    return src_port, dest_port, length, raw_data[8:]


def unpack_icmp_packet(raw_data):
    """
    ICMP header = 4 bytes: type(1) + code(1) + checksum(2)
    """
    icmp_type, code, checksum = struct.unpack('! B B H', raw_data[:4])
    return icmp_type, code, checksum, raw_data[4:]


PROTO_NAMES = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}


# ---------------------------------------------------------------------
# Main capture loop
# ---------------------------------------------------------------------

def main(packet_limit=None, interface=None):
    """
    Open a raw socket and capture packets until packet_limit is hit
    (or forever if packet_limit is None - stop with Ctrl+C).
    """
    try:
        # AF_PACKET + SOCK_RAW + ETH_P_ALL(0x0003) captures every
        # Ethernet frame that reaches this host's NIC.
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        if interface:
            conn.bind((interface, 0))
    except PermissionError:
        print("[!] Permission denied. Raw sockets need root privileges.")
        print("    Try: sudo python3 sniffer.py")
        return
    except AttributeError:
        print("[!] AF_PACKET is Linux-only. On Windows/macOS, use scapy's")
        print("    sniff() function instead (see scapy_version.py).")
        return

    print(f"[*] Sniffer started on interface: {interface or 'all interfaces'}")
    print("[*] Press Ctrl+C to stop.\n")

    count = 0
    try:
        while True:
            raw_data, addr = conn.recvfrom(65536)
            dest_mac, src_mac, eth_proto, eth_payload = unpack_ethernet_frame(raw_data)

            timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]

            # EtherType 0x0800 == IPv4
            if eth_proto == 8:
                (version, header_len, ttl, proto, src_ip, dest_ip,
                 ip_payload) = unpack_ipv4_packet(eth_payload)

                proto_name = PROTO_NAMES.get(proto, f'OTHER({proto})')

                print(f"[{timestamp}] Ethernet Frame:")
                print(f"    Dest MAC: {dest_mac}, Src MAC: {src_mac}, EtherType: {eth_proto}")
                print(f"    IPv{version} Packet:  TTL={ttl}  Protocol={proto_name}")
                print(f"    Src IP: {src_ip}   ->   Dest IP: {dest_ip}")

                if proto == 6:  # TCP
                    (src_port, dest_port, sequence, ack, flags,
                     tcp_payload) = unpack_tcp_segment(ip_payload)
                    active_flags = ','.join(f for f, v in flags.items() if v)
                    print(f"    TCP  Src Port: {src_port} -> Dest Port: {dest_port}")
                    print(f"    Seq={sequence} Ack={ack} Flags=[{active_flags}]")
                    if tcp_payload:
                        print(f"    Payload ({len(tcp_payload)} bytes):")
                        print(f"        {format_payload(tcp_payload)}")

                elif proto == 17:  # UDP
                    src_port, dest_port, length, udp_payload = unpack_udp_segment(ip_payload)
                    print(f"    UDP  Src Port: {src_port} -> Dest Port: {dest_port}  Length={length}")
                    if udp_payload:
                        print(f"    Payload ({len(udp_payload)} bytes):")
                        print(f"        {format_payload(udp_payload)}")

                elif proto == 1:  # ICMP
                    icmp_type, code, checksum, icmp_payload = unpack_icmp_packet(ip_payload)
                    print(f"    ICMP Type: {icmp_type}  Code: {code}")

                else:
                    print(f"    [Other IP protocol #{proto}, {len(ip_payload)} bytes payload]")

                print('-' * 70)
                count += 1
                if packet_limit and count >= packet_limit:
                    print(f"[*] Reached packet limit ({packet_limit}). Stopping.")
                    break
            else:
                # Non-IPv4 frame (ARP=0x0806, IPv6=0x86DD, etc.) - skip quietly
                continue

    except KeyboardInterrupt:
        print(f"\n[*] Stopped by user. Captured {count} IPv4 packets.")
    finally:
        conn.close()


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description="Basic Network Sniffer - CodeAlpha Task 1")
    parser.add_argument('-c', '--count', type=int, default=None,
                         help="Number of packets to capture before stopping (default: run until Ctrl+C)")
    parser.add_argument('-i', '--interface', type=str, default=None,
                         help="Network interface to bind to, e.g. eth0 (default: all interfaces)")
    args = parser.parse_args()

    main(packet_limit=args.count, interface=args.interface)
