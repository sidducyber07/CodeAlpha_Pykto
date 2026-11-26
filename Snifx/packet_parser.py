"""
Packet parsing and formatting utilities for Pykto.

This module decodes raw network bytes (from Python's built-in `socket`) as
well as `scapy` Packet objects into one shared `PacketRecord` structure so the
GUI can display them identically.
"""

from dataclasses import dataclass
from datetime import datetime
import socket
import struct
from typing import Optional


# IPv4 "Protocol" / IPv6 "Next Header" numbers mapped to human-readable names.
PROTO_NAMES = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6-Encap",
    47: "GRE",
    50: "ESP",
    58: "ICMPv6",
    89: "OSPF",
}

# Common TCP/UDP port numbers used to label traffic in the Summary column.
WELL_KNOWN_PORTS = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-ALT",
}


@dataclass(slots=True)
class PacketRecord:
    """Normalized representation of a single captured network packet."""

    index: int             # Sequential packet counter (# column in UI)
    timestamp: str         # Local capture time (HH:MM:SS.mmm)
    protocol: str          # Primary filter bucket: TCP, UDP, ICMP, or OTHER
    src_ip: str            # Source IP address (or MAC for non-IP L2 frames)
    dst_ip: str            # Destination IP address (or MAC for non-IP L2 frames)
    src_port: Optional[int]
    dst_port: Optional[int]
    length: int            # Total captured frame/packet length in bytes
    info: str              # One-line summary shown in the live packet table
    src_mac: str = ""
    dst_mac: str = ""
    ttl: Optional[int] = None
    ip_version: Optional[int] = None
    tcp_flags: str = ""
    payload: bytes = b""   # Upper-layer application payload bytes
    detail_lines: tuple[str, ...] = ()

    @property
    def src_display(self) -> str:
        """Format source as 'IP:Port' when a transport port exists."""
        if self.src_port is not None:
            return f"{self.src_ip}:{self.src_port}"
        return self.src_ip

    @property
    def dst_display(self) -> str:
        """Format destination as 'IP:Port' when a transport port exists."""
        if self.dst_port is not None:
            return f"{self.dst_ip}:{self.dst_port}"
        return self.dst_ip

    @property
    def is_loopback(self) -> bool:
        """Return True if either endpoint is IPv4 (127.x) or IPv6 (::1) loopback."""
        return (
            self.src_ip.startswith("127.")
            or self.dst_ip.startswith("127.")
            or self.src_ip == "::1"
            or self.dst_ip == "::1"
        )


def format_mac(raw_bytes: bytes) -> str:
    """Convert 6 raw MAC bytes into uppercase colon-separated hex (XX:XX:XX:XX:XX:XX)."""
    return ":".join(f"{b:02X}" for b in raw_bytes)


def format_ipv4(raw_bytes: bytes) -> str:
    """Convert 4 raw bytes into dotted-decimal IPv4 notation (e.g., 192.168.1.1)."""
    return ".".join(str(b) for b in raw_bytes)


def format_ipv6(raw_bytes: bytes) -> str:
    """Convert 16 raw bytes into standard compressed IPv6 notation."""
    try:
        return socket.inet_ntop(socket.AF_INET6, raw_bytes)
    except (OSError, ValueError):
        return ":".join(f"{raw_bytes[i]:02x}{raw_bytes[i + 1]:02x}" for i in range(0, 16, 2))


def format_payload_hexdump(data: bytes, max_bytes: int = 512) -> str:
    """
    Format payload bytes as a bounded Wireshark-style hex + ASCII dump.

    Capping at `max_bytes` keeps the Packet Inspector fast and readable even on
    large 1500-byte frames.
    """
    if not data:
        return "(no payload)"

    truncated = len(data) > max_bytes
    snippet = data[:max_bytes]
    lines: list[str] = []

    for offset in range(0, len(snippet), 16):
        chunk = snippet[offset:offset + 16]
        hex_cols = " ".join(f"{b:02x}" for b in chunk)
        # Replace non-printable control/binary bytes with '.' so UI text stays clean.
        ascii_col = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{offset:04x}  {hex_cols:<47}  |{ascii_col}|")

    if truncated:
        lines.append(f"... ({len(data) - max_bytes} more bytes omitted; total {len(data)} bytes)")

    return "\n".join(lines)


def _service_hint(src_port: Optional[int], dst_port: Optional[int]) -> str:
    """Return a known protocol label (e.g., HTTPS, DNS) if either port is recognized."""
    for port in (dst_port, src_port):
        if port in WELL_KNOWN_PORTS:
            return WELL_KNOWN_PORTS[port]
    return ""


def _parse_transport(
    proto_num: int,
    ip_payload: bytes,
    src_ip: str,
    dst_ip: str,
    ip_version: int,
    ttl: int,
    src_mac: str,
    dst_mac: str,
    total_len: int,
    index: int,
    timestamp: str,
) -> PacketRecord:
    """
    Parse Layer 4 (TCP, UDP, ICMP, ICMPv6, or other) inside an IPv4/IPv6 packet.

    `!` in struct.unpack formats specifies network byte order (big-endian).
    """
    details = [
        f"Captured At : {timestamp}",
        f"Frame Length: {total_len} bytes",
    ]
    if src_mac or dst_mac:
        details.append(f"Ethernet    : {src_mac} -> {dst_mac}")
    details.append(f"IPv{ip_version}        : {src_ip} -> {dst_ip}  (TTL/HopLimit={ttl})")

    # TCP header is at least 20 bytes:
    #   src_port(2) | dst_port(2) | seq(4) | ack(4) | data_offset(4 bits) + reserved + flags(6 bits)
    if proto_num == 6 and len(ip_payload) >= 20:
        src_port, dst_port, seq, ack, off_flags = struct.unpack("! H H L L H", ip_payload[:14])
        # Top 4 bits hold header length in 32-bit (4-byte) words; TCP options can extend it >20 bytes.
        data_offset = max(20, (off_flags >> 12) * 4)
        flag_bits = (
            ("URG", 32),
            ("ACK", 16),
            ("PSH", 8),
            ("RST", 4),
            ("SYN", 2),
            ("FIN", 1),
        )
        active_flags = [name for name, mask in flag_bits if off_flags & mask]
        flags_str = ",".join(active_flags) if active_flags else "NONE"
        payload = ip_payload[data_offset:] if len(ip_payload) >= data_offset else b""
        svc = _service_hint(src_port, dst_port)
        svc_tag = f"[{svc}] " if svc else ""
        info = f"{svc_tag}{src_port} -> {dst_port} [{flags_str}] Len={len(payload)}"
        details.extend([
            f"Protocol    : TCP" + (f" ({svc})" if svc else ""),
            f"Ports       : {src_port} -> {dst_port}",
            f"Flags       : [{flags_str}]",
            f"Sequence    : {seq}   Ack: {ack}",
            f"Header Len  : {data_offset} bytes   Payload: {len(payload)} bytes",
        ])
        return PacketRecord(
            index=index,
            timestamp=timestamp,
            protocol="TCP",
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            length=total_len,
            info=info,
            src_mac=src_mac,
            dst_mac=dst_mac,
            ttl=ttl,
            ip_version=ip_version,
            tcp_flags=flags_str,
            payload=payload,
            detail_lines=tuple(details),
        )

    # UDP header is fixed at 8 bytes: src_port(2) | dst_port(2) | length(2) | checksum(2)
    if proto_num == 17 and len(ip_payload) >= 8:
        src_port, dst_port, udp_len = struct.unpack("! H H H", ip_payload[:6])
        payload = ip_payload[8:]
        svc = _service_hint(src_port, dst_port)
        svc_tag = f"[{svc}] " if svc else ""
        info = f"{svc_tag}{src_port} -> {dst_port} Len={len(payload)}"
        details.extend([
            f"Protocol    : UDP" + (f" ({svc})" if svc else ""),
            f"Ports       : {src_port} -> {dst_port}",
            f"UDP Length  : {udp_len} bytes   Payload: {len(payload)} bytes",
        ])
        return PacketRecord(
            index=index,
            timestamp=timestamp,
            protocol="UDP",
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            length=total_len,
            info=info,
            src_mac=src_mac,
            dst_mac=dst_mac,
            ttl=ttl,
            ip_version=ip_version,
            payload=payload,
            detail_lines=tuple(details),
        )

    # ICMP / ICMPv6 header starts with 4 bytes: type(1) | code(1) | checksum(2)
    if proto_num in (1, 58) and len(ip_payload) >= 4:
        icmp_type, code, checksum = struct.unpack("! B B H", ip_payload[:4])
        payload = ip_payload[4:]
        proto_label = "ICMPv6" if proto_num == 58 else "ICMP"
        type_desc = ""
        if proto_num == 1:
            type_desc = {0: " (Echo Reply)", 8: " (Echo Request)", 3: " (Dest Unreachable)", 11: " (Time Exceeded)"}.get(icmp_type, "")
        info = f"{proto_label} Type={icmp_type}{type_desc} Code={code}"
        details.extend([
            f"Protocol    : {proto_label}",
            f"Type / Code : {icmp_type}{type_desc} / {code}",
            f"Checksum    : 0x{checksum:04x}   Payload: {len(payload)} bytes",
        ])
        return PacketRecord(
            index=index,
            timestamp=timestamp,
            protocol="ICMP",
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=None,
            dst_port=None,
            length=total_len,
            info=info,
            src_mac=src_mac,
            dst_mac=dst_mac,
            ttl=ttl,
            ip_version=ip_version,
            payload=payload,
            detail_lines=tuple(details),
        )

    # Any other IP protocol (IGMP, GRE, OSPF, etc.) falls into the OTHER bucket.
    proto_name = PROTO_NAMES.get(proto_num, f"IP-PROTO-{proto_num}")
    details.extend([
        f"Protocol    : {proto_name} (#{proto_num})",
        f"Payload     : {len(ip_payload)} bytes",
    ])
    return PacketRecord(
        index=index,
        timestamp=timestamp,
        protocol="OTHER",
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=None,
        dst_port=None,
        length=total_len,
        info=f"{proto_name} (#{proto_num}) Len={len(ip_payload)}",
        src_mac=src_mac,
        dst_mac=dst_mac,
        ttl=ttl,
        ip_version=ip_version,
        payload=ip_payload,
        detail_lines=tuple(details),
    )


def parse_raw_ethernet_frame(raw_data: bytes, index: int) -> Optional[PacketRecord]:
    """
    Parse a raw Ethernet II frame captured from an AF_PACKET raw socket.

    Returns None if the frame is shorter than a valid 14-byte Ethernet header.
    """
    if len(raw_data) < 14:
        return None

    # Ethernet II header = 14 bytes: Dest MAC (6) | Src MAC (6) | EtherType (2)
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    dest_mac_b, src_mac_b, eth_type = struct.unpack("! 6s 6s H", raw_data[:14])
    dest_mac = format_mac(dest_mac_b)
    src_mac = format_mac(src_mac_b)
    eth_payload = raw_data[14:]
    total_len = len(raw_data)

    # IPv4 (EtherType 0x0800): minimum 20-byte header.
    if eth_type == 0x0800 and len(eth_payload) >= 20:
        ver_ihl = eth_payload[0]
        version = ver_ihl >> 4             # High 4 bits = IP version (4)
        ihl = (ver_ihl & 0x0F) * 4         # Low 4 bits = header length in 32-bit words
        if ihl < 20 or len(eth_payload) < ihl:
            return None
        # Skip first 8 bytes, read TTL(1) + Proto(1), skip 2B checksum, read Src(4) + Dst(4).
        ttl, proto, src_b, dst_b = struct.unpack("! 8x B B 2x 4s 4s", eth_payload[:20])
        return _parse_transport(
            proto_num=proto,
            ip_payload=eth_payload[ihl:],
            src_ip=format_ipv4(src_b),
            dst_ip=format_ipv4(dst_b),
            ip_version=version,
            ttl=ttl,
            src_mac=src_mac,
            dst_mac=dest_mac,
            total_len=total_len,
            index=index,
            timestamp=timestamp,
        )

    # IPv6 (EtherType 0x86DD): fixed 40-byte header; Next Header is byte 6, Hop Limit is byte 7.
    if eth_type == 0x86DD and len(eth_payload) >= 40:
        next_hdr, hop_limit, src_b, dst_b = struct.unpack("! 6x B B 16s 16s", eth_payload[:40])
        return _parse_transport(
            proto_num=next_hdr,
            ip_payload=eth_payload[40:],
            src_ip=format_ipv6(src_b),
            dst_ip=format_ipv6(dst_b),
            ip_version=6,
            ttl=hop_limit,
            src_mac=src_mac,
            dst_mac=dest_mac,
            total_len=total_len,
            index=index,
            timestamp=timestamp,
        )

    # ARP (EtherType 0x0806): resolves IPv4 addresses to MAC addresses on local LANs.
    if eth_type == 0x0806 and len(eth_payload) >= 28:
        # Skip 6-byte hardware/proto metadata, then unpack Operation + Sender/Target MAC & IP.
        oper, sha, spa, tha, tpa = struct.unpack("! 6x H 6s 4s 6s 4s", eth_payload[:28])
        src_ip = format_ipv4(spa)
        dst_ip = format_ipv4(tpa)
        op_label = "Request" if oper == 1 else ("Reply" if oper == 2 else f"Op={oper}")
        info = f"ARP {op_label}: {src_ip} ({format_mac(sha)}) -> {dst_ip}"
        details = (
            f"Captured At : {timestamp}",
            f"Frame Length: {total_len} bytes",
            f"Ethernet    : {src_mac} -> {dest_mac}",
            f"Protocol    : ARP ({op_label})",
            f"Sender      : {src_ip} ({format_mac(sha)})",
            f"Target      : {dst_ip} ({format_mac(tha)})",
        )
        return PacketRecord(
            index=index,
            timestamp=timestamp,
            protocol="OTHER",
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=None,
            dst_port=None,
            length=total_len,
            info=info,
            src_mac=src_mac,
            dst_mac=dest_mac,
            payload=eth_payload,
            detail_lines=details,
        )

    # Other L2 EtherType (e.g., VLAN, LLDP, IPX)
    info = f"EtherType 0x{eth_type:04X} ({len(eth_payload)} bytes)"
    details = (
        f"Captured At : {timestamp}",
        f"Frame Length: {total_len} bytes",
        f"Ethernet    : {src_mac} -> {dest_mac} (EtherType=0x{eth_type:04X})",
    )
    return PacketRecord(
        index=index,
        timestamp=timestamp,
        protocol="OTHER",
        src_ip=src_mac,
        dst_ip=dest_mac,
        src_port=None,
        dst_port=None,
        length=total_len,
        info=info,
        src_mac=src_mac,
        dst_mac=dest_mac,
        payload=eth_payload,
        detail_lines=details,
    )


def parse_raw_ipv4_packet(raw_data: bytes, index: int) -> Optional[PacketRecord]:
    """Parse a raw IPv4 packet (used on Windows AF_INET raw sockets without L2 header)."""
    if len(raw_data) < 20:
        return None
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    ver_ihl = raw_data[0]
    version = ver_ihl >> 4
    ihl = (ver_ihl & 0x0F) * 4
    if version != 4 or ihl < 20 or len(raw_data) < ihl:
        return None
    ttl, proto, src_b, dst_b = struct.unpack("! 8x B B 2x 4s 4s", raw_data[:20])
    return _parse_transport(
        proto_num=proto,
        ip_payload=raw_data[ihl:],
        src_ip=format_ipv4(src_b),
        dst_ip=format_ipv4(dst_b),
        ip_version=4,
        ttl=ttl,
        src_mac="",
        dst_mac="",
        total_len=len(raw_data),
        index=index,
        timestamp=timestamp,
    )


def parse_scapy_packet(packet, index: int) -> PacketRecord:
    """
    Convert a `scapy` Packet object into a normalized `PacketRecord`.

    Scapy already dissects Ethernet, IP/IPv6, TCP/UDP/ICMP, ARP, and Raw
    payload layers for us; this function extracts the same fields used by the UI.
    """
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import ARP, Ether
    from scapy.packet import Raw

    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    raw_bytes = bytes(packet)
    total_len = len(raw_bytes)
    src_mac = (packet[Ether].src or "").upper() if Ether in packet else ""
    dst_mac = (packet[Ether].dst or "").upper() if Ether in packet else ""
    payload = bytes(packet[Raw].load) if Raw in packet else b""

    details = [
        f"Captured At : {timestamp}",
        f"Frame Length: {total_len} bytes",
    ]
    if src_mac or dst_mac:
        details.append(f"Ethernet    : {src_mac} -> {dst_mac}")

    if IP in packet or IPv6 in packet:
        if IP in packet:
            ip_layer = packet[IP]
            ip_ver = 4
            ttl = int(ip_layer.ttl)
            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)
            proto_num = int(ip_layer.proto)
        else:
            ip_layer = packet[IPv6]
            ip_ver = 6
            ttl = int(ip_layer.hlim)
            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)
            proto_num = int(ip_layer.nh)

        details.append(f"IPv{ip_ver}        : {src_ip} -> {dst_ip}  (TTL/HopLimit={ttl})")

        if TCP in packet:
            tcp = packet[TCP]
            src_port, dst_port = int(tcp.sport), int(tcp.dport)
            flags_str = str(tcp.flags) or "NONE"
            svc = _service_hint(src_port, dst_port)
            svc_tag = f"[{svc}] " if svc else ""
            info = f"{svc_tag}{src_port} -> {dst_port} [{flags_str}] Len={len(payload)}"
            details.extend([
                f"Protocol    : TCP" + (f" ({svc})" if svc else ""),
                f"Ports       : {src_port} -> {dst_port}",
                f"Flags       : [{flags_str}]",
                f"Sequence    : {tcp.seq}   Ack: {tcp.ack}",
                f"Payload     : {len(payload)} bytes",
            ])
            return PacketRecord(
                index=index,
                timestamp=timestamp,
                protocol="TCP",
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                length=total_len,
                info=info,
                src_mac=src_mac,
                dst_mac=dst_mac,
                ttl=ttl,
                ip_version=ip_ver,
                tcp_flags=flags_str,
                payload=payload,
                detail_lines=tuple(details),
            )

        if UDP in packet:
            udp = packet[UDP]
            src_port, dst_port = int(udp.sport), int(udp.dport)
            svc = _service_hint(src_port, dst_port)
            svc_tag = f"[{svc}] " if svc else ""
            info = f"{svc_tag}{src_port} -> {dst_port} Len={len(payload)}"
            details.extend([
                f"Protocol    : UDP" + (f" ({svc})" if svc else ""),
                f"Ports       : {src_port} -> {dst_port}",
                f"UDP Length  : {udp.len} bytes   Payload: {len(payload)} bytes",
            ])
            return PacketRecord(
                index=index,
                timestamp=timestamp,
                protocol="UDP",
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                length=total_len,
                info=info,
                src_mac=src_mac,
                dst_mac=dst_mac,
                ttl=ttl,
                ip_version=ip_ver,
                payload=payload,
                detail_lines=tuple(details),
            )

        if ICMP in packet:
            icmp = packet[ICMP]
            info = f"ICMP Type={icmp.type} Code={icmp.code}"
            details.extend([
                "Protocol    : ICMP",
                f"Type / Code : {icmp.type} / {icmp.code}",
                f"Payload     : {len(payload)} bytes",
            ])
            return PacketRecord(
                index=index,
                timestamp=timestamp,
                protocol="ICMP",
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=None,
                dst_port=None,
                length=total_len,
                info=info,
                src_mac=src_mac,
                dst_mac=dst_mac,
                ttl=ttl,
                ip_version=ip_ver,
                payload=payload,
                detail_lines=tuple(details),
            )

        proto_name = PROTO_NAMES.get(proto_num, f"IP-PROTO-{proto_num}")
        details.append(f"Protocol    : {proto_name} (#{proto_num})")
        return PacketRecord(
            index=index,
            timestamp=timestamp,
            protocol="OTHER",
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=None,
            dst_port=None,
            length=total_len,
            info=packet.summary(),
            src_mac=src_mac,
            dst_mac=dst_mac,
            ttl=ttl,
            ip_version=ip_ver,
            payload=payload,
            detail_lines=tuple(details),
        )

    if ARP in packet:
        arp = packet[ARP]
        op_label = "Request" if arp.op == 1 else ("Reply" if arp.op == 2 else f"Op={arp.op}")
        info = f"ARP {op_label}: {arp.psrc} -> {arp.pdst}"
        details.extend([
            f"Protocol    : ARP ({op_label})",
            f"Sender      : {arp.psrc} ({arp.hwsrc})",
            f"Target      : {arp.pdst} ({arp.hwdst})",
        ])
        return PacketRecord(
            index=index,
            timestamp=timestamp,
            protocol="OTHER",
            src_ip=str(arp.psrc),
            dst_ip=str(arp.pdst),
            src_port=None,
            dst_port=None,
            length=total_len,
            info=info,
            src_mac=src_mac,
            dst_mac=dst_mac,
            payload=raw_bytes[14:],
            detail_lines=tuple(details),
        )

    details.append(f"Summary     : {packet.summary()}")
    return PacketRecord(
        index=index,
        timestamp=timestamp,
        protocol="OTHER",
        src_ip=src_mac or "unknown",
        dst_ip=dst_mac or "unknown",
        src_port=None,
        dst_port=None,
        length=total_len,
        info=packet.summary(),
        src_mac=src_mac,
        dst_mac=dst_mac,
        payload=payload or raw_bytes,
        detail_lines=tuple(details),
    )
