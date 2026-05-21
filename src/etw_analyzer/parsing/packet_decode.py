"""Packet-header decoder.

Stdlib-only decoder for Ethernet, IPv4, IPv6, TCP, UDP, ICMP, and ICMPv6
headers. Used by the Phase 4 packet-capture tools to lazily inspect bytes
recorded by the ``Microsoft-Windows-NDIS-PacketCapture`` provider.

Design notes:
  * Single entry point: :func:`decode_packet_headers` — takes ``bytes`` and
    returns a flat dict with dot-delimited keys (``eth.src``, ``ip.proto``,
    ``tcp.src_port``, ...).
  * Defensive: every layer checks the input length before slicing; if the
    buffer is too short to contain a header, the function returns whatever
    has been decoded so far plus ``_truncated_at`` indicating the layer at
    which parsing stopped (``"eth"``, ``"ip"``, ``"tcp"``, ...).
  * Best-effort, not exhaustive: IP options are consumed but not decoded;
    TCP options are consumed but not decoded; IPv6 extension headers are
    not chased (we read the first ``next_header`` and use that as the L4
    protocol). The NDIS PacketCapture provider records the Ethernet /
    on-wire bytes, so the common case is a single IPv4/IPv6 header
    followed directly by TCP/UDP.
  * No scapy. Uses ``struct`` for fixed-width fields and ``socket.inet_ntop``
    for address formatting.

The decoded dict uses ``str`` values for addresses and IDs (matches scapy /
pktmon style for ease of reading), ``int`` for numeric fields, and ``list``
for TCP flag names.
"""

from __future__ import annotations

import socket
import struct
from typing import Any

# Ethernet
_ETH_HEADER_LEN = 14
_ETHERTYPE_IPV4 = 0x0800
_ETHERTYPE_IPV6 = 0x86DD
_ETHERTYPE_ARP = 0x0806
_ETHERTYPE_VLAN = 0x8100

# IPv4
_IPV4_MIN_HEADER_LEN = 20

# IPv6
_IPV6_HEADER_LEN = 40

# Transport protocols
_PROTO_ICMP = 1
_PROTO_TCP = 6
_PROTO_UDP = 17
_PROTO_ICMPV6 = 58

# TCP
_TCP_MIN_HEADER_LEN = 20

# UDP
_UDP_HEADER_LEN = 8

# ICMP
_ICMP_MIN_HEADER_LEN = 4


def _mac_str(b: bytes) -> str:
    """Format 6-byte MAC as ``aa:bb:cc:dd:ee:ff``."""
    return ":".join(f"{x:02x}" for x in b)


def _decode_ethernet(packet: bytes, out: dict[str, Any]) -> tuple[int, int] | None:
    """Decode an Ethernet header.

    Returns ``(ethertype, offset_after_header)`` on success or ``None`` if
    the buffer is too short. Handles a single 802.1Q VLAN tag transparently
    so the caller sees the inner ethertype.
    """
    if len(packet) < _ETH_HEADER_LEN:
        out["_truncated_at"] = "eth"
        return None
    dst, src, ethertype = struct.unpack("!6s6sH", packet[:_ETH_HEADER_LEN])
    out["eth.dst"] = _mac_str(dst)
    out["eth.src"] = _mac_str(src)
    out["eth.ethertype"] = ethertype

    offset = _ETH_HEADER_LEN
    # Single VLAN tag (802.1Q). We don't decode the TCI fields beyond
    # surfacing the tagged ethertype.
    if ethertype == _ETHERTYPE_VLAN:
        if len(packet) < offset + 4:
            out["_truncated_at"] = "vlan"
            return None
        # TCI (16 bits) + inner ethertype (16 bits)
        (_tci, inner_et) = struct.unpack("!HH", packet[offset:offset + 4])
        out["eth.vlan_ethertype"] = inner_et
        ethertype = inner_et
        offset += 4

    return ethertype, offset


def _decode_ipv4(packet: bytes, offset: int, out: dict[str, Any]) -> tuple[int, int] | None:
    """Decode an IPv4 header at ``offset``.

    Returns ``(protocol, next_offset)`` on success or ``None`` on truncation.
    """
    if len(packet) < offset + _IPV4_MIN_HEADER_LEN:
        out["_truncated_at"] = "ip"
        return None

    vihl = packet[offset]
    version = vihl >> 4
    ihl = vihl & 0x0F
    header_len = ihl * 4

    if version != 4:
        # Caller already saw an IPv4 ethertype; this is malformed. Surface
        # the version and stop.
        out["ip.version"] = version
        out["_truncated_at"] = "ip"
        return None

    if header_len < _IPV4_MIN_HEADER_LEN:
        # Bogus IHL. Don't trust subsequent bytes.
        out["ip.version"] = 4
        out["ip.ihl"] = ihl
        out["_truncated_at"] = "ip"
        return None

    if len(packet) < offset + header_len:
        out["ip.version"] = 4
        out["ip.ihl"] = ihl
        out["_truncated_at"] = "ip"
        return None

    # Standard 20-byte fields.
    (
        _vihl, tos, total_length, identification,
        flags_frag, ttl, proto, _checksum,
        src_addr, dst_addr,
    ) = struct.unpack("!BBHHHBBH4s4s", packet[offset:offset + _IPV4_MIN_HEADER_LEN])

    out["ip.version"] = 4
    out["ip.ihl"] = ihl
    out["ip.header_len"] = header_len
    out["ip.tos"] = tos
    out["ip.total_length"] = total_length
    out["ip.id"] = identification
    out["ip.flags"] = (flags_frag >> 13) & 0x07
    out["ip.frag_offset"] = flags_frag & 0x1FFF
    out["ip.ttl"] = ttl
    out["ip.proto"] = proto
    out["ip.src"] = socket.inet_ntop(socket.AF_INET, src_addr)
    out["ip.dst"] = socket.inet_ntop(socket.AF_INET, dst_addr)

    return proto, offset + header_len


def _decode_ipv6(packet: bytes, offset: int, out: dict[str, Any]) -> tuple[int, int] | None:
    """Decode an IPv6 header at ``offset``.

    Returns ``(next_header, next_offset)`` on success or ``None`` on
    truncation. We do not walk extension headers — ``next_header`` is
    surfaced as the L4 protocol, which is correct for the common case of
    no extensions and "best-effort" otherwise.
    """
    if len(packet) < offset + _IPV6_HEADER_LEN:
        out["_truncated_at"] = "ip"
        return None

    (
        vtcfl, payload_len, next_header, hop_limit,
        src_addr, dst_addr,
    ) = struct.unpack("!IHBB16s16s", packet[offset:offset + _IPV6_HEADER_LEN])

    version = vtcfl >> 28
    out["ip.version"] = version if version == 6 else 6
    out["ip.payload_length"] = payload_len
    out["ip.next_header"] = next_header
    out["ip.proto"] = next_header
    out["ip.hop_limit"] = hop_limit
    out["ip.src"] = socket.inet_ntop(socket.AF_INET6, src_addr)
    out["ip.dst"] = socket.inet_ntop(socket.AF_INET6, dst_addr)

    return next_header, offset + _IPV6_HEADER_LEN


_TCP_FLAG_NAMES = [
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
    (0x40, "ECE"),
    (0x80, "CWR"),
]


def _decode_tcp(packet: bytes, offset: int, out: dict[str, Any]) -> int | None:
    """Decode a TCP header at ``offset``.

    Returns the offset past the TCP header on success, ``None`` on
    truncation. Payload length is not computed here (caller has the IP
    total_length / payload_length).
    """
    if len(packet) < offset + _TCP_MIN_HEADER_LEN:
        out["_truncated_at"] = "tcp"
        return None

    (
        src_port, dst_port, seq, ack, off_flags,
        window, _checksum, urgent_ptr,
    ) = struct.unpack("!HHIIHHHH", packet[offset:offset + _TCP_MIN_HEADER_LEN])

    data_offset = (off_flags >> 12) & 0x0F
    flags_byte = off_flags & 0x01FF  # 9 bits incl. NS — we only name 8
    header_len = data_offset * 4

    if header_len < _TCP_MIN_HEADER_LEN:
        out["tcp.src_port"] = src_port
        out["tcp.dst_port"] = dst_port
        out["_truncated_at"] = "tcp"
        return None

    if len(packet) < offset + header_len:
        # Header claims to be longer than the buffer — surface the basic
        # fields we have and stop.
        out["tcp.src_port"] = src_port
        out["tcp.dst_port"] = dst_port
        out["tcp.seq"] = seq
        out["tcp.ack"] = ack
        out["tcp.data_offset"] = data_offset
        out["tcp.flags_raw"] = flags_byte
        out["_truncated_at"] = "tcp"
        return None

    flag_names = [name for mask, name in _TCP_FLAG_NAMES if flags_byte & mask]
    out["tcp.src_port"] = src_port
    out["tcp.dst_port"] = dst_port
    out["tcp.seq"] = seq
    out["tcp.ack"] = ack
    out["tcp.data_offset"] = data_offset
    out["tcp.header_len"] = header_len
    out["tcp.flags_raw"] = flags_byte
    out["tcp.flags"] = flag_names
    out["tcp.window"] = window
    out["tcp.urgent_ptr"] = urgent_ptr

    return offset + header_len


def _decode_udp(packet: bytes, offset: int, out: dict[str, Any]) -> int | None:
    """Decode a UDP header at ``offset``.

    Returns the offset past the UDP header on success, ``None`` on
    truncation.
    """
    if len(packet) < offset + _UDP_HEADER_LEN:
        out["_truncated_at"] = "udp"
        return None

    src_port, dst_port, length, _checksum = struct.unpack(
        "!HHHH", packet[offset:offset + _UDP_HEADER_LEN]
    )
    out["udp.src_port"] = src_port
    out["udp.dst_port"] = dst_port
    out["udp.length"] = length
    return offset + _UDP_HEADER_LEN


def _decode_icmp(packet: bytes, offset: int, out: dict[str, Any], *, v6: bool) -> int | None:
    """Decode an ICMP / ICMPv6 header (just type + code + checksum).

    Returns the offset past the 4-byte header on success, ``None`` on
    truncation. ``v6`` controls the key prefix (``icmpv6.*`` vs ``icmp.*``).
    """
    prefix = "icmpv6" if v6 else "icmp"
    if len(packet) < offset + _ICMP_MIN_HEADER_LEN:
        out["_truncated_at"] = prefix
        return None
    icmp_type, code, _checksum = struct.unpack(
        "!BBH", packet[offset:offset + _ICMP_MIN_HEADER_LEN]
    )
    out[f"{prefix}.type"] = icmp_type
    out[f"{prefix}.code"] = code
    return offset + _ICMP_MIN_HEADER_LEN


def decode_packet_headers(packet: bytes) -> dict[str, Any]:
    """Decode Ethernet → IP → L4 headers from a packet byte buffer.

    Returns a flat dict with dot-delimited keys:

    * ``eth.dst``, ``eth.src``, ``eth.ethertype`` (and ``eth.vlan_ethertype``
      when a single 802.1Q tag is present).
    * ``ip.version``, ``ip.src``, ``ip.dst``, ``ip.proto``, ``ip.ttl`` /
      ``ip.hop_limit``, ``ip.total_length`` / ``ip.payload_length``,
      ``ip.id`` (IPv4 only).
    * ``tcp.src_port``, ``tcp.dst_port``, ``tcp.seq``, ``tcp.ack``,
      ``tcp.flags`` (list of names), ``tcp.flags_raw`` (int).
    * ``udp.src_port``, ``udp.dst_port``, ``udp.length``.
    * ``icmp.type`` / ``icmp.code`` for ICMP, ``icmpv6.type`` / ``icmpv6.code``
      for ICMPv6.

    If the packet is truncated mid-header, the dict contains ``_truncated_at``
    set to ``"eth"``, ``"vlan"``, ``"ip"``, ``"tcp"``, ``"udp"``, ``"icmp"``,
    or ``"icmpv6"`` and the remaining keys reflect only what was decoded
    before the truncation.

    Non-IP ethertypes (ARP and friends) are reported via ``eth.ethertype``
    only — no further decoding is attempted.
    """
    out: dict[str, Any] = {}
    if not packet:
        out["_truncated_at"] = "eth"
        return out

    eth_result = _decode_ethernet(packet, out)
    if eth_result is None:
        return out
    ethertype, offset = eth_result

    if ethertype == _ETHERTYPE_IPV4:
        ip_result = _decode_ipv4(packet, offset, out)
        if ip_result is None:
            return out
        proto, l4_offset = ip_result
    elif ethertype == _ETHERTYPE_IPV6:
        ip_result = _decode_ipv6(packet, offset, out)
        if ip_result is None:
            return out
        proto, l4_offset = ip_result
    else:
        # ARP / LLDP / other — no IP/L4 to decode.
        return out

    if proto == _PROTO_TCP:
        _decode_tcp(packet, l4_offset, out)
    elif proto == _PROTO_UDP:
        _decode_udp(packet, l4_offset, out)
    elif proto == _PROTO_ICMP:
        _decode_icmp(packet, l4_offset, out, v6=False)
    elif proto == _PROTO_ICMPV6:
        _decode_icmp(packet, l4_offset, out, v6=True)
    # else: unknown L4 — leave the dict as-is with ip.* populated.

    return out


__all__ = ["decode_packet_headers"]
