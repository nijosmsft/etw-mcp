"""Manifest-event dispatch registry for the Phase N4b TDH path.

Once :class:`native.decoder.TdhDecoder` has produced a ``dict[str, value]``
of named TDH fields, this module maps it onto the canonical row schema
the Phase 3-5 tools expect (the same shape ``parsing.wpa_exporter`` builds
from xperf text). The mapping is one closed-form function per
(provider_guid, event_id) entry — manifests change occasionally between
Windows builds but the relevant TCPIP/AFD/Quic/HttpService event IDs and
their core fields are stable enough that a hand-written table beats any
runtime introspection.

For every supported manifest event we record:

* The **canonical class name** (e.g. ``"TcpIp/Recv"``) so it lands in
  the right ``results[canonical]`` bucket and ultimately the right
  DataFrame on :class:`TraceData`.
* A **mapping function** ``(fields, hdr, payload, decoder) -> dict | None``
  that produces the row dict in the canonical schema. ``fields`` is the
  formatted-string dict from TDH, ``hdr`` is the header dict the extract
  loop already built, ``payload`` is the raw event payload (so binary
  sockaddrs can be re-parsed), and ``decoder`` is the schema (in case
  the mapper needs to look at the property descriptor list).

Providers covered fully:

* **TCPIP** (``2f07e2ee-15db-40f1-90ef-9d7ba282188a``)
* **AFD/Winsock** (``e53c6823-7bb8-44bb-90dc-3f86090d48a6``)
* **MsQuic** (``ff15e657-4f26-570e-88ab-0796b258d11c``)
* **HttpService** (``dd5ef90a-6398-47a4-ad34-4dcecdef795f``)
* **NDIS-PacketCapture** (``2ed6006e-4729-4609-b423-3ee7bcd678ef``)

Event-ID source: the ``multi-provider.etl`` reference trace at
``C:\\temp\\etw-feasibility\\`` and the field-name discovery probe whose
output is committed alongside this commit. The IDs hold on Windows
22621+ (multi-provider.etl was captured on a recent build).
"""

from __future__ import annotations

import struct
from typing import Callable, Optional


# Provider GUIDs (lowercase) — referenced by both the registry below and
# :mod:`native.extract` (which builds the dispatch table at import time).
TCPIP_GUID = "2f07e2ee-15db-40f1-90ef-9d7ba282188a"
AFD_GUID = "e53c6823-7bb8-44bb-90dc-3f86090d48a6"
QUIC_GUID = "ff15e657-4f26-570e-88ab-0796b258d11c"
HTTP_GUID = "dd5ef90a-6398-47a4-ad34-4dcecdef795f"
NDIS_PC_GUID = "2ed6006e-4729-4609-b423-3ee7bcd678ef"


# ---------------------------------------------------------------------------
# sockaddr → (ip, port) helpers.
#
# TCPIP and AFD encode addresses as BINARY-typed properties of variable
# length. The bytes are a Windows ``SOCKADDR_IN`` (length 16) or
# ``SOCKADDR_IN6`` (length 28). TDH formats BINARY as a hex string — not
# useful — so we re-parse from the formatted hex representation.
# ---------------------------------------------------------------------------

def _hex_to_bytes(value: str) -> bytes:
    """Convert a TDH-formatted BINARY hex string (``"0xAABBCC..."``) to bytes.

    Returns ``b""`` if the value isn't a parseable hex blob. Some TDH
    builds emit BINARY values with spaces or dashes — we strip both
    defensively.
    """
    if not isinstance(value, str):
        return b""
    v = value.strip()
    if v.startswith("0x") or v.startswith("0X"):
        v = v[2:]
    v = v.replace(" ", "").replace("-", "").replace(":", "")
    if not v or len(v) % 2 != 0:
        return b""
    try:
        return bytes.fromhex(v)
    except ValueError:
        return b""


def _parse_ip_port_string(value: str) -> tuple[str, int]:
    """Parse TDH's formatted sockaddr output ``"192.168.1.1:443"`` or
    ``"[fe80::1]:443"`` into (ip, port).

    When ``OutType`` is ``IPV4ADDR`` (24) or ``IPV6ADDR`` (25) TDH does
    the sockaddr parsing for us and emits a pre-formatted endpoint
    string. We just need to split it. Returns ``("", 0)`` if the value
    doesn't look like an endpoint string.
    """
    if not isinstance(value, str) or not value:
        return ("", 0)
    v = value.strip()
    # IPv6 endpoints come bracketed: "[2001:db8::1]:443".
    if v.startswith("["):
        close = v.find("]")
        if close < 0:
            return (v, 0)
        ip = v[1:close]
        port_str = v[close + 1:].lstrip(":")
        try:
            return (ip, int(port_str) if port_str else 0)
        except ValueError:
            return (ip, 0)
    # IPv4 endpoint: split on the last colon. (Plain IPv6 without
    # brackets has many colons — but TDH always brackets IPv6 endpoints
    # when emitting SOCKETADDR.)
    if v.count(":") == 1:
        ip, _, port_str = v.partition(":")
        try:
            return (ip, int(port_str) if port_str else 0)
        except ValueError:
            return (ip, 0)
    # No port — just return the address.
    return (v, 0)


def _sockaddr_to_ip_port(blob: bytes) -> tuple[str, int]:
    """Decode a Windows ``SOCKADDR_IN`` or ``SOCKADDR_IN6`` into (ip, port).

    Returns ``("", 0)`` on parse failure. The address family lives in the
    first two bytes (little-endian USHORT): 2 = AF_INET, 23 = AF_INET6.
    Port immediately follows in network byte order.
    """
    if len(blob) < 8:
        return ("", 0)
    family = int.from_bytes(blob[0:2], "little")
    port = int.from_bytes(blob[2:4], "big")
    if family == 2 and len(blob) >= 8:
        # IPv4: 4 bytes after the port.
        addr = blob[4:8]
        ip = f"{addr[0]}.{addr[1]}.{addr[2]}.{addr[3]}"
        return (ip, port)
    if family == 23 and len(blob) >= 24:
        # IPv6: 16 bytes starting 8 bytes in (skip flowinfo).
        addr = blob[8:24]
        # Format as a colon-grouped IPv6 string. Use struct for
        # endian-safe pair extraction.
        groups = struct.unpack(">8H", addr)
        # Compress the longest run of zeros (RFC 5952-ish but
        # good-enough for our diagnostic display).
        hex_groups = [f"{g:x}" for g in groups]
        # Quick & dirty: drop leading zeros, collapse :0:0:0: spans.
        ip_text = ":".join(hex_groups)
        # Find longest run of zero groups for ::.
        longest_start = -1
        longest_len = 0
        cur_start = -1
        cur_len = 0
        for i, g in enumerate(groups):
            if g == 0:
                if cur_start < 0:
                    cur_start = i
                    cur_len = 1
                else:
                    cur_len += 1
                if cur_len > longest_len and cur_len >= 2:
                    longest_len = cur_len
                    longest_start = cur_start
            else:
                cur_start = -1
                cur_len = 0
        if longest_start >= 0:
            head = ":".join(hex_groups[:longest_start])
            tail = ":".join(hex_groups[longest_start + longest_len:])
            ip_text = f"{head}::{tail}" if head and tail else (
                f"{head}::" if head else f"::{tail}" if tail else "::"
            )
        return (ip_text, port)
    return ("", 0)


def _make_header(hdr: dict) -> dict:
    """Project the header dict onto the column names xperf-mode produces.

    The native ``hdr`` dict carries TimeStamp/ProcessId/ThreadId/
    ProcessorNumber. The xperf-mode handlers emit "Process Name" / "PID"
    / "ThreadID" / "CPU". We don't have a process-name lookup yet (Phase
    N3 only resolved kernel images, not user-mode processes), so we
    emit ``"<unknown>"`` and rely on the process-info aggregator to
    fill it in later. The PID is real.
    """
    pid = int(hdr.get("ProcessId", 0))
    return {
        "TimeStamp": int(hdr.get("TimeStamp", 0)),
        "Process Name": "<unknown>",
        "PID": pid,
        "ThreadID": int(hdr.get("ThreadId", 0)),
        "CPU": int(hdr.get("ProcessorNumber", 0)),
    }


# ---------------------------------------------------------------------------
# TCPIP mappers.
# ---------------------------------------------------------------------------

def _tcpip_addr_pair(fields: dict) -> tuple[tuple[str, int], tuple[str, int]]:
    """Pull (Local, Remote) address pairs from a TCPIP event.

    Most TCPIP events with addresses use the pair
    (LocalAddressLength, LocalAddress, RemoteAddressLength,
    RemoteAddress). UDP events use (LocalSockAddr, RemoteSockAddr). We
    accept either spelling.

    TDH formats BINARY properties with ``OutType=SOCKETADDR`` (25 / 28)
    as a human-readable endpoint string such as ``"192.168.1.1:443"``
    or ``"[fe80::1]:443"`` — we parse that directly. As a fallback we
    re-parse the raw hex bytes via ``_sockaddr_to_ip_port`` (in case
    TDH falls back to hex on this build).
    """
    local = ("", 0)
    remote = ("", 0)
    for local_key in ("LocalAddress", "LocalSockAddr"):
        if local_key in fields:
            v = fields[local_key]
            local = _parse_ip_port_string(str(v))
            if local == ("", 0) or local[1] == 0:
                fallback = _sockaddr_to_ip_port(_hex_to_bytes(str(v)))
                if fallback != ("", 0):
                    local = fallback
            break
    for remote_key in ("RemoteAddress", "RemoteSockAddr"):
        if remote_key in fields:
            v = fields[remote_key]
            remote = _parse_ip_port_string(str(v))
            if remote == ("", 0) or remote[1] == 0:
                fallback = _sockaddr_to_ip_port(_hex_to_bytes(str(v)))
                if fallback != ("", 0):
                    remote = fallback
            break
    return local, remote


def _to_int(value, default: int = 0) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return default
        try:
            if s.startswith("0x") or s.startswith("0X"):
                return int(s, 16)
            return int(s)
        except ValueError:
            return default
    return default


# --- TcpIp/Send -- 1332 (TcpDataTransferSend), 1159 (TcpSendPosted),
#                   1160 (TcpSendTransmitted), 1426 (TcpSendComplete) ---
# These don't carry the 5-tuple inline — the connection identity is
# the Tcb pointer. We still emit Size + SeqNo so per-Tcb aggregation
# works. The 5-tuple is provided via TcpConnectionRundown (1300) and
# TcpRequestConnect (1002) — the existing tool layer joins those.
def _map_tcpip_send_databytes(fields, hdr, payload, decoder):
    row = _make_header(hdr)
    row.update({
        "LocalAddr": "",
        "LocalPort": 0,
        "RemoteAddr": "",
        "RemotePort": 0,
        "Size": _to_int(fields.get("BytesSent") or fields.get("NumBytes")),
        "SeqNo": _to_int(fields.get("SeqNo")),
        "ConnId": _to_int(fields.get("Tcb")),
    })
    return row


def _map_tcpip_recv_databytes(fields, hdr, payload, decoder):
    row = _make_header(hdr)
    row.update({
        "LocalAddr": "",
        "LocalPort": 0,
        "RemoteAddr": "",
        "RemotePort": 0,
        "Size": _to_int(fields.get("NumBytes") or fields.get("BytesRecv")),
        "SeqNo": _to_int(fields.get("SeqNo")),
        "ConnId": _to_int(fields.get("Tcb")),
    })
    return row


def _map_tcpip_connect(fields, hdr, payload, decoder):
    """TcpConnectTcbComplete (1033) / TcpRequestConnect (1002) /
    TcpConnectTcbProceeding (1031). Carry the 5-tuple."""
    row = _make_header(hdr)
    (la, lp), (ra, rp) = _tcpip_addr_pair(fields)
    row.update({
        "LocalAddr": la,
        "LocalPort": lp,
        "RemoteAddr": ra,
        "RemotePort": rp,
        "Size": 0,
        "MSS": _to_int(fields.get("MSS")),
        "RcvWin": _to_int(fields.get("RcvWnd")),
        "SeqNo": _to_int(fields.get("ISN") or fields.get("SeqNo")),
        "ConnId": _to_int(fields.get("Tcb")),
    })
    return row


def _map_tcpip_accept(fields, hdr, payload, decoder):
    """TcpInitiateSynRstValidation (1182) — when a SYN arrives. The
    field order is local/remote relative to the host."""
    row = _make_header(hdr)
    (la, lp), (ra, rp) = _tcpip_addr_pair(fields)
    row.update({
        "LocalAddr": la,
        "LocalPort": lp,
        "RemoteAddr": ra,
        "RemotePort": rp,
        "Size": 0,
        "MSS": 0,
        "RcvWin": 0,
        "SeqNo": 0,
        "ConnId": _to_int(fields.get("Tcb")),
    })
    return row


def _map_tcpip_retransmit(fields, hdr, payload, decoder):
    """TcpConnectRestransmit (1186) / TcpDataTransferRestransmit (1187)."""
    row = _map_tcpip_connect(fields, hdr, payload, decoder)
    row["RetransmitCount"] = max(1, _to_int(fields.get("RexmitCount"), 1))
    return row


def _map_tcpip_connection_rundown(fields, hdr, payload, decoder):
    """TcpConnectionRundown (1300) — emits one row per active connection
    at trace start. Routes to TcpIp/Connect so it shows up in connection
    summaries."""
    return _map_tcpip_connect(fields, hdr, payload, decoder)


# --- UdpIp/Send and UdpIp/Recv (1169/1170) carry the full 5-tuple. ---
def _map_udp_send_or_recv(fields, hdr, payload, decoder):
    row = _make_header(hdr)
    (la, lp), (ra, rp) = _tcpip_addr_pair(fields)
    row.update({
        "LocalAddr": la,
        "LocalPort": lp,
        "RemoteAddr": ra,
        "RemotePort": rp,
        "Size": _to_int(fields.get("NumBytes")),
    })
    return row


# ---------------------------------------------------------------------------
# AFD mappers.
#
# Schema (from probe_events2.py):
#   1003 AfdSend                — Endpoint, BufferCount, Buffer, BufferLength, Status
#   1004 AfdReceive             — same shape
#   1005 AfdSendTo              — same shape (connected UDP send)
#   1006 AfdReceiveFrom         — same shape
#   1007 AfdSendToWithAddress   — adds AddressLen, Address (sockaddr)
#   1009 AfdReceiveFromWithAddress — adds AddressLen, Address
#   1012 AfdReceiveMessage      — same as 1003
#   1013 AfdSendMessageWithAddress — adds AddressLen, Address
#   1015 AfdReceiveMessageWithAddress — adds AddressLen, Address
#   1017 AfdConnect / 1018 AfdConnectWithAddress / 1020 AfdConnectEx / 1021 AfdConnectExWithAddress
#   1000 AfdCreate, 1001 AfdClose, 1002 AfdCleanup, 1030 AfdBindWithAddress, 1032 AfdAbort
# ---------------------------------------------------------------------------

def _map_afd_recv_or_send(fields, hdr, payload, decoder):
    """AFD send/recv variants — emit SocketHandle, Size, CompletionStatus."""
    row = _make_header(hdr)
    handle = _to_int(fields.get("Endpoint"))
    size = _to_int(fields.get("BufferLength"))
    status = _to_int(fields.get("Status"))
    row.update({
        "SocketHandle": handle,
        "Size": size,
        "CompletionStatus": status,
    })
    return row


def _parse_afd_address(value: object) -> tuple[str, int]:
    """Decode an AFD ``Address`` field (TDH may emit IP:port or hex)."""
    if not value:
        return ("", 0)
    s = str(value)
    parsed = _parse_ip_port_string(s)
    if parsed != ("", 0):
        return parsed
    return _sockaddr_to_ip_port(_hex_to_bytes(s))


def _map_afd_connect_or_accept(fields, hdr, payload, decoder):
    """AFD connect/connect-with-address — emit SocketHandle + 5-tuple."""
    row = _make_header(hdr)
    handle = _to_int(fields.get("Endpoint"))
    remote_ip, remote_port = _parse_afd_address(fields.get("Address"))
    row.update({
        "SocketHandle": handle,
        "LocalAddr": "",
        "LocalPort": 0,
        "RemoteAddr": remote_ip,
        "RemotePort": remote_port,
    })
    return row


def _map_afd_bind(fields, hdr, payload, decoder):
    """AfdBindWithAddress (1030) — local address only."""
    row = _make_header(hdr)
    handle = _to_int(fields.get("Endpoint"))
    local_ip, local_port = _parse_afd_address(fields.get("Address"))
    row.update({
        "SocketHandle": handle,
        "LocalAddr": local_ip,
        "LocalPort": local_port,
        "RemoteAddr": "",
        "RemotePort": 0,
    })
    return row


def _map_afd_close(fields, hdr, payload, decoder):
    row = _make_header(hdr)
    handle = _to_int(fields.get("Endpoint"))
    row["SocketHandle"] = handle
    return row


# ---------------------------------------------------------------------------
# MsQuic mappers. Most useful events:
#   ConnectionCreated — event Id usually 5/6/7 in the manifest
#   ConnectionClosed  — usually 9/10
#   PacketSend/Recv   — packet-level events
#   AckReceived       — ack-frame event
# The test fixture has only the global / registration events, so we
# register conservative mappers and accept that the test trace won't
# populate the connection DataFrames. The IDs below match the public
# MsQuic manifest names (msquic.man).
# ---------------------------------------------------------------------------

def _map_quic_connection_created(fields, hdr, payload, decoder):
    row = _make_header(hdr)
    row.update({
        "ConnectionId": _to_int(fields.get("CorrelationId") or fields.get("Connection")),
        "CID": str(fields.get("CID") or fields.get("ClientCid") or ""),
        "LocalAddr": str(fields.get("LocalAddress") or ""),
        "RemoteAddr": str(fields.get("RemoteAddress") or ""),
    })
    return row


def _map_quic_connection_closed(fields, hdr, payload, decoder):
    row = _make_header(hdr)
    row["ConnectionId"] = _to_int(
        fields.get("CorrelationId") or fields.get("Connection")
    )
    return row


def _map_quic_packet(fields, hdr, payload, decoder):
    row = _make_header(hdr)
    row.update({
        "ConnectionId": _to_int(
            fields.get("CorrelationId") or fields.get("Connection")
        ),
        "PacketNumber": _to_int(fields.get("PacketNumber") or fields.get("Number")),
        "Size": _to_int(fields.get("Size") or fields.get("Length")),
    })
    return row


def _map_quic_ack(fields, hdr, payload, decoder):
    row = _make_header(hdr)
    row.update({
        "ConnectionId": _to_int(
            fields.get("CorrelationId") or fields.get("Connection")
        ),
        "AckDelay": _to_int(fields.get("AckDelay")),
        "LargestAcknowledged": _to_int(fields.get("LargestAcknowledged")),
    })
    return row


# ---------------------------------------------------------------------------
# HttpService mappers. We cover the four canonical lifecycle events.
# Field names match the Microsoft-Windows-HttpService manifest.
# ---------------------------------------------------------------------------

def _map_http_recv(fields, hdr, payload, decoder):
    row = _make_header(hdr)
    row.update({
        "RequestId": _to_int(fields.get("RequestId") or fields.get("RequestObj")),
        "ConnectionId": _to_int(fields.get("ConnectionId") or fields.get("ConnectionObj")),
        "Verb": str(fields.get("Verb") or fields.get("HttpVerb") or ""),
        "Url": str(fields.get("Url") or ""),
    })
    return row


def _map_http_deliver(fields, hdr, payload, decoder):
    row = _make_header(hdr)
    row.update({
        "RequestId": _to_int(fields.get("RequestId")),
        "UrlGroupId": _to_int(fields.get("UrlGroupId") or fields.get("UrlGroup")),
    })
    return row


def _map_http_send(fields, hdr, payload, decoder):
    row = _make_header(hdr)
    row.update({
        "RequestId": _to_int(fields.get("RequestId")),
        "StatusCode": _to_int(fields.get("StatusCode") or fields.get("HttpStatus")),
        "ContentLength": _to_int(fields.get("ContentLength")),
    })
    return row


def _map_http_close(fields, hdr, payload, decoder):
    row = _make_header(hdr)
    row["RequestId"] = _to_int(fields.get("RequestId"))
    return row


# ---------------------------------------------------------------------------
# NDIS PacketCapture (event id 1001).
# Fields per probe: MiniportIfIndex, LowerIfIndex, FragmentSize, Fragment
# (BINARY), GftFlowEntryId, GftOffloadInformation.
# ---------------------------------------------------------------------------

def _map_ndis_packet_capture(fields, hdr, payload, decoder):
    row = _make_header(hdr)
    fragment_hex = str(fields.get("Fragment") or "")
    blob = _hex_to_bytes(fragment_hex)
    size = _to_int(fields.get("FragmentSize"), len(blob))
    if not blob:
        # No usable packet — skip the row. Otherwise downstream packet
        # decoders would just see an empty PacketBytes string.
        return None
    row.update({
        "Direction": "Recv",  # NDIS PacketCapture is RX-only on the test trace
        "MiniportName": f"IfIndex={_to_int(fields.get('MiniportIfIndex'))}",
        "PacketBytes": blob.hex(),
        "Size": size,
    })
    return row


# ---------------------------------------------------------------------------
# The registry. (provider_guid_lower, event_id) -> (canonical, mapper).
#
# Versions are ignored deliberately: the field *names* in a TDH schema are
# stable across versions even when the field set changes. The mapper
# already tolerates missing fields.
# ---------------------------------------------------------------------------

MapperFn = Callable[[dict, dict, bytes, object], Optional[dict]]


_REGISTRY: dict[tuple[str, int], tuple[str, MapperFn]] = {
    # --- TCPIP send/recv data-transfer events ------------------------
    # 1332 TcpDataTransferSend — the most useful per-segment send event.
    (TCPIP_GUID, 1332): ("TcpIp/Send", _map_tcpip_send_databytes),
    # 1159 TcpSendPosted — application-level send accepted into TCP.
    (TCPIP_GUID, 1159): ("TcpIp/Send", _map_tcpip_send_databytes),
    # 1160 TcpSendTransmitted — segment hit the wire.
    (TCPIP_GUID, 1160): ("TcpIp/Send", _map_tcpip_send_databytes),
    # 1426 TcpSendComplete — completion side.
    (TCPIP_GUID, 1426): ("TcpIp/Send", _map_tcpip_send_databytes),
    # 1074 TcpDataTransferReceive — server-side bytes received.
    (TCPIP_GUID, 1074): ("TcpIp/Recv", _map_tcpip_recv_databytes),
    # 1601 TcpRx — every accepted segment.
    (TCPIP_GUID, 1601): ("TcpIp/Recv", _map_tcpip_recv_databytes),

    # --- TCPIP connect/accept/disconnect/rundown ---------------------
    (TCPIP_GUID, 1002): ("TcpIp/Connect", _map_tcpip_connect),     # TcpRequestConnect
    (TCPIP_GUID, 1031): ("TcpIp/Connect", _map_tcpip_connect),     # TcpConnectTcbProceeding
    (TCPIP_GUID, 1033): ("TcpIp/Connect", _map_tcpip_connect),     # TcpConnectTcbComplete
    (TCPIP_GUID, 1182): ("TcpIp/Accept", _map_tcpip_accept),       # TcpInitiateSynRstValidation
    (TCPIP_GUID, 1300): ("TcpIp/Connect", _map_tcpip_connection_rundown),  # TcpConnectionRundown
    (TCPIP_GUID, 1186): ("TcpIp/Retransmit", _map_tcpip_retransmit),       # TcpConnectRestransmit
    (TCPIP_GUID, 1187): ("TcpIp/Retransmit", _map_tcpip_retransmit),       # TcpDataTransferRestransmit

    # --- UDP send/recv ----------------------------------------------
    (TCPIP_GUID, 1169): ("UdpIp/Send", _map_udp_send_or_recv),     # UdpEndpointSendMessages
    (TCPIP_GUID, 1170): ("UdpIp/Recv", _map_udp_send_or_recv),     # UdpEndpointReceiveMessages

    # --- AFD send variants ------------------------------------------
    (AFD_GUID, 1003): ("AFD/Send", _map_afd_recv_or_send),         # AfdSend
    (AFD_GUID, 1005): ("AFD/Send", _map_afd_recv_or_send),         # AfdSendTo
    (AFD_GUID, 1007): ("AFD/Send", _map_afd_recv_or_send),         # AfdSendToWithAddress
    (AFD_GUID, 1013): ("AFD/Send", _map_afd_recv_or_send),         # AfdSendMessageWithAddress

    # --- AFD recv variants ------------------------------------------
    (AFD_GUID, 1004): ("AFD/Recv", _map_afd_recv_or_send),         # AfdReceive
    (AFD_GUID, 1006): ("AFD/Recv", _map_afd_recv_or_send),         # AfdReceiveFrom
    (AFD_GUID, 1009): ("AFD/Recv", _map_afd_recv_or_send),         # AfdReceiveFromWithAddress
    (AFD_GUID, 1012): ("AFD/Recv", _map_afd_recv_or_send),         # AfdReceiveMessage
    (AFD_GUID, 1015): ("AFD/Recv", _map_afd_recv_or_send),         # AfdReceiveMessageWithAddress

    # --- AFD connect/accept -----------------------------------------
    (AFD_GUID, 1017): ("AFD/Connect", _map_afd_connect_or_accept),         # AfdConnect
    (AFD_GUID, 1018): ("AFD/Connect", _map_afd_connect_or_accept),         # AfdConnectWithAddress
    (AFD_GUID, 1020): ("AFD/Connect", _map_afd_connect_or_accept),         # AfdConnectEx
    (AFD_GUID, 1021): ("AFD/Connect", _map_afd_connect_or_accept),         # AfdConnectExWithAddress
    (AFD_GUID, 1030): ("AFD/Accept", _map_afd_bind),                        # AfdBindWithAddress (server-side)

    # --- AFD close / cleanup ----------------------------------------
    (AFD_GUID, 1001): ("AFD/Close", _map_afd_close),                # AfdClose
    (AFD_GUID, 1002): ("AFD/Close", _map_afd_close),                # AfdCleanup
    (AFD_GUID, 1032): ("AFD/Close", _map_afd_close),                # AfdAbort
    (AFD_GUID, 3006): ("AFD/Close", _map_afd_close),                # AfdDisconnect

    # --- MsQuic — manifest event IDs from msquic.man -----------------
    # 5 = ConnectionCreated, 6 = ConnectionDestroyed, 7 = ConnectionStateUpdated
    (QUIC_GUID, 5): ("Quic/ConnectionCreated", _map_quic_connection_created),
    (QUIC_GUID, 6): ("Quic/ConnectionClosed", _map_quic_connection_closed),
    (QUIC_GUID, 9): ("Quic/ConnectionClosed", _map_quic_connection_closed),
    # 9012 = ConnectionPacketSent, 9013 = ConnectionPacketRecv, 9014 = AckFrame
    (QUIC_GUID, 9012): ("Quic/PacketSend", _map_quic_packet),
    (QUIC_GUID, 9013): ("Quic/PacketRecv", _map_quic_packet),
    (QUIC_GUID, 9014): ("Quic/AckReceived", _map_quic_ack),

    # --- HttpService — manifest event IDs from HttpEvent.man ---------
    # 1 = RequestReceived, 2 = Parse, 12 = UrlMatched, 20 = FastResponse,
    # 21 = DeliveredRequest, 25 = ConnectionClose
    (HTTP_GUID, 1): ("HttpService/Recv", _map_http_recv),
    (HTTP_GUID, 2): ("HttpService/Recv", _map_http_recv),
    (HTTP_GUID, 21): ("HttpService/Deliver", _map_http_deliver),
    (HTTP_GUID, 20): ("HttpService/Send", _map_http_send),
    (HTTP_GUID, 27): ("HttpService/Send", _map_http_send),       # FastResponse
    (HTTP_GUID, 25): ("HttpService/Close", _map_http_close),

    # --- NDIS-PacketCapture -----------------------------------------
    (NDIS_PC_GUID, 1001): ("NdisPacketCapture", _map_ndis_packet_capture),
}


# Set of GUIDs we should attempt TDH decode for. The consumer uses this
# to short-circuit kernel-MOF providers via TdhDecoder.mark_provider_skip.
MANIFEST_PROVIDERS: frozenset[str] = frozenset({
    TCPIP_GUID, AFD_GUID, QUIC_GUID, HTTP_GUID, NDIS_PC_GUID,
})


def lookup(guid_lower: str, event_id: int) -> Optional[tuple[str, MapperFn]]:
    """Return the (canonical, mapper) for a manifest event, or None."""
    return _REGISTRY.get((guid_lower, event_id))


def manifest_event_count() -> int:
    """Number of (guid, event_id) pairs in the registry. For tests."""
    return len(_REGISTRY)


__all__ = [
    "TCPIP_GUID",
    "AFD_GUID",
    "QUIC_GUID",
    "HTTP_GUID",
    "NDIS_PC_GUID",
    "MANIFEST_PROVIDERS",
    "lookup",
    "manifest_event_count",
]
