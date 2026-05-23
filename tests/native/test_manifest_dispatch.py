"""Tests for :mod:`etw_analyzer.native.manifest` — the registry of
(provider_guid, event_id) -> (canonical_class, mapper).

The expensive end-to-end pieces (load_trace + extract_events on a real
ETL) live behind the existing ``slow`` mark. These tests cover the
hand-written lookup table and the field-mapping helpers.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Skip the whole module on non-Windows hosts — ``etw_analyzer.native``
# imports ``advapi32`` at import time via ``etw_analyzer.tools.trace_mgmt``
# (which we reference in one of the tests below).
pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Native ETW manifest dispatch requires Windows",
)

MULTI_PROVIDER_ETL = Path(r"C:\temp\etw-feasibility\multi-provider.etl")
need_multi_provider = pytest.mark.skipif(
    not MULTI_PROVIDER_ETL.exists(),
    reason=f"Fixture not present: {MULTI_PROVIDER_ETL}",
)

from etw_analyzer.native.manifest import (
    AFD_GUID,
    HTTP_GUID,
    MANIFEST_PROVIDERS,
    NDIS_PC_GUID,
    QUIC_GUID,
    TCPIP_GUID,
    _hex_to_bytes,
    _parse_ip_port_string,
    _sockaddr_to_ip_port,
    _to_int,
    lookup,
    manifest_event_count,
)


# ---------------------------------------------------------------------------
# Address-helper unit tests
# ---------------------------------------------------------------------------

def test_hex_to_bytes_accepts_0x_prefix():
    assert _hex_to_bytes("0xAABB") == b"\xaa\xbb"


def test_hex_to_bytes_strips_separators():
    assert _hex_to_bytes("AA BB CC") == b"\xaa\xbb\xcc"
    assert _hex_to_bytes("AA-BB-CC") == b"\xaa\xbb\xcc"
    assert _hex_to_bytes("AA:BB:CC") == b"\xaa\xbb\xcc"


def test_hex_to_bytes_rejects_odd_length():
    assert _hex_to_bytes("ABC") == b""


def test_hex_to_bytes_rejects_non_hex():
    assert _hex_to_bytes("hello world") == b""


def test_parse_ip_port_string_ipv4():
    assert _parse_ip_port_string("192.168.1.1:443") == ("192.168.1.1", 443)


def test_parse_ip_port_string_ipv6_bracketed():
    assert _parse_ip_port_string("[2001:db8::1]:80") == ("2001:db8::1", 80)


def test_parse_ip_port_string_just_ip_returns_zero_port():
    assert _parse_ip_port_string("10.0.0.1") == ("10.0.0.1", 0)


def test_parse_ip_port_string_empty():
    assert _parse_ip_port_string("") == ("", 0)
    assert _parse_ip_port_string(None) == ("", 0)


def test_sockaddr_in_ipv4():
    # AF_INET (2, little-endian), port 443 (big-endian = 0x01BB),
    # 10.0.0.1, 8 bytes padding.
    blob = bytes([0x02, 0x00, 0x01, 0xBB, 10, 0, 0, 1]) + b"\x00" * 8
    assert _sockaddr_to_ip_port(blob) == ("10.0.0.1", 443)


def test_sockaddr_in6_ipv6():
    # AF_INET6 (23), port 8080 (0x1F90), flowinfo 0, ::1, scope_id 0.
    addr = b"\x00" * 15 + b"\x01"
    blob = bytes([0x17, 0x00, 0x1F, 0x90]) + b"\x00" * 4 + addr + b"\x00" * 4
    ip, port = _sockaddr_to_ip_port(blob)
    assert port == 8080
    # ::1 compresses to "::1"
    assert ip == "::1"


def test_sockaddr_too_short():
    assert _sockaddr_to_ip_port(b"\x00\x00") == ("", 0)


def test_to_int_handles_hex():
    assert _to_int("0xFF") == 255
    assert _to_int("0XFF") == 255


def test_to_int_handles_decimal():
    assert _to_int("123") == 123


def test_to_int_handles_int_passthrough():
    assert _to_int(42) == 42


def test_to_int_empty_returns_default():
    assert _to_int("") == 0
    assert _to_int("nothing", default=-1) == -1


# ---------------------------------------------------------------------------
# Registry coverage
# ---------------------------------------------------------------------------

def test_registry_has_minimum_coverage():
    """The hand-written dispatch must cover at least N events.

    If the registry shrinks below this bar, callers will silently lose
    coverage and ``get_connection_summary`` will start returning empty
    on traces it used to handle.
    """
    assert manifest_event_count() >= 30


def test_registry_covers_all_five_providers():
    """Every required provider must contribute at least one event id."""
    # Touch a known event id from each provider — if it's missing the
    # whole registry table is suspect.
    assert lookup(TCPIP_GUID, 1033) is not None     # TcpConnectTcbComplete
    assert lookup(TCPIP_GUID, 1332) is not None     # TcpDataTransferSend
    assert lookup(TCPIP_GUID, 1601) is not None     # TcpRx
    assert lookup(TCPIP_GUID, 1187) is not None     # TcpDataTransferRestransmit
    assert lookup(TCPIP_GUID, 1169) is not None     # UdpEndpointSendMessages
    assert lookup(TCPIP_GUID, 1170) is not None     # UdpEndpointReceiveMessages
    assert lookup(AFD_GUID, 1003) is not None       # AfdSend
    assert lookup(AFD_GUID, 1004) is not None       # AfdReceive
    assert lookup(AFD_GUID, 1001) is not None       # AfdClose
    assert lookup(QUIC_GUID, 5) is not None         # ConnectionCreated
    assert lookup(HTTP_GUID, 1) is not None         # RequestReceived
    assert lookup(NDIS_PC_GUID, 1001) is not None   # PacketCapture


def test_registry_misses_return_none():
    assert lookup(TCPIP_GUID, 999999) is None
    assert lookup("not-a-real-guid", 1001) is None


def test_canonical_class_names_are_valid():
    """Every canonical class in the registry must match the names the
    Phase 3-5 tools key off of in ``_DUMPER_EVENT_CLASSES``."""
    from etw_analyzer.tools.trace_mgmt import _DUMPER_EVENT_CLASSES
    valid_classes = set(_DUMPER_EVENT_CLASSES.keys())

    from etw_analyzer.native.manifest import _REGISTRY
    for (guid, eid), (canonical, _mapper) in _REGISTRY.items():
        assert canonical in valid_classes, (
            f"Registry maps ({guid},{eid}) to {canonical!r} but no "
            f"DataFrame attribute is wired up for that class."
        )


def test_manifest_providers_excludes_kernel_guids():
    """The MANIFEST_PROVIDERS set must not overlap kernel-MOF GUIDs."""
    from etw_analyzer.native.mof import kernel_provider_guids
    kernel = kernel_provider_guids()
    overlap = MANIFEST_PROVIDERS & kernel
    assert not overlap, (
        f"MANIFEST_PROVIDERS overlaps kernel GUIDs: {overlap}. "
        f"The TDH path would race the MOF path on these events."
    )


# ---------------------------------------------------------------------------
# Mapper-shape tests — exercise each mapper without TDH being involved.
# ---------------------------------------------------------------------------

def _hdr():
    return {
        "TimeStamp": 1_000_000,
        "ProcessId": 1234,
        "ThreadId": 5678,
        "ProcessorNumber": 4,
        "Opcode": 0,
        "Version": 0,
    }


def test_tcpip_connect_mapper_extracts_ip_port():
    canonical, mapper = lookup(TCPIP_GUID, 1033)
    fields = {
        "LocalAddressLength": 16,
        "LocalAddress": "192.168.1.10:54321",
        "RemoteAddressLength": 16,
        "RemoteAddress": "10.0.0.1:443",
        "Status": "STATUS_SUCCESS",
        "ProcessId": 1234,
        "Tcb": "0xFFFF1234ABCD0000",
    }
    row = mapper(fields, _hdr(), b"", None)
    assert canonical == "TcpIp/Connect"
    assert row["LocalAddr"] == "192.168.1.10"
    assert row["LocalPort"] == 54321
    assert row["RemoteAddr"] == "10.0.0.1"
    assert row["RemotePort"] == 443
    assert row["PID"] == 1234
    assert row["CPU"] == 4


def test_tcpip_send_mapper_extracts_size():
    canonical, mapper = lookup(TCPIP_GUID, 1332)
    fields = {"Tcb": "0xFFFF", "BytesSent": 1460, "SeqNo": 12345}
    row = mapper(fields, _hdr(), b"", None)
    assert canonical == "TcpIp/Send"
    assert row["Size"] == 1460
    assert row["SeqNo"] == 12345


def test_afd_recv_mapper_extracts_handle_and_size():
    canonical, mapper = lookup(AFD_GUID, 1004)
    fields = {"Endpoint": "0xFFFF8300DEADBEEF", "BufferLength": 256, "Status": 0}
    row = mapper(fields, _hdr(), b"", None)
    assert canonical == "AFD/Recv"
    assert row["SocketHandle"] == 0xFFFF8300DEADBEEF
    assert row["Size"] == 256
    assert row["CompletionStatus"] == 0


def test_afd_close_mapper_emits_just_handle():
    canonical, mapper = lookup(AFD_GUID, 1001)
    fields = {"Endpoint": "0xFEFE"}
    row = mapper(fields, _hdr(), b"", None)
    assert canonical == "AFD/Close"
    assert row["SocketHandle"] == 0xFEFE


def test_ndis_packet_capture_returns_none_on_empty_fragment():
    canonical, mapper = lookup(NDIS_PC_GUID, 1001)
    assert canonical == "NdisPacketCapture"
    fields = {"MiniportIfIndex": 5, "Fragment": "", "FragmentSize": 0}
    assert mapper(fields, _hdr(), b"", None) is None


def test_ndis_packet_capture_extracts_packet_bytes():
    canonical, mapper = lookup(NDIS_PC_GUID, 1001)
    fields = {
        "MiniportIfIndex": 7,
        "Fragment": "0xAABBCCDDEEFF",
        "FragmentSize": 6,
    }
    row = mapper(fields, _hdr(), b"", None)
    assert row is not None
    assert row["PacketBytes"] == "aabbccddeeff"
    assert row["Size"] == 6
    assert "IfIndex=7" in row["MiniportName"]
    assert row["Direction"] == "Recv"


# ---------------------------------------------------------------------------
# Integration: real ETL.
# ---------------------------------------------------------------------------

@pytest.mark.slow
@need_multi_provider
def test_native_mode_multi_provider_populates_manifest_dataframes():
    """End-to-end: load multi-provider.etl in native mode, verify each of
    the manifest event-class DataFrames is non-empty and has sensible
    column values. This is the headline Phase N4b acceptance test —
    before this commit those DataFrames were always empty in native
    mode."""
    from etw_analyzer.native.extract import ExtractStats, extract_events

    stats_sink: list[ExtractStats] = []
    results = extract_events(MULTI_PROVIDER_ETL, stats_sink=stats_sink)

    # Counts validated against multi-summary.txt (the xperf -a tracestats
    # reference). Lower bounds chosen well below observed so the test
    # tolerates trace re-captures with slightly different event mixes.
    assert len(results["TcpIp/Recv"]) > 1000
    assert len(results["TcpIp/Send"]) > 1000
    assert len(results["TcpIp/Connect"]) > 100
    assert len(results["TcpIp/Retransmit"]) > 100
    assert len(results["UdpIp/Recv"]) > 100
    assert len(results["UdpIp/Send"]) > 100
    assert len(results["AFD/Recv"]) > 1000
    assert len(results["AFD/Send"]) > 1000
    assert len(results["AFD/Close"]) > 100
    assert len(results["NdisPacketCapture"]) > 100

    # Connect rows must carry valid 5-tuples — this is what the connection
    # summary aggregates over.
    conn = results["TcpIp/Connect"]
    have_addr = conn[conn["LocalAddr"] != ""]
    assert len(have_addr) > 50, (
        f"Expected >50 TcpIp/Connect rows with a non-empty LocalAddr; "
        f"got {len(have_addr)}"
    )
    sample = have_addr.iloc[0]
    # IPv4 form check — at least one dot in LocalAddr.
    assert "." in sample["LocalAddr"] or ":" in sample["LocalAddr"]
    # Ports are 16-bit.
    assert 0 < int(sample["LocalPort"]) < 65536
    assert 0 < int(sample["RemotePort"]) < 65536

    # TDH cache should have grown — we want a non-trivial schema count
    # and zero "lost" events.
    stats = stats_sink[0]
    assert stats.tdh_schemas_cached >= 10
    assert stats.events_lost == 0


@pytest.mark.slow
@need_multi_provider
def test_native_mode_get_connection_summary_returns_real_data():
    """The headline regression: ``get_connection_summary`` against a
    native-mode-loaded multi-provider trace must return >0 connections.
    Before Phase N4b this returned an empty-table message."""
    from etw_analyzer.tools.network_events import get_connection_summary
    from etw_analyzer.tools.trace_mgmt import load_trace
    from etw_analyzer.trace_state import get_trace
    import re

    result = load_trace(str(MULTI_PROVIDER_ETL), mode="native", force=True)
    m = re.search(r"`(trace_[a-f0-9]+)`", result)
    assert m, f"Couldn't find trace_id in load_trace output: {result[:300]}"
    trace_id = m.group(1)
    trace = get_trace(trace_id)
    trace.wait_for_dumper()

    out = get_connection_summary(trace_id, top_n=20)
    # Must mention "Connections observed: N" with N>=1, not the empty
    # placeholder.
    m2 = re.search(r"Connections observed:\s*(\d+)", out)
    assert m2 is not None, f"Output doesn't look like a summary: {out[:500]}"
    n_conn = int(m2.group(1))
    assert n_conn >= 10, f"Expected >=10 connections, got {n_conn}"
