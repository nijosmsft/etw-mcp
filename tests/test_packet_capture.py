"""Tests for Phase 4 packet-capture parsing + tools.

Synthetic-only — no xperf, no .etl files. Packet bytes are built with
``struct`` (same approach as ``test_packet_decode.py``) and pasted into
fixture rows or fixture dumper text.
"""

from __future__ import annotations

import socket
import struct
from pathlib import Path
from unittest.mock import patch

import pandas as pd
import pytest

from etw_analyzer.parsing.wpa_exporter import (
    EVENT_HANDLERS,
    _handle_ndis_packet_capture,
    parse_dumper_events,
)
from etw_analyzer.tools.packet_capture import (
    decode_packet,
    get_packet_capture_summary,
    get_packet_timeline,
    get_send_recv_latency,
)
from etw_analyzer.trace_state import (
    TraceData,
    clear_traces,
    register_trace,
)


@pytest.fixture(autouse=True)
def _clean_registry():
    clear_traces()
    yield
    clear_traces()


def _patch_xperf_lines(text: str):
    def _fake_lines(*_args, **_kwargs):
        for line in text.splitlines():
            yield line
    return patch(
        "etw_analyzer.parsing.wpa_exporter._run_xperf_lines",
        side_effect=_fake_lines,
    )


# ---------------------------------------------------------------------------
# Packet builders (small, reusable)
# ---------------------------------------------------------------------------


def _build_ipv4_udp(
    *,
    src_ip: str, dst_ip: str,
    src_port: int, dst_port: int,
    ip_id: int = 0,
    payload: bytes = b"",
) -> bytes:
    """Build an Ethernet + IPv4 + UDP packet, returning the raw bytes."""
    eth = bytes.fromhex("aabbccddeeff112233445566") + struct.pack("!H", 0x0800)
    total_len = 20 + 8 + len(payload)
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        (4 << 4) | 5, 0, total_len, ip_id, 0, 64, 17, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )
    udp = struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0)
    return eth + ipv4 + udp + payload


def _build_ipv4_tcp(
    *,
    src_ip: str, dst_ip: str,
    src_port: int, dst_port: int,
    seq: int = 0, ack: int = 0, flags: int = 0x02,  # SYN
    payload: bytes = b"",
) -> bytes:
    """Build an Ethernet + IPv4 + TCP packet."""
    eth = bytes.fromhex("aabbccddeeff112233445566") + struct.pack("!H", 0x0800)
    total_len = 20 + 20 + len(payload)
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        (4 << 4) | 5, 0, total_len, 0xabcd, 0, 64, 6, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )
    tcp = struct.pack(
        "!HHIIHHHH",
        src_port, dst_port, seq, ack, (5 << 12) | (flags & 0x1ff),
        8192, 0, 0,
    )
    return eth + ipv4 + tcp + payload


# ---------------------------------------------------------------------------
# Parser tests
# ---------------------------------------------------------------------------


_PACKET_A_HEX = _build_ipv4_udp(
    src_ip="10.0.0.1", dst_ip="10.0.0.2",
    src_port=5000, dst_port=6000,
    ip_id=1,
).hex()

_PACKET_B_HEX = _build_ipv4_udp(
    src_ip="10.0.0.2", dst_ip="10.0.0.1",
    src_port=6000, dst_port=5000,
    ip_id=2,
).hex()


# Synthetic dumper text covering NDIS PacketCapture Recv + Send + alias forms.
_FIXTURE_DUMPER = f"""\
NdisPacketCapture/Recv, TimeStamp, Process Name ( PID), ThreadID, CPU, MiniportName, Size, PacketBytes
    NdisPacketCapture/Recv, 1000, <unknown> (0), 0, 4, mlx5.sys, {len(_PACKET_A_HEX) // 2}, {_PACKET_A_HEX}
    NdisPacketCapture/Send, 1100, <unknown> (0), 0, 4, mlx5.sys, {len(_PACKET_B_HEX) // 2}, {_PACKET_B_HEX}
    PacketCapture/Recv, 1200, <unknown> (0), 0, 4, mlx5.sys, {len(_PACKET_A_HEX) // 2}, {_PACKET_A_HEX}
"""


class TestParseDumperEventsPhase4:
    def test_event_handler_registered(self):
        assert "NdisPacketCapture" in EVENT_HANDLERS

    def test_parses_recv_and_send(self, tmp_path):
        with _patch_xperf_lines(_FIXTURE_DUMPER):
            results = parse_dumper_events(
                tmp_path / "fake.etl",
                event_classes={"NdisPacketCapture"},
            )
        df = results["NdisPacketCapture"]
        # 3 fixture lines: Recv, Send, alias-Recv.
        assert len(df) == 3
        directions = df["Direction"].value_counts().to_dict()
        assert directions.get("Recv") == 2
        assert directions.get("Send") == 1

    def test_schema(self, tmp_path):
        with _patch_xperf_lines(_FIXTURE_DUMPER):
            results = parse_dumper_events(
                tmp_path / "fake.etl",
                event_classes={"NdisPacketCapture"},
            )
        df = results["NdisPacketCapture"]
        required = {
            "TimeStamp", "Direction", "MiniportName", "PacketBytes", "Size",
        }
        assert required <= set(df.columns)
        row = df.iloc[0]
        assert row["MiniportName"] == "mlx5.sys"
        # PacketBytes is normalized lowercase hex.
        assert row["PacketBytes"] == _PACKET_A_HEX
        assert row["Size"] == len(_PACKET_A_HEX) // 2


class TestPacketCaptureHandlerDirect:
    def test_basic_recv(self):
        parts = [
            "NdisPacketCapture/Recv", "1000", "<unknown> (0)", "0", "4",
            "mlx5.sys", str(len(_PACKET_A_HEX) // 2), _PACKET_A_HEX,
        ]
        row = _handle_ndis_packet_capture(parts)
        assert row is not None
        assert row["Direction"] == "Recv"
        assert row["MiniportName"] == "mlx5.sys"
        assert row["PacketBytes"] == _PACKET_A_HEX

    def test_quoted_hex_blob(self):
        parts = [
            "NdisPacketCapture/Send", "1000", "<unknown> (0)", "0", "4",
            "mlx5.sys", str(len(_PACKET_B_HEX) // 2), f'"{_PACKET_B_HEX}"',
        ]
        row = _handle_ndis_packet_capture(parts)
        assert row is not None
        assert row["Direction"] == "Send"
        assert row["PacketBytes"] == _PACKET_B_HEX

    def test_returns_none_when_no_hex(self):
        parts = [
            "NdisPacketCapture/Recv", "1000", "<unknown> (0)", "0", "4",
            "mlx5.sys", "100", "not-hex-data",
        ]
        row = _handle_ndis_packet_capture(parts)
        assert row is None


# ---------------------------------------------------------------------------
# Tool fixtures
# ---------------------------------------------------------------------------


def _packet_capture_df(rows: list[dict]) -> pd.DataFrame:
    df = pd.DataFrame(rows)
    for col in (
        "TimeStamp", "Direction", "MiniportName", "PacketBytes", "Size",
        "Process Name", "PID", "ThreadID", "CPU",
    ):
        if col not in df.columns:
            df[col] = "" if col in ("Direction", "MiniportName", "PacketBytes", "Process Name") else 0
    return df


def _register_synthetic(trace_id: str, df: pd.DataFrame | None) -> TraceData:
    trace = TraceData(
        trace_id=trace_id,
        etl_path=Path(f"C:\\fake\\{trace_id}.etl"),
        export_dir=Path(f"C:\\fake\\.etw-export-{trace_id}"),
        packet_capture_df=df,
    )
    trace._dumper_ready.set()
    register_trace(trace)
    return trace


# ---------------------------------------------------------------------------
# Tool tests: get_packet_capture_summary
# ---------------------------------------------------------------------------


class TestPacketCaptureSummary:
    def test_groups_by_five_tuple(self):
        df = _packet_capture_df([
            {"TimeStamp": 1, "Direction": "Recv", "MiniportName": "mlx5.sys",
             "PacketBytes": _PACKET_A_HEX, "Size": len(_PACKET_A_HEX) // 2,
             "Process Name": "echo_server.exe", "PID": 100},
            {"TimeStamp": 2, "Direction": "Send", "MiniportName": "mlx5.sys",
             "PacketBytes": _PACKET_B_HEX, "Size": len(_PACKET_B_HEX) // 2,
             "Process Name": "echo_server.exe", "PID": 100},
            {"TimeStamp": 3, "Direction": "Recv", "MiniportName": "mlx5.sys",
             "PacketBytes": _PACKET_A_HEX, "Size": len(_PACKET_A_HEX) // 2,
             "Process Name": "echo_server.exe", "PID": 100},
        ])
        _register_synthetic("pcs1", df)
        out = get_packet_capture_summary("pcs1")
        assert "Packet Capture Summary" in out
        # Two distinct 5-tuples (A→B and B→A).
        assert "10.0.0.1:5000 -> 10.0.0.2:6000/udp" in out
        assert "10.0.0.2:6000 -> 10.0.0.1:5000/udp" in out

    def test_no_data(self):
        _register_synthetic("pcs2", None)
        out = get_packet_capture_summary("pcs2")
        assert "No packet-capture data" in out

    def test_empty_df(self):
        _register_synthetic("pcs3", pd.DataFrame())
        out = get_packet_capture_summary("pcs3")
        assert "No packet-capture data" in out

    def test_process_filter(self):
        df = _packet_capture_df([
            {"TimeStamp": 1, "Direction": "Recv", "MiniportName": "mlx5.sys",
             "PacketBytes": _PACKET_A_HEX, "Size": 42,
             "Process Name": "wanted.exe", "PID": 100},
            {"TimeStamp": 2, "Direction": "Recv", "MiniportName": "mlx5.sys",
             "PacketBytes": _PACKET_B_HEX, "Size": 42,
             "Process Name": "skipped.exe", "PID": 200},
        ])
        _register_synthetic("pcs4", df)
        out = get_packet_capture_summary("pcs4", process_filter="wanted")
        assert "10.0.0.1:5000 -> 10.0.0.2:6000/udp" in out
        assert "10.0.0.2:6000 -> 10.0.0.1:5000/udp" not in out


# ---------------------------------------------------------------------------
# Tool tests: get_packet_timeline
# ---------------------------------------------------------------------------


class TestPacketTimeline:
    def test_filters_to_matching_tuple_both_directions(self):
        df = _packet_capture_df([
            {"TimeStamp": 1000, "Direction": "Send",
             "PacketBytes": _PACKET_A_HEX, "Size": 42},
            {"TimeStamp": 1100, "Direction": "Recv",
             "PacketBytes": _PACKET_B_HEX, "Size": 42},
            # Unrelated packet — different 5-tuple.
            {"TimeStamp": 1200, "Direction": "Recv",
             "PacketBytes": _build_ipv4_udp(
                src_ip="10.0.0.5", dst_ip="10.0.0.6",
                src_port=7000, dst_port=8000,
             ).hex(), "Size": 42},
        ])
        _register_synthetic("pt1", df)
        out = get_packet_timeline("pt1", "10.0.0.1:5000 -> 10.0.0.2:6000/udp")
        assert "Packet Timeline" in out
        assert "Matched packets: 2" in out
        assert "1,000" in out
        assert "1,100" in out
        # The unrelated 7000/8000 packet should not appear.
        assert "1,200" not in out

    def test_no_data(self):
        _register_synthetic("pt2", None)
        out = get_packet_timeline("pt2", "10.0.0.1:1 -> 10.0.0.2:2/udp")
        assert "No packet-capture data" in out

    def test_unparseable_tuple(self):
        _register_synthetic("pt3", _packet_capture_df([
            {"TimeStamp": 1, "Direction": "Recv",
             "PacketBytes": _PACKET_A_HEX, "Size": 42},
        ]))
        out = get_packet_timeline("pt3", "")
        assert "Could not parse 5-tuple" in out

    def test_no_match(self):
        _register_synthetic("pt4", _packet_capture_df([
            {"TimeStamp": 1, "Direction": "Recv",
             "PacketBytes": _PACKET_A_HEX, "Size": 42},
        ]))
        out = get_packet_timeline("pt4", "1.2.3.4:5 -> 6.7.8.9:10/udp")
        assert "No packets match" in out


# ---------------------------------------------------------------------------
# Tool tests: get_send_recv_latency
# ---------------------------------------------------------------------------


class TestSendRecvLatency:
    def test_matches_udp_by_ipid_and_reports_latency(self):
        # Three send/recv pairs with known latencies of 100, 200, 300 us.
        # The recv mirrors the send tuple but uses the SAME IPID so the
        # matching key (src/dst/sport/dport/ipid) hits.
        rows = []
        latencies = [100, 200, 300]
        ts = 1_000_000
        for i, latency in enumerate(latencies):
            send_pkt = _build_ipv4_udp(
                src_ip="10.0.0.1", dst_ip="10.0.0.2",
                src_port=5000, dst_port=6000,
                ip_id=100 + i,
            )
            recv_pkt = send_pkt  # same key; loopback-style.
            rows.append({
                "TimeStamp": ts, "Direction": "Send",
                "PacketBytes": send_pkt.hex(), "Size": len(send_pkt),
            })
            rows.append({
                "TimeStamp": ts + latency, "Direction": "Recv",
                "PacketBytes": recv_pkt.hex(), "Size": len(recv_pkt),
            })
            ts += 10_000_000  # space pairs out so windows don't overlap
        df = _packet_capture_df(rows)
        _register_synthetic("srl1", df)
        out = get_send_recv_latency("srl1")
        assert "Send" in out and "Recv" in out
        # p50 of [100, 200, 300] = 200.0 → table cell rendered as "200".
        assert "| 200 |" in out
        # Min latency = 100, max = 300. Format_table renders ints with commas
        # — but 100/300 are 3 digits so no comma.
        assert "100" in out and "300" in out

    def test_matches_tcp_by_seqno(self):
        # TCP path uses the seq number, not the IPID.
        rows = []
        seqnos = [1000, 2000, 3000]
        latencies = [50, 75, 100]
        ts = 1_000_000
        for seq, latency in zip(seqnos, latencies):
            send_pkt = _build_ipv4_tcp(
                src_ip="10.0.0.1", dst_ip="10.0.0.2",
                src_port=5000, dst_port=80, seq=seq, flags=0x18,
            )
            recv_pkt = send_pkt
            rows.append({
                "TimeStamp": ts, "Direction": "Send",
                "PacketBytes": send_pkt.hex(), "Size": len(send_pkt),
            })
            rows.append({
                "TimeStamp": ts + latency, "Direction": "Recv",
                "PacketBytes": recv_pkt.hex(), "Size": len(recv_pkt),
            })
            ts += 10_000_000
        df = _packet_capture_df(rows)
        _register_synthetic("srl2", df)
        out = get_send_recv_latency("srl2")
        # p50 of [50, 75, 100] = 75.0 → "75".
        assert "| 75 |" in out

    def test_no_data(self):
        _register_synthetic("srl3", None)
        out = get_send_recv_latency("srl3")
        assert "No packet-capture data" in out

    def test_send_only_returns_friendly_msg(self):
        # All Send, no Recv → no pairs to match.
        send_pkt = _build_ipv4_udp(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=5000, dst_port=6000, ip_id=1,
        )
        rows = [
            {"TimeStamp": 1000, "Direction": "Send",
             "PacketBytes": send_pkt.hex(), "Size": len(send_pkt)},
        ]
        _register_synthetic("srl4", _packet_capture_df(rows))
        out = get_send_recv_latency("srl4")
        assert "No matched Send/Recv pairs" in out


# ---------------------------------------------------------------------------
# Tool tests: decode_packet
# ---------------------------------------------------------------------------


class TestDecodePacket:
    def test_closest_packet_decoded(self):
        df = _packet_capture_df([
            {"TimeStamp": 1000, "Direction": "Recv",
             "MiniportName": "mlx5.sys", "PacketBytes": _PACKET_A_HEX,
             "Size": len(_PACKET_A_HEX) // 2},
            {"TimeStamp": 5000, "Direction": "Send",
             "MiniportName": "mlx5.sys", "PacketBytes": _PACKET_B_HEX,
             "Size": len(_PACKET_B_HEX) // 2},
        ])
        _register_synthetic("dp1", df)
        out = decode_packet("dp1", timestamp_us=1100)
        # Closest to 1100 is ts=1000.
        assert "1000 us" in out
        assert "Ethernet" in out
        assert "IPv4" in out
        assert "10.0.0.1" in out

    def test_no_data(self):
        _register_synthetic("dp2", None)
        out = decode_packet("dp2", timestamp_us=100)
        assert "No packet-capture data" in out


# ---------------------------------------------------------------------------
# Plumbing
# ---------------------------------------------------------------------------


def test_phase4_class_wired_into_dumper_map():
    from etw_analyzer.tools.trace_mgmt import (
        _DUMPER_EVENT_CLASSES,
        _PARQUET_EXCLUDED,
    )
    assert "NdisPacketCapture" in _DUMPER_EVENT_CLASSES
    _, stem = _DUMPER_EVENT_CLASSES["NdisPacketCapture"]
    assert stem == "packet_capture"
    assert stem in _PARQUET_EXCLUDED
