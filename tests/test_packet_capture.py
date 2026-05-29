"""Tests for Phase 4 packet-capture parsing + tools.

Synthetic-only — no xperf, no .etl files. Packet bytes are built with
``struct`` (same approach as ``test_packet_decode.py``) and pasted into
fixture rows or fixture dumper text.
"""

from __future__ import annotations

import os
import socket
import struct
import subprocess
from pathlib import Path
from unittest.mock import patch

import pandas as pd
import pytest

from etw_analyzer.native.event_store import EventStoreTimebase, NativeEventStoreWriter
from etw_analyzer.parsing.wpa_exporter import (
    EVENT_HANDLERS,
    _handle_ndis_packet_capture,
    parse_dumper_events,
)
from etw_analyzer.tools.packet_capture import (
    _ensure_pktmon_text,
    _write_cache_metadata,
    decode_packet,
    get_packet_capture_summary,
    get_packet_timeline,
    get_pktmon_layer_latency,
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


def _packet_store_row(
    sequence: int,
    qpc: int,
    direction: str,
    packet_hex: str,
    *,
    process: str = "echo_server.exe",
    pid: int = 100,
) -> dict:
    return {
        "EventSequence": sequence,
        "TimeStampQpc": qpc,
        "CPU": 4,
        "Process Name": process,
        "PID": pid,
        "ThreadID": 10,
        "Direction": direction,
        "MiniportName": "mlx5.sys",
        "PacketBytes": packet_hex,
        "Size": len(packet_hex) // 2,
    }


def _register_event_store_trace(
    tmp_path: Path,
    trace_id: str,
    rows: list[dict],
) -> TraceData:
    writer = NativeEventStoreWriter(
        tmp_path / f".etw-export-{trace_id}",
        run_id=f"{trace_id}-store",
        timebase=EventStoreTimebase(qpc_origin=0, perf_freq=1_000_000),
        staging=False,
        max_rows_per_part=1,
    )
    for row in rows:
        writer.append("packet_capture", row)
    trace = TraceData(
        trace_id=trace_id,
        etl_path=tmp_path / f"{trace_id}.etl",
        export_dir=tmp_path / f".etw-export-{trace_id}",
        mode="native",
        event_store=writer.commit(),
    )
    trace._dumper_ready.set()
    register_trace(trace)
    return trace


def _pcapng_block(block_type: int, body: bytes) -> bytes:
    total_len = 12 + len(body)
    return struct.pack("<II", block_type, total_len) + body + struct.pack("<I", total_len)


def _write_pcapng(path: Path, packets: list[bytes]) -> None:
    section_body = (
        b"\x4d\x3c\x2b\x1a"
        + struct.pack("<HHq", 1, 0, -1)
    )
    interface_body = struct.pack("<HHI", 1, 0, 65535)
    blocks = [
        _pcapng_block(0x0A0D0D0A, section_body),
        _pcapng_block(0x00000001, interface_body),
    ]
    for index, packet in enumerate(packets):
        timestamp = 1_000_000 + index
        packet_body = struct.pack(
            "<IIIII",
            0,
            timestamp >> 32,
            timestamp & 0xFFFFFFFF,
            len(packet),
            len(packet),
        )
        packet_body += packet
        packet_body += b"\x00" * ((4 - (len(packet) % 4)) % 4)
        blocks.append(_pcapng_block(0x00000006, packet_body))
    path.write_bytes(b"".join(blocks))


def _register_pktmon_text_trace(
    trace_id: str,
    tmp_path: Path,
    text: str,
    packets: list[bytes] | None = None,
) -> TraceData:
    etl_path = tmp_path / f"{trace_id}.etl"
    export_dir = tmp_path / f".etw-export-{trace_id}"
    etl_path.write_bytes(b"synthetic pktmon etl")
    export_dir.mkdir()
    text_path = export_dir / "pktmon.etl2txt.txt"
    text_path.write_bytes(text.encode("utf-16"))
    _write_cache_metadata(text_path, etl_path)
    (export_dir / "pktmon.components.txt").write_text(_PKTMON_COMPONENTS_FIXTURE, encoding="utf-8")
    if packets is not None:
        pcapng_path = export_dir / "pktmon.etl2pcap.pcapng"
        _write_pcapng(pcapng_path, packets)
        _write_cache_metadata(pcapng_path, etl_path)
    trace = TraceData(
        trace_id=trace_id,
        etl_path=etl_path,
        export_dir=export_dir,
        packet_capture_df=None,
    )
    trace._dumper_ready.set()
    register_trace(trace)
    return trace


_PKTMON_TEXT_FIXTURE = f"""
12:05:31.000000000 PktGroupId 1, PktNumber 1, Appearance 0, Direction Tx , Type Ethernet , Component 12, Edge 1, Filter 2, OriginalSize {len(_PACKET_A_HEX) // 2}, LoggedSize {len(_PACKET_A_HEX) // 2}
\t00-00-00-00-00-01 > 00-00-00-00-00-02, IPv4, length 28: 10.0.0.1.5000 > 10.0.0.2.6000: UDP, length 8
12:05:31.000001000 PktGroupId 2, PktNumber 1, Appearance 0, Direction Tx , Type Ethernet , Component 4, Edge 1, Filter 2, OriginalSize {len(_PACKET_A_HEX) // 2}, LoggedSize {len(_PACKET_A_HEX) // 2}
\t00-00-00-00-00-01 > 00-00-00-00-00-02, IPv4, length 28: 10.0.0.1.5000 > 10.0.0.2.6000: UDP, length 8
12:05:31.000002000 PktGroupId 3, PktNumber 1, Appearance 0, Direction Rx , Type Ethernet , Component 1, Edge 1, Filter 2, OriginalSize {len(_PACKET_B_HEX) // 2}, LoggedSize {len(_PACKET_B_HEX) // 2}
\t00-00-00-00-00-02 > 00-00-00-00-00-01, IPv4, length 28: 10.0.0.2.6000 > 10.0.0.1.5000: UDP, length 8
12:05:31.000003000 PktGroupId 4, PktNumber 1, Appearance 0, Direction Rx , Type Ethernet , Component 4, Edge 1, Filter 2, OriginalSize {len(_PACKET_B_HEX) // 2}, LoggedSize {len(_PACKET_B_HEX) // 2}
\t00-00-00-00-00-02 > 00-00-00-00-00-01, IPv4, length 28: 10.0.0.2.6000 > 10.0.0.1.5000: UDP, length 8
"""


_PKTMON_COMPONENTS_FIXTURE = """
NIC: Synthetic NIC
    Id: 1
    Driver: syntheticnic.sys

    Filter Drivers:
        Id Driver           Name
        -- ------           ----
        6 wfplwfs.sys       WFP Native Filter
        4 samplelwf.sys     Sample LWF

    Protocols:
        Id Driver     Name   EtherType
        -- ------     ----   ---------
        12 tcpip.sys  TCPIP  IPv4, ARP
        9             NETVSCVFPP * (All)
"""


def _pktmon_path_text(
    *,
    direction: str,
    packet_len: int,
    detail: str,
    stages: list[tuple[int, int]],
    start_group: int = 100,
) -> str:
    lines = []
    for index, (component, edge) in enumerate(stages):
        lines.append(
            "12:05:31."
            f"{index:09d} PktGroupId {start_group + index}, PktNumber 1, "
            f"Appearance 0, Direction {direction} , Type Ethernet , "
            f"Component {component}, Edge {edge}, Filter 1, "
            f"OriginalSize {packet_len}, LoggedSize {packet_len}"
        )
        lines.append(f"\t{detail}")
    return "\n".join(lines) + "\n"


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

    def test_pktmon_text_fallback_dedupes_boundary_packets(self, tmp_path):
        _register_pktmon_text_trace("pcs_pktmon", tmp_path, _PKTMON_TEXT_FIXTURE)

        out = get_packet_capture_summary("pcs_pktmon")

        assert "Source: pktmon ETL text fallback" in out
        assert "Total packets: 2" in out
        assert "10.0.0.1:5000 -> 10.0.0.2:6000/udp" in out
        assert "10.0.0.2:6000 -> 10.0.0.1:5000/udp" in out

    def test_pktmon_text_fallback_rejects_process_filter(self, tmp_path):
        _register_pktmon_text_trace("pcs_pktmon_filter", tmp_path, _PKTMON_TEXT_FIXTURE)

        out = get_packet_capture_summary("pcs_pktmon_filter", process_filter="echo")

        assert "Process filtering is not available for pktmon text fallback" in out


class TestPktmonDerivedPacketTools:
    def test_pktmon_component_sidecar_next_to_etl_is_used(self, tmp_path):
        trace_id = "pktmon_sidecar"
        etl_path = tmp_path / f"{trace_id}.etl"
        export_dir = tmp_path / f".etw-export-{trace_id}"
        etl_path.write_bytes(b"synthetic pktmon etl")
        export_dir.mkdir()
        (etl_path.with_name(f"{etl_path.stem}.components.txt")).write_text(
            _PKTMON_COMPONENTS_FIXTURE,
            encoding="utf-8",
        )
        text = _pktmon_path_text(
            direction="Tx",
            packet_len=len(_PACKET_A_HEX) // 2,
            detail=(
                "00-00-00-00-00-01 > 00-00-00-00-00-02, IPv4, length 28: "
                "10.0.0.1.5000 > 10.0.0.2.6000: UDP, length 8"
            ),
            stages=[(4, 1), (4, 2)],
        )
        text_path = export_dir / "pktmon.etl2txt.txt"
        pcapng_path = export_dir / "pktmon.etl2pcap.pcapng"
        text_path.write_bytes(text.encode("utf-16"))
        _write_cache_metadata(text_path, etl_path)
        _write_pcapng(pcapng_path, [bytes.fromhex(_PACKET_A_HEX), bytes.fromhex(_PACKET_A_HEX)])
        _write_cache_metadata(pcapng_path, etl_path)
        trace = TraceData(trace_id=trace_id, etl_path=etl_path, export_dir=export_dir)
        trace._dumper_ready.set()
        register_trace(trace)

        out = get_pktmon_layer_latency(trace_id)

        assert "Component names:" in out
        assert "Sample LWF (samplelwf.sys): edge 1 -> edge 2" in out

    def test_stale_pktmon_text_cache_is_regenerated(self, tmp_path):
        etl_path = tmp_path / "stale.etl"
        export_dir = tmp_path / ".etw-export-stale"
        text_path = export_dir / "pktmon.etl2txt.txt"
        export_dir.mkdir()
        etl_path.write_bytes(b"old")
        text_path.write_text("stale", encoding="utf-16")
        _write_cache_metadata(text_path, etl_path)
        etl_path.write_bytes(b"new etl with different identity")
        os.utime(etl_path, (2, 2))
        os.utime(text_path, (3, 3))
        trace = TraceData(trace_id="stale", etl_path=etl_path, export_dir=export_dir)

        def fake_run(cmd, **_kwargs):
            out_path = Path(cmd[cmd.index("--out") + 1])
            out_path.write_text("fresh", encoding="utf-16")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with patch("etw_analyzer.tools.packet_capture.subprocess.run", side_effect=fake_run):
            path, error = _ensure_pktmon_text(trace)

        assert error is None
        assert path == text_path
        assert text_path.read_text(encoding="utf-16") == "fresh"

    def test_pktmon_pcapng_fallback_powers_timeline_and_decode(self, tmp_path):
        _register_pktmon_text_trace(
            "pktmon_deep",
            tmp_path,
            _PKTMON_TEXT_FIXTURE,
            [
                bytes.fromhex(_PACKET_A_HEX),
                bytes.fromhex(_PACKET_A_HEX),
                bytes.fromhex(_PACKET_B_HEX),
                bytes.fromhex(_PACKET_B_HEX),
            ],
        )

        timeline = get_packet_timeline(
            "pktmon_deep",
            "10.0.0.1:5000 -> 10.0.0.2:6000/udp",
        )
        decoded = decode_packet("pktmon_deep", 0)

        assert "Matched packets: 2" in timeline
        assert "10.0.0.1:5000" in timeline
        assert "10.0.0.2:6000" in timeline
        assert "**UDP:**" in decoded
        assert "src: `10.0.0.1`" in decoded

    def test_empty_native_packet_dataset_falls_back_to_pktmon(self, tmp_path):
        trace_id = "pktmon_empty_native"
        etl_path = tmp_path / f"{trace_id}.etl"
        export_dir = tmp_path / f".etw-export-{trace_id}"
        etl_path.write_bytes(b"synthetic pktmon etl")
        writer = NativeEventStoreWriter(
            export_dir,
            run_id=f"{trace_id}-store",
            event_classes=["packet_capture"],
            staging=False,
        )
        text_path = export_dir / "pktmon.etl2txt.txt"
        pcapng_path = export_dir / "pktmon.etl2pcap.pcapng"
        text_path.write_bytes(_PKTMON_TEXT_FIXTURE.encode("utf-16"))
        _write_cache_metadata(text_path, etl_path)
        _write_pcapng(
            pcapng_path,
            [
                bytes.fromhex(_PACKET_A_HEX),
                bytes.fromhex(_PACKET_A_HEX),
                bytes.fromhex(_PACKET_B_HEX),
                bytes.fromhex(_PACKET_B_HEX),
            ],
        )
        _write_cache_metadata(pcapng_path, etl_path)
        trace = TraceData(
            trace_id=trace_id,
            etl_path=etl_path,
            export_dir=export_dir,
            mode="native",
            event_store=writer.commit(),
        )
        trace._dumper_ready.set()
        register_trace(trace)

        out = get_packet_timeline(trace_id, "10.0.0.1:5000 -> 10.0.0.2:6000/udp")

        assert "Matched packets: 2" in out

    def test_pktmon_pcapng_fallback_supports_send_recv_latency(self, tmp_path):
        detail = (
            "00-00-00-00-00-01 > 00-00-00-00-00-02, IPv4, length 28: "
            "10.0.0.1.5000 > 10.0.0.2.6000: UDP, length 8"
        )
        text = (
            _pktmon_path_text(
                direction="Tx",
                packet_len=len(_PACKET_A_HEX) // 2,
                detail=detail,
                stages=[(12, 1)],
            )
            + _pktmon_path_text(
                direction="Rx",
                packet_len=len(_PACKET_A_HEX) // 2,
                detail=detail,
                stages=[(1, 1)],
                start_group=200,
            )
        )
        _register_pktmon_text_trace(
            "pktmon_latency",
            tmp_path,
            text,
            [bytes.fromhex(_PACKET_A_HEX), bytes.fromhex(_PACKET_A_HEX)],
        )

        out = get_send_recv_latency("pktmon_latency")

        assert "Send → Recv Latency" in out
        assert "10.0.0.1:5000 -> 10.0.0.2:6000/udp" in out

    def test_pktmon_layer_latency_groups_udp_and_tcp_paths(self, tmp_path):
        udp_detail = (
            "00-00-00-00-00-01 > 00-00-00-00-00-02, IPv4, length 28: "
            "10.0.0.1.5000 > 10.0.0.2.6000: UDP, length 8"
        )
        tcp_packet = _build_ipv4_tcp(
            src_ip="10.0.0.3",
            dst_ip="10.0.0.4",
            src_port=7000,
            dst_port=443,
            seq=123,
            ack=456,
            flags=0x10,
        )
        tcp_detail = (
            "00-00-00-00-00-03 > 00-00-00-00-00-04, IPv4, length 40: "
            "10.0.0.3.7000 > 10.0.0.4.443: tcp 0"
        )
        text = (
            _pktmon_path_text(
                direction="Tx",
                packet_len=len(_PACKET_A_HEX) // 2,
                detail=udp_detail,
                stages=[(12, 1), (4, 1)],
            )
            + _pktmon_path_text(
                direction="Tx",
                packet_len=len(tcp_packet),
                detail=tcp_detail,
                stages=[(12, 1), (4, 1), (4, 2), (6, 1), (6, 2), (2, 1), (9, 1), (1, 1)],
                start_group=300,
            )
        )
        _register_pktmon_text_trace(
            "pktmon_layers",
            tmp_path,
            text,
            [bytes.fromhex(_PACKET_A_HEX), bytes.fromhex(_PACKET_A_HEX)] + [tcp_packet] * 8,
        )

        out = get_pktmon_layer_latency("pktmon_layers")

        assert "Pktmon Layer Latency" in out
        assert "udp" in out
        assert "tcp" in out
        assert "12/1 -> 4/1" in out
        assert "Sample LWF (samplelwf.sys): edge 1 -> edge 2" in out
        assert "high" in out

    def test_pktmon_layer_latency_direction_filter_limits_journeys(self, tmp_path):
        tx_detail = (
            "00-00-00-00-00-01 > 00-00-00-00-00-02, IPv4, length 28: "
            "10.0.0.1.5000 > 10.0.0.2.6000: UDP, length 8"
        )
        rx_detail = (
            "00-00-00-00-00-02 > 00-00-00-00-00-01, IPv4, length 28: "
            "10.0.0.2.6000 > 10.0.0.1.5000: UDP, length 8"
        )
        text = (
            _pktmon_path_text(
                direction="Tx",
                packet_len=len(_PACKET_A_HEX) // 2,
                detail=tx_detail,
                stages=[(12, 1), (4, 1)],
            )
            + _pktmon_path_text(
                direction="Rx",
                packet_len=len(_PACKET_B_HEX) // 2,
                detail=rx_detail,
                stages=[(1, 1), (9, 1)],
                start_group=200,
            )
        )
        _register_pktmon_text_trace(
            "pktmon_tx_only",
            tmp_path,
            text,
            [
                bytes.fromhex(_PACKET_A_HEX),
                bytes.fromhex(_PACKET_A_HEX),
                bytes.fromhex(_PACKET_B_HEX),
                bytes.fromhex(_PACKET_B_HEX),
            ],
        )

        out = get_pktmon_layer_latency("pktmon_tx_only", direction="tx")

        assert "Direction filter: `tx`" in out
        assert "Journeys grouped: 1" in out
        assert "| Send |" in out
        assert "| Recv |" not in out


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

    def test_pairs_more_than_ten_ms_apart_are_not_matched(self):
        packet = _build_ipv4_udp(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=5000, dst_port=6000, ip_id=1,
        )
        rows = [
            {"TimeStamp": 1_000, "Direction": "Send",
             "PacketBytes": packet.hex(), "Size": len(packet)},
            {"TimeStamp": 11_001, "Direction": "Recv",
             "PacketBytes": packet.hex(), "Size": len(packet)},
        ]
        _register_synthetic("srl_far", _packet_capture_df(rows))

        out = get_send_recv_latency("srl_far")

        assert "No Send" in out
        assert "within the matching window" in out

    def test_exact_window_match_survives_older_candidate_eviction(self):
        old_send = _build_ipv4_udp(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=5000, dst_port=6000, ip_id=1,
        )
        matched = _build_ipv4_udp(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=5000, dst_port=6000, ip_id=2,
        )
        rows = [
            {"TimeStamp": 0, "Direction": "Send",
             "PacketBytes": old_send.hex(), "Size": len(old_send)},
            {"TimeStamp": 1, "Direction": "Send",
             "PacketBytes": matched.hex(), "Size": len(matched)},
            {"TimeStamp": 10_001, "Direction": "Recv",
             "PacketBytes": matched.hex(), "Size": len(matched)},
        ]
        _register_synthetic("srl5", _packet_capture_df(rows))
        out = get_send_recv_latency("srl5")
        assert "Send" in out and "Recv" in out
        assert "| 10,000 |" in out


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


class TestPacketCaptureEventStore:
    def test_summary_decode_and_latency_without_dataframe(self, tmp_path):
        rows = [
            _packet_store_row(1, 1_000, "Send", _PACKET_A_HEX),
            _packet_store_row(2, 1_200, "Recv", _PACKET_A_HEX),
            _packet_store_row(3, 2_000, "Recv", _PACKET_B_HEX),
        ]
        _register_event_store_trace(tmp_path, "pc_store", rows)

        summary = get_packet_capture_summary("pc_store")
        assert "Packet Capture Summary" in summary
        assert "10.0.0.1:5000 -> 10.0.0.2:6000/udp" in summary

        decoded = decode_packet("pc_store", timestamp_us=1_010)
        assert "Decoded Packet" in decoded
        assert "IPv4" in decoded
        assert "10.0.0.1" in decoded

        latency = get_send_recv_latency("pc_store")
        assert "Send" in latency and "Recv" in latency
        assert "| 200 |" in latency

    def test_malformed_packet_bytes_do_not_crash_event_store_tools(self, tmp_path):
        rows = [
            {
                **_packet_store_row(1, 1_000, "Recv", "not-hex"),
                "Size": 7,
            },
        ]
        _register_event_store_trace(tmp_path, "pc_bad", rows)

        summary = get_packet_capture_summary("pc_bad")
        assert "undecoded" in summary

        decoded = decode_packet("pc_bad", timestamp_us=1_000)
        assert "failed to decode" in decoded


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
