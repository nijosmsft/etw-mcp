"""Tests for Phase 3b networking-event parsing + tools.

Synthetic only — no xperf, no .etl files. Parser tests feed fixture dumper
text through ``parse_dumper_events`` with ``_run_xperf_lines`` patched to
yield the fixture, then assert row counts and column schemas for each
event class. The tool tests register synthetic ``TraceData`` objects with
pre-populated event DataFrames and assert the markdown output is shaped
correctly.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pandas as pd
import pytest

from etw_analyzer.parsing.wpa_exporter import (
    EVENT_HANDLERS,
    _handle_afd_close,
    _handle_afd_connect_or_accept,
    _handle_afd_recv_or_send,
    _handle_ndis_drop,
    parse_dumper_events,
)
from etw_analyzer.tools.network_events_extra import (
    _AFD_BATCH_WINDOW_US,
    get_accept_latency,
    get_afd_batching,
    get_connect_latency,
    get_packet_drops,
    get_socket_affinity_check,
    get_socket_lifecycle,
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
    """Patch ``_run_xperf_lines`` to yield ``text`` line-by-line."""
    def _fake_lines(*_args, **_kwargs):
        for line in text.splitlines():
            yield line
    return patch(
        "etw_analyzer.parsing.wpa_exporter._run_xperf_lines",
        side_effect=_fake_lines,
    )


# ---------------------------------------------------------------------------
# Parser tests
# ---------------------------------------------------------------------------


# Synthetic dumper output covering every Phase 3b event class. AFD events
# follow the header + event-specific layout documented in wpa_exporter.py;
# headers (column-name lines) are included for every class so the parser's
# header-skip path is exercised too.
_FIXTURE_DUMPER = """\
AFD/Recv, TimeStamp, Process Name ( PID), ThreadID, CPU, SocketHandle, Size, CompletionStatus
    AFD/Recv, 5000, echo_server.exe (1234), 5678, 4, 0x100, 1024, 0
    AFD/Recv, 5005, echo_server.exe (1234), 5678, 4, 0x100, 1024, 0
    AFD_Recv, 5100, echo_server.exe (1234), 5678, 4, 0x100, 1024, 0
AFD/Send, TimeStamp, Process Name ( PID), ThreadID, CPU, SocketHandle, Size, CompletionStatus
    AFD/Send, 5050, echo_server.exe (1234), 5678, 4, 0x100, 128, 0
AFD/Connect, TimeStamp, Process Name ( PID), ThreadID, CPU, SocketHandle, LocalAddr, LocalPort, RemoteAddr, RemotePort
    AFD/Connect, 4900, echo_server.exe (1234), 5678, 4, 0x100, 10.0.0.5, 5000, 10.0.0.7, 40000
AFD/Accept, TimeStamp, Process Name ( PID), ThreadID, CPU, SocketHandle, LocalAddr, LocalPort, RemoteAddr, RemotePort
    AFD/Accept, 4950, echo_server.exe (1234), 5678, 4, 0x200, 10.0.0.5, 5000, 10.0.0.7, 40000
AFD/Close, TimeStamp, Process Name ( PID), ThreadID, CPU, SocketHandle
    AFD/Close, 9000, echo_server.exe (1234), 5678, 4, 0x100
    AFDClose, 9100, echo_server.exe (1234), 5678, 4, 0x200
NdisDrop, TimeStamp, Process Name ( PID), ThreadID, CPU, MiniportName, Reason, Size
    NdisDrop, 6000, <unknown> (0), 0, 1, mlx5.sys, MissingBuffer, 1500
    NdisDrop, 6100, <unknown> (0), 0, 1, mlx5.sys, MissingBuffer, 1500
    NdisDrop, 6200, <unknown> (0), 0, 1, mlx5.sys, IpsecRcvPolicyError, 64
"""


_ALL_PHASE3B_CLASSES = {
    "AFD/Recv", "AFD/Send", "AFD/Connect", "AFD/Accept", "AFD/Close",
    "NdisDrop",
}


class TestParseDumperEventsPhase3b:
    def test_event_handlers_contain_phase3b_classes(self):
        for cls in _ALL_PHASE3B_CLASSES:
            assert cls in EVENT_HANDLERS, f"missing handler for {cls}"

    def test_all_phase3b_classes_parsed(self, tmp_path):
        with _patch_xperf_lines(_FIXTURE_DUMPER):
            results = parse_dumper_events(
                tmp_path / "fake.etl",
                event_classes=_ALL_PHASE3B_CLASSES,
            )
        assert len(results["AFD/Recv"]) == 3      # 2 slash + 1 underscore alias
        assert len(results["AFD/Send"]) == 1
        assert len(results["AFD/Connect"]) == 1
        assert len(results["AFD/Accept"]) == 1
        assert len(results["AFD/Close"]) == 2     # slash + AFDClose alias
        assert len(results["NdisDrop"]) == 3

    def test_afd_recv_schema(self, tmp_path):
        with _patch_xperf_lines(_FIXTURE_DUMPER):
            results = parse_dumper_events(
                tmp_path / "fake.etl",
                event_classes={"AFD/Recv"},
            )
        df = results["AFD/Recv"]
        required = {
            "TimeStamp", "Process Name", "PID", "ThreadID", "CPU",
            "SocketHandle", "Size", "CompletionStatus",
        }
        assert required <= set(df.columns)
        row = df.iloc[0]
        assert row["SocketHandle"] == 0x100
        assert row["Size"] == 1024

    def test_afd_connect_schema(self, tmp_path):
        with _patch_xperf_lines(_FIXTURE_DUMPER):
            results = parse_dumper_events(
                tmp_path / "fake.etl",
                event_classes={"AFD/Connect"},
            )
        df = results["AFD/Connect"]
        required = {
            "TimeStamp", "Process Name", "PID", "ThreadID", "CPU",
            "SocketHandle", "LocalAddr", "LocalPort",
            "RemoteAddr", "RemotePort",
        }
        assert required <= set(df.columns)
        assert df.iloc[0]["LocalPort"] == 5000

    def test_afd_close_schema(self, tmp_path):
        with _patch_xperf_lines(_FIXTURE_DUMPER):
            results = parse_dumper_events(
                tmp_path / "fake.etl",
                event_classes={"AFD/Close"},
            )
        df = results["AFD/Close"]
        required = {
            "TimeStamp", "Process Name", "PID", "ThreadID", "CPU",
            "SocketHandle",
        }
        assert required <= set(df.columns)

    def test_ndis_drop_schema(self, tmp_path):
        with _patch_xperf_lines(_FIXTURE_DUMPER):
            results = parse_dumper_events(
                tmp_path / "fake.etl",
                event_classes={"NdisDrop"},
            )
        df = results["NdisDrop"]
        required = {"TimeStamp", "MiniportName", "Reason", "Size"}
        assert required <= set(df.columns)
        row = df.iloc[0]
        assert row["MiniportName"] == "mlx5.sys"
        assert row["Reason"] == "MissingBuffer"
        assert row["Size"] == 1500


class TestAfdHandlersDirect:
    def test_recv_handler(self):
        parts = (
            "AFD/Recv, 1000, echo_server.exe (1234), 5678, 4, "
            "0x100, 1024, 0"
        ).split(",")
        row = _handle_afd_recv_or_send(parts)
        assert row is not None
        assert row["SocketHandle"] == 0x100
        assert row["Size"] == 1024
        assert row["CompletionStatus"] == 0

    def test_recv_handler_handles_decimal_socket(self):
        parts = "AFD/Recv, 1000, p.exe (1), 2, 3, 256, 64, 0".split(",")
        row = _handle_afd_recv_or_send(parts)
        assert row is not None
        assert row["SocketHandle"] == 256

    def test_recv_handler_returns_none_on_bad_header(self):
        parts = ["AFD/Recv", "notanint", "p.exe (1)", "1", "0", "0x1", "10", "0"]
        row = _handle_afd_recv_or_send(parts)
        assert row is None

    def test_connect_handler(self):
        parts = (
            "AFD/Connect, 1000, p.exe (1), 2, 3, "
            "0x500, 10.0.0.1, 8080, 10.0.0.2, 80"
        ).split(",")
        row = _handle_afd_connect_or_accept(parts)
        assert row is not None
        assert row["SocketHandle"] == 0x500
        assert row["LocalPort"] == 8080
        assert row["RemoteAddr"] == "10.0.0.2"

    def test_close_handler(self):
        parts = "AFD/Close, 1000, p.exe (1), 2, 3, 0x100".split(",")
        row = _handle_afd_close(parts)
        assert row is not None
        assert row["SocketHandle"] == 0x100

    def test_ndis_drop_handler(self):
        parts = (
            "NdisDrop, 1000, <unknown> (0), 0, 1, "
            "mlx5.sys, MissingBuffer, 1500"
        ).split(",")
        row = _handle_ndis_drop(parts)
        assert row is not None
        assert row["MiniportName"] == "mlx5.sys"
        assert row["Reason"] == "MissingBuffer"
        assert row["Size"] == 1500


# ---------------------------------------------------------------------------
# Tool test helpers
# ---------------------------------------------------------------------------


def _register_synthetic(
    trace_id: str = "trace_t",
    *,
    tcpip_connect=None,
    tcpip_accept=None,
    afd_recv=None,
    afd_send=None,
    afd_connect=None,
    afd_accept=None,
    afd_close=None,
    ndis_drops=None,
) -> TraceData:
    """Register a TraceData with pre-populated event DataFrames."""
    trace = TraceData(
        trace_id=trace_id,
        etl_path=Path(f"C:\\fake\\{trace_id}.etl"),
        export_dir=Path(f"C:\\fake\\.etw-export-{trace_id}"),
        tcpip_connect_df=tcpip_connect,
        tcpip_accept_df=tcpip_accept,
        afd_recv_df=afd_recv,
        afd_send_df=afd_send,
        afd_connect_df=afd_connect,
        afd_accept_df=afd_accept,
        afd_close_df=afd_close,
        ndis_drops_df=ndis_drops,
    )
    trace._dumper_ready.set()
    register_trace(trace)
    return trace


def _connect_df(rows):
    df = pd.DataFrame(rows)
    for col in ("TimeStamp", "Process Name", "PID", "ThreadID", "CPU"):
        if col not in df.columns:
            df[col] = 0 if col != "Process Name" else ""
    return df


def _afd_recv_df(rows):
    df = pd.DataFrame(rows)
    for col in (
        "TimeStamp", "Process Name", "PID", "ThreadID", "CPU",
        "SocketHandle", "Size", "CompletionStatus",
    ):
        if col not in df.columns:
            df[col] = 0 if col != "Process Name" else ""
    return df


def _afd_event_df(rows):
    """Builds a generic AFD event DF (Connect / Accept / Close / Send)."""
    df = pd.DataFrame(rows)
    for col in (
        "TimeStamp", "Process Name", "PID", "ThreadID", "CPU",
        "SocketHandle",
    ):
        if col not in df.columns:
            df[col] = 0 if col != "Process Name" else ""
    return df


# ---------------------------------------------------------------------------
# Tool tests
# ---------------------------------------------------------------------------


class TestConnectLatency:
    def test_known_percentiles(self):
        # Build per-thread inter-arrival pattern so latencies are exactly
        # [10, 20, 30, ..., 100] us. p50=55, p99=99.1, p999=99.91 us when
        # interpolated linearly (pandas default).
        deltas_us = list(range(10, 101, 10))
        rows = []
        t = 1_000_000
        rows.append({
            "TimeStamp": t, "Process Name": "p.exe", "PID": 1,
            "ThreadID": 100, "CPU": 0,
        })
        for d in deltas_us:
            t += d
            rows.append({
                "TimeStamp": t, "Process Name": "p.exe", "PID": 1,
                "ThreadID": 100, "CPU": 0,
            })
        df = _connect_df(rows)
        _register_synthetic("cl1", tcpip_connect=df)
        out = get_connect_latency("cl1")
        assert "TCP Connect Latency" in out
        assert "p.exe" in out
        # format_table strips trailing .0 from integer-valued floats, so
        # p50 of 10..100 (= 55.0) renders as "55", and p99 (=99.1) renders
        # as "99.10". Look for the rendered forms.
        assert "| 55 |" in out
        assert "99.10" in out

    def test_no_data(self):
        _register_synthetic("cl2")
        out = get_connect_latency("cl2")
        assert "No TCP/IP event data" in out

    def test_falls_back_to_afd(self):
        rows = [
            {"TimeStamp": 1_000, "Process Name": "p.exe", "PID": 1,
             "ThreadID": 10, "CPU": 0},
            {"TimeStamp": 2_000, "Process Name": "p.exe", "PID": 1,
             "ThreadID": 10, "CPU": 0},
        ]
        afd = _connect_df(rows)
        _register_synthetic("cl3", afd_connect=afd)
        out = get_connect_latency("cl3")
        assert "TCP Connect Latency" in out
        assert "p.exe" in out


class TestAcceptLatency:
    def test_known_percentiles(self):
        # Latencies: [1000, 2000, 3000, 4000, 5000] us. p50=3000, p99=4960.
        deltas = [1000, 2000, 3000, 4000, 5000]
        rows = [{
            "TimeStamp": 0, "Process Name": "srv.exe", "PID": 2,
            "ThreadID": 20, "CPU": 0,
        }]
        t = 0
        for d in deltas:
            t += d
            rows.append({
                "TimeStamp": t, "Process Name": "srv.exe", "PID": 2,
                "ThreadID": 20, "CPU": 0,
            })
        df = _connect_df(rows)
        _register_synthetic("al1", tcpip_accept=df)
        out = get_accept_latency("al1")
        assert "TCP Accept Latency" in out
        # format_table renders integer-valued floats without decimals, so
        # p50 of [1000, 2000, 3000, 4000, 5000] = 3000.0 renders as "3,000".
        assert "3,000" in out
        # p95 of the same data is 4800.0 → "4,800".
        assert "4,800" in out

    def test_no_data(self):
        _register_synthetic("al2")
        out = get_accept_latency("al2")
        assert "No TCP/IP event data" in out


class TestPacketDrops:
    def test_grouping(self):
        df = pd.DataFrame([
            {"TimeStamp": 1, "MiniportName": "mlx5.sys",
             "Reason": "MissingBuffer", "Size": 1500},
            {"TimeStamp": 2, "MiniportName": "mlx5.sys",
             "Reason": "MissingBuffer", "Size": 1500},
            {"TimeStamp": 3, "MiniportName": "mlx5.sys",
             "Reason": "IpsecRcvPolicyError", "Size": 64},
        ])
        _register_synthetic("d1", ndis_drops=df)
        out = get_packet_drops("d1")
        assert "NDIS Packet Drops" in out
        assert "mlx5.sys" in out
        assert "MissingBuffer" in out
        # 2 MissingBuffer + 1 Ipsec = 3 total → 66.67% MissingBuffer.
        assert "66.67" in out or "66.7" in out

    def test_no_data(self):
        _register_synthetic("d2")
        out = get_packet_drops("d2")
        assert "No NDIS dropped-packet" in out


class TestAfdBatching:
    def test_average_batch_size(self):
        # Three rapid events (within window) followed by a gap, then three
        # more rapid events. Two batches of three → avg per completion = 3.
        events = []
        base = 1_000_000
        # First batch: t, t+1, t+2 us
        for i in range(3):
            events.append({
                "TimeStamp": base + i, "Process Name": "p.exe", "PID": 1,
                "ThreadID": 10, "CPU": 4, "SocketHandle": 0x100, "Size": 64,
            })
        # Gap > _AFD_BATCH_WINDOW_US, then second batch of 3.
        gap_start = base + 1000  # 1000us > 10us window
        for i in range(3):
            events.append({
                "TimeStamp": gap_start + i, "Process Name": "p.exe", "PID": 1,
                "ThreadID": 10, "CPU": 4, "SocketHandle": 0x100, "Size": 64,
            })
        df = _afd_recv_df(events)
        _register_synthetic("b1", afd_recv=df)
        out = get_afd_batching("b1")
        assert "AFD Batching" in out
        # 6 events / 2 batches = 3.0 average. format_table renders the
        # integer-valued float without a trailing decimal: the row cells
        # are "| 6 | 2 | 3 |".
        assert "| 6 | 2 | 3 |" in out
        # Make sure batch window is documented.
        assert f"{_AFD_BATCH_WINDOW_US} us" in out

    def test_singletons_get_avg_one(self):
        # Five events each separated by >> window → 5 batches, avg = 1.
        events = []
        for i in range(5):
            events.append({
                "TimeStamp": 1_000_000 + i * 100_000,
                "Process Name": "p.exe", "PID": 1,
                "ThreadID": 10, "CPU": 4, "SocketHandle": 0x100, "Size": 64,
            })
        df = _afd_recv_df(events)
        _register_synthetic("b2", afd_recv=df)
        out = get_afd_batching("b2")
        # 5 events / 5 batches = 1.0 → rendered as "| 5 | 5 | 1 |".
        assert "| 5 | 5 | 1 |" in out

    def test_no_data(self):
        _register_synthetic("b3")
        out = get_afd_batching("b3")
        assert "No AFD socket event data" in out


class TestSocketLifecycle:
    def test_basic_lifecycle(self):
        connect = _afd_event_df([
            {"TimeStamp": 1_000_000, "Process Name": "p.exe", "PID": 1,
             "ThreadID": 10, "CPU": 4, "SocketHandle": 0x100},
        ])
        close = _afd_event_df([
            {"TimeStamp": 3_000_000, "Process Name": "p.exe", "PID": 1,
             "ThreadID": 10, "CPU": 4, "SocketHandle": 0x100},
        ])
        recv = _afd_recv_df([
            {"TimeStamp": 2_000_000, "Process Name": "p.exe", "PID": 1,
             "ThreadID": 10, "CPU": 4, "SocketHandle": 0x100, "Size": 1024},
            {"TimeStamp": 2_500_000, "Process Name": "p.exe", "PID": 1,
             "ThreadID": 10, "CPU": 4, "SocketHandle": 0x100, "Size": 1024},
        ])
        _register_synthetic("sl1", afd_connect=connect, afd_close=close, afd_recv=recv)
        out = get_socket_lifecycle("sl1")
        assert "AFD Socket Lifecycle" in out
        assert "0x100" in out
        # Duration = 2.0 s → rendered as "| 2 |" (integer-valued float).
        # Bytes = 2048 → "2,048".
        assert "2,048" in out
        # Check the full row signature: created=1000000, closed=3000000,
        # dur=2, recv=2, send=0, bytes=2048.
        assert "| 1,000,000 | 3,000,000 | 2 | 2 | 0 | 2,048 |" in out

    def test_open_socket(self):
        # Socket with connect but no close — duration cell is "open".
        connect = _afd_event_df([
            {"TimeStamp": 1_000_000, "Process Name": "p.exe", "PID": 1,
             "ThreadID": 10, "CPU": 4, "SocketHandle": 0x200},
        ])
        _register_synthetic("sl2", afd_connect=connect)
        out = get_socket_lifecycle("sl2")
        assert "0x200" in out
        assert "open" in out

    def test_no_data(self):
        _register_synthetic("sl3")
        out = get_socket_lifecycle("sl3")
        assert "No AFD socket event data" in out


class TestSocketAffinityCheck:
    def test_affinity_working_when_dominant(self):
        # 95 recvs on CPU 4 + 5 on others → 95% dominance → "affinity working".
        events = []
        for _ in range(95):
            events.append({
                "TimeStamp": 1, "Process Name": "p.exe", "PID": 1,
                "ThreadID": 10, "CPU": 4, "SocketHandle": 0x100, "Size": 64,
            })
        for cpu in (0, 1, 2, 3, 5):
            events.append({
                "TimeStamp": 2, "Process Name": "p.exe", "PID": 1,
                "ThreadID": 10, "CPU": cpu, "SocketHandle": 0x100, "Size": 64,
            })
        df = _afd_recv_df(events)
        _register_synthetic("aff1", afd_recv=df)
        out = get_socket_affinity_check("aff1")
        assert "Socket Affinity Check" in out
        assert "affinity working" in out
        # The header summary line should count 1 working socket.
        assert "Affinity working" in out

    def test_affinity_not_working_when_spread(self):
        # Even distribution across 8 CPUs → no dominant CPU → "not working".
        events = []
        for cpu in range(8):
            for _ in range(10):
                events.append({
                    "TimeStamp": 1, "Process Name": "p.exe", "PID": 1,
                    "ThreadID": 10, "CPU": cpu, "SocketHandle": 0x200, "Size": 64,
                })
        df = _afd_recv_df(events)
        _register_synthetic("aff2", afd_recv=df)
        out = get_socket_affinity_check("aff2")
        assert "affinity not working" in out

    def test_low_confidence_small_sample(self):
        # Fewer than 10 recv events → "low confidence".
        events = [
            {"TimeStamp": 1, "Process Name": "p.exe", "PID": 1,
             "ThreadID": 10, "CPU": 4, "SocketHandle": 0x300, "Size": 64}
            for _ in range(5)
        ]
        df = _afd_recv_df(events)
        _register_synthetic("aff3", afd_recv=df)
        out = get_socket_affinity_check("aff3")
        assert "low confidence" in out

    def test_no_data(self):
        _register_synthetic("aff4")
        out = get_socket_affinity_check("aff4")
        assert "No AFD socket event data" in out


# ---------------------------------------------------------------------------
# Plumbing test — Phase 3b classes must be wired into the dumper map.
# ---------------------------------------------------------------------------


def test_phase3b_classes_wired_into_dumper_map():
    from etw_analyzer.tools.trace_mgmt import (
        _DUMPER_EVENT_CLASSES,
        _PARQUET_EXCLUDED,
    )

    for cls in _ALL_PHASE3B_CLASSES:
        assert cls in _DUMPER_EVENT_CLASSES, (
            f"event class {cls!r} missing from _DUMPER_EVENT_CLASSES"
        )
        _, stem = _DUMPER_EVENT_CLASSES[cls]
        assert stem in _PARQUET_EXCLUDED, (
            f"parquet stem {stem!r} missing from _PARQUET_EXCLUDED"
        )
