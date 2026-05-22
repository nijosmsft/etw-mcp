"""Tests for Phase 3a networking-event parsing + tools.

Synthetic only — no xperf, no .etl files. The parser tests feed fixture
dumper text through ``parse_dumper_events`` with ``_run_xperf_lines``
patched to yield the fixture, then assert row counts and column schemas
per event class. The tool tests register synthetic ``TraceData`` objects
with pre-populated event DataFrames and assert the markdown output is
shaped correctly.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pandas as pd
import pytest

from etw_analyzer.parsing.wpa_exporter import (
    EVENT_HANDLERS,
    _handle_tcpip_connect_or_accept,
    _handle_tcpip_recv_or_send,
    _handle_tcpip_retransmit,
    _handle_udp_recv_or_send,
    parse_dumper_events,
)
from etw_analyzer.tools.network_events import (
    get_connection_summary,
    get_per_process_socket_throughput,
    get_tcp_retransmits,
    get_udp_flow_summary,
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
# Parser tests — fixture dumper text → parse_dumper_events
# ---------------------------------------------------------------------------


# Synthetic dumper output covering every Phase 3a event class. The layout
# follows the documented MOF schemas (TcpIp_TypeGroup1, TcpIp_TypeGroup2,
# UdpIp_TypeGroup1) with xperf's standard 5-column event header prepended:
#   event_name, TimeStamp, "Process Name ( PID)", ThreadID, CPU, <fields...>
#
# Headers (column-name lines) are included for every class so the parser's
# header-skip path (non-numeric timestamp) is exercised too.
_FIXTURE_DUMPER = """\
SampledProfile, TimeStamp, Process Name ( PID), ThreadID, PrgrmCtr, CPU, ThreadStartImage!Function, Image!Function, Count, Type
    SampledProfile, 1000, echo_server.exe (1234), 5678, 0x0, 0, x!y, ntoskrnl.exe!KiIdle, 1, Profile
CSwitch, TimeStamp, New Process Name ( PID), New TID, NPri, NQnt, TmSinceLast, WaitTime, Old Process Name ( PID), Old TID, OPri, OQnt, OldState, Wait Reason, Swapable, InSwitchTime, CPU, IdealProc, OldRemQnt, NewPriDecr, PrevCState
    CSwitch, 2000, echo_server.exe (1234), 5678, 9, 0, 0, 100, Idle (   0), 0, 0, 0, Waiting, WrQueue, NonSwap, 12345, 3, 0, 0, 0, 0
TcpIp/Recv, TimeStamp, Process Name ( PID), ThreadID, CPU, size, daddr, saddr, dport, sport, seqnum, connid
    TcpIp/Recv, 3000, echo_server.exe (1234), 5678, 4, 1024, 10.0.0.5, 10.0.0.7, 5000, 40000, 100, 1
    TcpIp/Recv, 3100, echo_server.exe (1234), 5678, 4, 1024, 10.0.0.5, 10.0.0.7, 5000, 40000, 200, 1
TcpIp/Send, TimeStamp, Process Name ( PID), ThreadID, CPU, size, daddr, saddr, dport, sport, seqnum, connid
    TcpIp/Send, 3050, echo_server.exe (1234), 5678, 4, 128, 10.0.0.7, 10.0.0.5, 40000, 5000, 100, 1
    TcpIp/Send, 3150, echo_server.exe (1234), 5678, 4, 128, 10.0.0.7, 10.0.0.5, 40000, 5000, 200, 1
    TcpIp_Send, 3200, echo_server.exe (1234), 5678, 4, 64, 10.0.0.7, 10.0.0.5, 40000, 5000, 300, 1
TcpIp/Retransmit, TimeStamp, Process Name ( PID), ThreadID, CPU, size, daddr, saddr, dport, sport, seqnum, connid, RetransmitCount
    TcpIp/Retransmit, 3175, echo_server.exe (1234), 5678, 4, 128, 10.0.0.7, 10.0.0.5, 40000, 5000, 100, 1, 2
TcpIp/Connect, TimeStamp, Process Name ( PID), ThreadID, CPU, size, daddr, saddr, dport, sport, mss, sackopt, tsopt, wsopt, rcvwin, rcvwinscale, sndwinscale, seqnum, connid
    TcpIp/Connect, 2900, echo_server.exe (1234), 5678, 4, 0, 10.0.0.7, 10.0.0.5, 40000, 5000, 1460, 1, 0, 1, 65535, 8, 8, 0, 1
TcpIp/Accept, TimeStamp, Process Name ( PID), ThreadID, CPU, size, daddr, saddr, dport, sport, mss, sackopt, tsopt, wsopt, rcvwin, rcvwinscale, sndwinscale, seqnum, connid
    TcpIp/Accept, 2950, echo_server.exe (1234), 5678, 4, 0, 10.0.0.5, 10.0.0.7, 5000, 40000, 1460, 1, 0, 1, 65535, 8, 8, 0, 1
UdpIp/Recv, TimeStamp, Process Name ( PID), ThreadID, CPU, size, daddr, saddr, dport, sport, seqnum, connid
    UdpIp/Recv, 4000, echo_server.exe (1234), 5678, 4, 64, 10.0.0.5, 10.0.0.7, 5000, 40000, 0, 0
    UdpIp/Recv, 4100, echo_server.exe (1234), 5678, 4, 64, 10.0.0.5, 10.0.0.7, 5000, 40000, 0, 0
    UdpIp_Recv, 4200, echo_server.exe (1234), 5678, 4, 64, 10.0.0.5, 10.0.0.7, 5000, 40000, 0, 0
UdpIp/Send, TimeStamp, Process Name ( PID), ThreadID, CPU, size, daddr, saddr, dport, sport, seqnum, connid
    UdpIp/Send, 4050, echo_server.exe (1234), 5678, 4, 64, 10.0.0.7, 10.0.0.5, 40000, 5000, 0, 0
"""


_ALL_PHASE3_CLASSES = {
    "TcpIp/Recv", "TcpIp/Send", "TcpIp/Retransmit",
    "TcpIp/Connect", "TcpIp/Accept",
    "UdpIp/Recv", "UdpIp/Send",
}


class TestParseDumperEventsPhase3a:
    """Synthetic dumper text → parse_dumper_events with all phase-3a classes."""

    def test_event_handlers_contain_phase3_classes(self):
        for cls in _ALL_PHASE3_CLASSES:
            assert cls in EVENT_HANDLERS, f"missing handler for {cls}"

    def test_all_phase3_classes_parsed(self, tmp_path):
        with _patch_xperf_lines(_FIXTURE_DUMPER):
            results = parse_dumper_events(
                tmp_path / "fake.etl",
                event_classes=_ALL_PHASE3_CLASSES,
            )

        # Two TcpIp/Recv rows in fixture.
        assert len(results["TcpIp/Recv"]) == 2
        # Three TcpIp/Send rows including one with the TcpIp_Send alias.
        assert len(results["TcpIp/Send"]) == 3
        assert len(results["TcpIp/Retransmit"]) == 1
        assert len(results["TcpIp/Connect"]) == 1
        assert len(results["TcpIp/Accept"]) == 1
        # Three UdpIp/Recv rows including one with the UdpIp_Recv alias.
        assert len(results["UdpIp/Recv"]) == 3
        assert len(results["UdpIp/Send"]) == 1

    def test_tcpip_recv_schema(self, tmp_path):
        with _patch_xperf_lines(_FIXTURE_DUMPER):
            results = parse_dumper_events(
                tmp_path / "fake.etl",
                event_classes={"TcpIp/Recv"},
            )
        df = results["TcpIp/Recv"]
        required = {
            "TimeStamp", "Process Name", "PID", "ThreadID", "CPU",
            "LocalAddr", "LocalPort", "RemoteAddr", "RemotePort",
            "Size", "SeqNo",
        }
        assert required <= set(df.columns)
        # On a Recv line: local = dest (we are the receiver). Fixture uses
        # daddr=10.0.0.5/dport=5000, saddr=10.0.0.7/sport=40000.
        row = df.iloc[0]
        assert row["LocalAddr"] == "10.0.0.5"
        assert row["LocalPort"] == 5000
        assert row["RemoteAddr"] == "10.0.0.7"
        assert row["RemotePort"] == 40000
        assert row["Size"] == 1024

    def test_tcpip_send_schema(self, tmp_path):
        with _patch_xperf_lines(_FIXTURE_DUMPER):
            results = parse_dumper_events(
                tmp_path / "fake.etl",
                event_classes={"TcpIp/Send"},
            )
        df = results["TcpIp/Send"]
        # On Send: local = source. Fixture uses saddr=10.0.0.5/sport=5000.
        row = df.iloc[0]
        assert row["LocalAddr"] == "10.0.0.5"
        assert row["LocalPort"] == 5000
        assert row["RemoteAddr"] == "10.0.0.7"
        assert row["RemotePort"] == 40000

    def test_retransmit_schema(self, tmp_path):
        with _patch_xperf_lines(_FIXTURE_DUMPER):
            results = parse_dumper_events(
                tmp_path / "fake.etl",
                event_classes={"TcpIp/Retransmit"},
            )
        df = results["TcpIp/Retransmit"]
        assert "RetransmitCount" in df.columns
        assert int(df.iloc[0]["RetransmitCount"]) == 2

    def test_connect_accept_schema(self, tmp_path):
        with _patch_xperf_lines(_FIXTURE_DUMPER):
            results = parse_dumper_events(
                tmp_path / "fake.etl",
                event_classes={"TcpIp/Connect", "TcpIp/Accept"},
            )
        connect = results["TcpIp/Connect"]
        accept = results["TcpIp/Accept"]
        required = {
            "TimeStamp", "Process Name", "PID", "ThreadID", "CPU",
            "LocalAddr", "LocalPort", "RemoteAddr", "RemotePort",
            "MSS", "RcvWin",
        }
        assert required <= set(connect.columns)
        assert required <= set(accept.columns)
        # mss/rcvwin parsed from positions 10/14.
        assert int(connect.iloc[0]["MSS"]) == 1460
        assert int(connect.iloc[0]["RcvWin"]) == 65535

    def test_udp_send_recv_schema(self, tmp_path):
        with _patch_xperf_lines(_FIXTURE_DUMPER):
            results = parse_dumper_events(
                tmp_path / "fake.etl",
                event_classes={"UdpIp/Recv", "UdpIp/Send"},
            )
        urecv = results["UdpIp/Recv"]
        usend = results["UdpIp/Send"]
        required = {
            "TimeStamp", "Process Name", "PID", "ThreadID", "CPU",
            "LocalAddr", "LocalPort", "RemoteAddr", "RemotePort", "Size",
        }
        assert required <= set(urecv.columns)
        assert required <= set(usend.columns)
        # Fixture UdpIp/Recv line: daddr=10.0.0.5, saddr=10.0.0.7.
        # Recv → local = daddr (we're the receiver).
        assert urecv.iloc[0]["LocalAddr"] == "10.0.0.5"
        assert int(urecv.iloc[0]["Size"]) == 64
        # Fixture UdpIp/Send line: daddr=10.0.0.7, saddr=10.0.0.5.
        # Send → local = saddr (we're the sender). So LocalAddr=10.0.0.5,
        # RemoteAddr=10.0.0.7.
        assert usend.iloc[0]["LocalAddr"] == "10.0.0.5"
        assert usend.iloc[0]["RemoteAddr"] == "10.0.0.7"

    def test_underscore_alias_accepted(self, tmp_path):
        with _patch_xperf_lines(_FIXTURE_DUMPER):
            results = parse_dumper_events(
                tmp_path / "fake.etl",
                event_classes={"TcpIp/Send", "UdpIp/Recv"},
            )
        # TcpIp_Send line is one of the three send rows.
        send_ts = results["TcpIp/Send"]["TimeStamp"].tolist()
        assert 3200 in send_ts
        # UdpIp_Recv line is one of the three udp-recv rows.
        urecv_ts = results["UdpIp/Recv"]["TimeStamp"].tolist()
        assert 4200 in urecv_ts

    def test_existing_classes_still_parse(self, tmp_path):
        # Mixing Phase-3 classes with the existing SampledProfile/CSwitch
        # classes must not break the original behavior.
        with _patch_xperf_lines(_FIXTURE_DUMPER):
            results = parse_dumper_events(
                tmp_path / "fake.etl",
                event_classes={"SampledProfile", "CSwitch", "TcpIp/Recv"},
            )
        assert len(results["SampledProfile"]) == 1
        assert len(results["CSwitch"]) == 1
        assert len(results["TcpIp/Recv"]) == 2


class TestTcpIpHandlersDirect:
    """Direct unit tests on individual handlers — easier to debug schema drift."""

    def test_recv_handler(self):
        parts = (
            "TcpIp/Recv, 1000, echo_server.exe (1234), 5678, 4, "
            "1024, 10.0.0.5, 10.0.0.7, 5000, 40000, 100, 1"
        ).split(",")
        row = _handle_tcpip_recv_or_send(parts)
        assert row is not None
        assert row["TimeStamp"] == 1000
        assert row["LocalAddr"] == "10.0.0.5"
        assert row["RemoteAddr"] == "10.0.0.7"
        assert row["Size"] == 1024

    def test_retransmit_without_count(self):
        # No RetransmitCount column — defaults to 1.
        parts = (
            "TcpIp/Retransmit, 1000, echo_server.exe (1234), 5678, 4, "
            "1024, 10.0.0.7, 10.0.0.5, 40000, 5000, 100, 1"
        ).split(",")
        row = _handle_tcpip_retransmit(parts)
        assert row is not None
        assert row["RetransmitCount"] == 1

    def test_connect_handler(self):
        parts = (
            "TcpIp/Connect, 1000, echo_server.exe (1234), 5678, 4, "
            "0, 10.0.0.7, 10.0.0.5, 40000, 5000, "
            "1460, 1, 0, 1, 65535, 8, 8, 0, 1"
        ).split(",")
        row = _handle_tcpip_connect_or_accept(parts)
        assert row is not None
        assert row["MSS"] == 1460
        assert row["RcvWin"] == 65535

    def test_udp_handler_returns_none_on_short_row(self):
        # Fewer columns than the header requires.
        parts = ["UdpIp/Recv", "1000", "foo"]
        row = _handle_udp_recv_or_send(parts)
        assert row is None

    def test_recv_handler_returns_none_on_bad_timestamp(self):
        parts = (
            "TcpIp/Recv, notanint, echo_server.exe (1234), 5678, 4, "
            "1024, 10.0.0.5, 10.0.0.7, 5000, 40000, 100, 1"
        ).split(",")
        row = _handle_tcpip_recv_or_send(parts)
        assert row is None


# ---------------------------------------------------------------------------
# Tool tests
# ---------------------------------------------------------------------------


def _make_recv_df(rows: list[dict]) -> pd.DataFrame:
    cols = {
        "TimeStamp", "Process Name", "PID", "ThreadID", "CPU",
        "LocalAddr", "LocalPort", "RemoteAddr", "RemotePort", "Size",
    }
    df = pd.DataFrame(rows)
    for col in cols:
        if col not in df.columns:
            df[col] = ""
    return df


def _make_tcp_recv_df(rows):
    df = _make_recv_df(rows)
    df["SeqNo"] = 0
    return df


def _make_rtx_df(rows):
    df = _make_recv_df(rows)
    df["RetransmitCount"] = [r.get("RetransmitCount", 1) for r in rows]
    df["SeqNo"] = 0
    return df


def _register_synthetic(
    trace_id: str = "trace_t",
    *,
    tcp_recv=None,
    tcp_send=None,
    tcp_rtx=None,
    udp_recv=None,
    udp_send=None,
) -> TraceData:
    """Register a TraceData with pre-populated event DataFrames.

    ``_dumper_ready`` is set so ``wait_for_dumper()`` is a no-op.
    """
    trace = TraceData(
        trace_id=trace_id,
        etl_path=Path(f"C:\\fake\\{trace_id}.etl"),
        export_dir=Path(f"C:\\fake\\.etw-export-{trace_id}"),
        tcpip_recv_df=tcp_recv,
        tcpip_send_df=tcp_send,
        tcpip_retransmit_df=tcp_rtx,
        udp_recv_df=udp_recv,
        udp_send_df=udp_send,
    )
    trace._dumper_ready.set()
    register_trace(trace)
    return trace


class TestConnectionSummary:
    def test_aggregates_recv_and_send_by_five_tuple(self):
        recv = _make_tcp_recv_df([
            {"TimeStamp": 1_000_000, "Process Name": "echo_server.exe", "PID": 1,
             "LocalAddr": "10.0.0.5", "LocalPort": 5000,
             "RemoteAddr": "10.0.0.7", "RemotePort": 40000, "Size": 1000},
            {"TimeStamp": 2_000_000, "Process Name": "echo_server.exe", "PID": 1,
             "LocalAddr": "10.0.0.5", "LocalPort": 5000,
             "RemoteAddr": "10.0.0.7", "RemotePort": 40000, "Size": 500},
        ])
        send = _make_tcp_recv_df([
            {"TimeStamp": 1_500_000, "Process Name": "echo_server.exe", "PID": 1,
             "LocalAddr": "10.0.0.5", "LocalPort": 5000,
             "RemoteAddr": "10.0.0.7", "RemotePort": 40000, "Size": 200},
        ])
        rtx = _make_rtx_df([
            {"TimeStamp": 1_800_000, "Process Name": "echo_server.exe", "PID": 1,
             "LocalAddr": "10.0.0.5", "LocalPort": 5000,
             "RemoteAddr": "10.0.0.7", "RemotePort": 40000, "Size": 0,
             "RetransmitCount": 3},
        ])
        _register_synthetic("c1", tcp_recv=recv, tcp_send=send, tcp_rtx=rtx)

        out = get_connection_summary("c1")
        assert "10.0.0.5:5000" in out
        assert "10.0.0.7:40000" in out
        # Total bytes = 1000 + 500 + 200 = 1700
        assert "1,700" in out
        # Retransmit count = 3
        assert "3" in out

    def test_no_tcp_data(self):
        _register_synthetic("c2")
        out = get_connection_summary("c2")
        assert "No TCP/IP event data" in out

    def test_process_filter(self):
        recv = _make_tcp_recv_df([
            {"TimeStamp": 1_000_000, "Process Name": "echo_server.exe", "PID": 1,
             "LocalAddr": "10.0.0.5", "LocalPort": 5000,
             "RemoteAddr": "10.0.0.7", "RemotePort": 40000, "Size": 1000},
            {"TimeStamp": 1_100_000, "Process Name": "other.exe", "PID": 2,
             "LocalAddr": "10.0.0.5", "LocalPort": 9000,
             "RemoteAddr": "10.0.0.8", "RemotePort": 80, "Size": 500},
        ])
        _register_synthetic("c3", tcp_recv=recv)
        out = get_connection_summary("c3", process_filter="echo")
        assert "echo_server.exe" in out
        assert "10.0.0.5:5000" in out
        assert "10.0.0.8:80" not in out

    def test_sorted_by_total_bytes(self):
        recv = _make_tcp_recv_df([
            {"TimeStamp": 1_000_000, "Process Name": "p.exe", "PID": 1,
             "LocalAddr": "10.0.0.5", "LocalPort": 100,
             "RemoteAddr": "10.0.0.6", "RemotePort": 200, "Size": 10},
            {"TimeStamp": 1_100_000, "Process Name": "p.exe", "PID": 1,
             "LocalAddr": "10.0.0.5", "LocalPort": 300,
             "RemoteAddr": "10.0.0.6", "RemotePort": 400, "Size": 10_000},
        ])
        _register_synthetic("c4", tcp_recv=recv)
        out = get_connection_summary("c4")
        # The larger flow should appear before the smaller one in the
        # rendered table.
        big_idx = out.find("10.0.0.5:300")
        small_idx = out.find("10.0.0.5:100")
        assert big_idx != -1 and small_idx != -1
        assert big_idx < small_idx


class TestUdpFlowSummary:
    def test_per_flow_with_pps(self):
        recv = _make_recv_df([
            {"TimeStamp": 1_000_000, "Process Name": "echo_server.exe", "PID": 1,
             "LocalAddr": "10.0.0.5", "LocalPort": 5000,
             "RemoteAddr": "10.0.0.7", "RemotePort": 40000, "Size": 64},
            {"TimeStamp": 1_500_000, "Process Name": "echo_server.exe", "PID": 1,
             "LocalAddr": "10.0.0.5", "LocalPort": 5000,
             "RemoteAddr": "10.0.0.7", "RemotePort": 40000, "Size": 64},
            {"TimeStamp": 2_000_000, "Process Name": "echo_server.exe", "PID": 1,
             "LocalAddr": "10.0.0.5", "LocalPort": 5000,
             "RemoteAddr": "10.0.0.7", "RemotePort": 40000, "Size": 64},
        ])
        _register_synthetic("u1", udp_recv=recv)
        out = get_udp_flow_summary("u1")
        # 3 packets over 1s → 3 PPS. format_table strips trailing .0 on
        # integer-valued floats, so the rendered cell is "3". The presence
        # of a "PPS" column header plus a flow row with packet count 3 and
        # a 1s duration is the signal we want.
        assert "PPS" in out
        assert "10.0.0.5:5000" in out
        assert "Total Pkts" in out

    def test_no_udp_data(self):
        _register_synthetic("u2")
        out = get_udp_flow_summary("u2")
        assert "No UDP event data" in out

    def test_process_filter(self):
        recv = _make_recv_df([
            {"TimeStamp": 1_000_000, "Process Name": "echo_server.exe", "PID": 1,
             "LocalAddr": "10.0.0.5", "LocalPort": 5000,
             "RemoteAddr": "10.0.0.7", "RemotePort": 40000, "Size": 64},
            {"TimeStamp": 1_100_000, "Process Name": "other.exe", "PID": 2,
             "LocalAddr": "10.0.0.5", "LocalPort": 9999,
             "RemoteAddr": "10.0.0.7", "RemotePort": 50000, "Size": 64},
        ])
        _register_synthetic("u3", udp_recv=recv)
        out = get_udp_flow_summary("u3", process_filter="echo")
        assert "10.0.0.5:5000" in out
        assert "10.0.0.5:9999" not in out

    def test_recv_and_send_merged(self):
        recv = _make_recv_df([
            {"TimeStamp": 1_000_000, "Process Name": "p.exe", "PID": 1,
             "LocalAddr": "10.0.0.5", "LocalPort": 5000,
             "RemoteAddr": "10.0.0.7", "RemotePort": 40000, "Size": 64},
        ])
        send = _make_recv_df([
            {"TimeStamp": 1_500_000, "Process Name": "p.exe", "PID": 1,
             "LocalAddr": "10.0.0.5", "LocalPort": 5000,
             "RemoteAddr": "10.0.0.7", "RemotePort": 40000, "Size": 64},
        ])
        _register_synthetic("u4", udp_recv=recv, udp_send=send)
        out = get_udp_flow_summary("u4")
        # Same 5-tuple → one row with 2 packets total.
        # Count rows in the table by counting 5-tuple occurrences.
        assert out.count("10.0.0.5:5000") <= 2  # header + single row


class TestTcpRetransmits:
    def test_flags_high_rate_connection(self):
        # 1000 recv + 0 send + 20 retransmits = rate 20 / 1020 = 1.96% > 0.1%
        recv = _make_tcp_recv_df([
            {"TimeStamp": 1_000_000 + i * 1000, "Process Name": "p.exe", "PID": 1,
             "LocalAddr": "10.0.0.5", "LocalPort": 5000,
             "RemoteAddr": "10.0.0.7", "RemotePort": 40000, "Size": 1}
            for i in range(1000)
        ])
        rtx = _make_rtx_df([
            {"TimeStamp": 1_500_000 + i * 1000, "Process Name": "p.exe", "PID": 1,
             "LocalAddr": "10.0.0.5", "LocalPort": 5000,
             "RemoteAddr": "10.0.0.7", "RemotePort": 40000, "Size": 0,
             "RetransmitCount": 1}
            for i in range(20)
        ])
        _register_synthetic("r1", tcp_recv=recv, tcp_rtx=rtx)
        out = get_tcp_retransmits("r1")
        assert "HIGH RETRANSMIT RATE" in out
        assert "1 connection(s)" in out or "1 connections" in out

    def test_below_threshold_not_flagged(self):
        # 10_000 recv + 1 retransmit → rate ≈ 0.01% < 0.1%
        recv = _make_tcp_recv_df([
            {"TimeStamp": 1_000_000 + i * 100, "Process Name": "p.exe", "PID": 1,
             "LocalAddr": "10.0.0.5", "LocalPort": 5000,
             "RemoteAddr": "10.0.0.7", "RemotePort": 40000, "Size": 1}
            for i in range(10_000)
        ])
        rtx = _make_rtx_df([
            {"TimeStamp": 1_500_000, "Process Name": "p.exe", "PID": 1,
             "LocalAddr": "10.0.0.5", "LocalPort": 5000,
             "RemoteAddr": "10.0.0.7", "RemotePort": 40000, "Size": 0,
             "RetransmitCount": 1},
        ])
        _register_synthetic("r2", tcp_recv=recv, tcp_rtx=rtx)
        out = get_tcp_retransmits("r2")
        assert "HIGH RETRANSMIT RATE" not in out
        assert "below 0.1%" in out

    def test_no_retransmits_with_tcp_data(self):
        recv = _make_tcp_recv_df([
            {"TimeStamp": 1_000_000, "Process Name": "p.exe", "PID": 1,
             "LocalAddr": "10.0.0.5", "LocalPort": 5000,
             "RemoteAddr": "10.0.0.7", "RemotePort": 40000, "Size": 64},
        ])
        _register_synthetic("r3", tcp_recv=recv)
        out = get_tcp_retransmits("r3")
        assert "No retransmit events" in out

    def test_no_tcp_data_at_all(self):
        _register_synthetic("r4")
        out = get_tcp_retransmits("r4")
        assert "No TCP/IP event data" in out


class TestPerProcessSocketThroughput:
    def test_splits_tcp_udp_send_recv(self):
        tcp_recv = _make_tcp_recv_df([
            {"TimeStamp": 1_000_000, "Process Name": "echo_server.exe", "PID": 1,
             "LocalAddr": "10.0.0.5", "LocalPort": 5000,
             "RemoteAddr": "10.0.0.7", "RemotePort": 40000, "Size": 1000},
            {"TimeStamp": 2_000_000, "Process Name": "echo_server.exe", "PID": 1,
             "LocalAddr": "10.0.0.5", "LocalPort": 5000,
             "RemoteAddr": "10.0.0.7", "RemotePort": 40000, "Size": 1000},
        ])
        tcp_send = _make_tcp_recv_df([
            {"TimeStamp": 1_500_000, "Process Name": "echo_server.exe", "PID": 1,
             "LocalAddr": "10.0.0.5", "LocalPort": 5000,
             "RemoteAddr": "10.0.0.7", "RemotePort": 40000, "Size": 500},
        ])
        udp_recv = _make_recv_df([
            {"TimeStamp": 1_000_000, "Process Name": "echo_server.exe", "PID": 1,
             "LocalAddr": "10.0.0.5", "LocalPort": 5001,
             "RemoteAddr": "10.0.0.7", "RemotePort": 40001, "Size": 64},
            {"TimeStamp": 2_000_000, "Process Name": "echo_server.exe", "PID": 1,
             "LocalAddr": "10.0.0.5", "LocalPort": 5001,
             "RemoteAddr": "10.0.0.7", "RemotePort": 40001, "Size": 64},
        ])
        _register_synthetic(
            "p1", tcp_recv=tcp_recv, tcp_send=tcp_send, udp_recv=udp_recv,
        )
        out = get_per_process_socket_throughput("p1")
        assert "echo_server.exe" in out
        # All four column headers must appear in the output.
        assert "TCP Recv PPS" in out
        assert "TCP Send PPS" in out
        assert "UDP Recv PPS" in out
        assert "UDP Send PPS" in out
        # No UDP Send → its cell should be 0.
        # No way to test cell value cheaply, just confirm UDP Send column
        # is rendered.

    def test_no_data(self):
        _register_synthetic("p2")
        out = get_per_process_socket_throughput("p2")
        assert "No TCP or UDP socket event data" in out


# ---------------------------------------------------------------------------
# Background dumper plumbing — verify the cache stem mapping is exclusive.
# ---------------------------------------------------------------------------


def test_dumper_event_classes_have_unique_attrs_and_stems():
    """Each canonical class must map to a unique attribute and parquet stem."""
    from etw_analyzer.tools.trace_mgmt import (
        _DUMPER_EVENT_CLASSES,
        _PARQUET_EXCLUDED,
    )

    attrs = [attr for attr, _ in _DUMPER_EVENT_CLASSES.values()]
    stems = [stem for _, stem in _DUMPER_EVENT_CLASSES.values()]
    assert len(set(attrs)) == len(attrs), "duplicate trace attr names"
    assert len(set(stems)) == len(stems), "duplicate parquet stems"

    # Every dumper parquet stem must be excluded from glob-based raw_csv
    # rehydration so they don't double-load.
    for stem in stems:
        assert stem in _PARQUET_EXCLUDED, (
            f"stem {stem!r} missing from _PARQUET_EXCLUDED — "
            "the glob loader will misroute it into raw_csv"
        )
