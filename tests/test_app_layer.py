"""Tests for Phase 5 application-layer parsing + tools (HTTP.sys + MsQuic).

Synthetic-only — no xperf, no .etl files. Parser tests feed fixture
dumper text through ``parse_dumper_events`` with ``_run_xperf_lines``
patched. Tool tests register synthetic ``TraceData`` objects with
pre-populated event DataFrames and assert the markdown output shape.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pandas as pd
import pytest

from etw_analyzer.native.event_store import EventStoreTimebase, NativeEventStoreWriter
from etw_analyzer.parsing.wpa_exporter import (
    EVENT_HANDLERS,
    _handle_http_recv,
    _handle_http_send,
    _handle_quic_conn_created,
    _handle_quic_packet,
    parse_dumper_events,
)
from etw_analyzer.tools.app_layer import (
    _fnv1a_hash,
    _cid_to_bytes,
    get_http_queue_depth,
    get_http_requests,
    get_quic_ack_delays,
    get_quic_cid_distribution,
    get_quic_connections,
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


_FIXTURE_HTTP_QUIC_DUMPER = """\
HttpService/Recv, TimeStamp, Process Name ( PID), ThreadID, CPU, RequestId, ConnectionId, Verb, Url
    HttpService/Recv, 1000, w3wp.exe (4000), 5000, 4, 0xabcd, 0x1111, GET, /api/test
    HttpService_Recv, 1100, w3wp.exe (4000), 5000, 4, 0xabce, 0x1111, POST, /api/other
HttpService/Deliver, TimeStamp, Process Name ( PID), ThreadID, CPU, RequestId, UrlGroupId
    HttpService/Deliver, 1050, w3wp.exe (4000), 5000, 4, 0xabcd, 0x9999
HttpService/Send, TimeStamp, Process Name ( PID), ThreadID, CPU, RequestId, StatusCode, ContentLength
    HttpService/Send, 1200, w3wp.exe (4000), 5000, 4, 0xabcd, 200, 1024
    HttpService/SendResponse, 1300, w3wp.exe (4000), 5000, 4, 0xabce, 500, 0
HttpService/Close, TimeStamp, Process Name ( PID), ThreadID, CPU, RequestId
    HttpService/Close, 1400, w3wp.exe (4000), 5000, 4, 0xabcd
Quic/ConnectionCreated, TimeStamp, Process Name ( PID), ThreadID, CPU, ConnectionId, CID, LocalAddr, RemoteAddr
    Quic/ConnectionCreated, 2000, secnetperf.exe (3000), 5500, 8, 0x2000, deadbeefcafe, 10.0.0.1:443, 10.0.0.2:5000
    QuicConnectionCreated, 2050, secnetperf.exe (3000), 5500, 8, 0x2001, feedface0102, 10.0.0.1:443, 10.0.0.3:5000
Quic/ConnectionClosed, TimeStamp, Process Name ( PID), ThreadID, CPU, ConnectionId
    Quic/ConnectionClosed, 5000, secnetperf.exe (3000), 5500, 8, 0x2000
Quic/PacketRecv, TimeStamp, Process Name ( PID), ThreadID, CPU, ConnectionId, PacketNumber, Size
    Quic/PacketRecv, 2100, secnetperf.exe (3000), 5500, 8, 0x2000, 1, 1200
    Quic/PacketRecv, 2200, secnetperf.exe (3000), 5500, 8, 0x2000, 2, 1200
Quic/PacketSend, TimeStamp, Process Name ( PID), ThreadID, CPU, ConnectionId, PacketNumber, Size
    Quic/PacketSend, 2150, secnetperf.exe (3000), 5500, 8, 0x2000, 1, 128
Quic/AckReceived, TimeStamp, Process Name ( PID), ThreadID, CPU, ConnectionId, AckDelay, LargestAcknowledged
    Quic/AckReceived, 2250, secnetperf.exe (3000), 5500, 8, 0x2000, 500, 1
    Quic_AckReceived, 2300, secnetperf.exe (3000), 5500, 8, 0x2000, 30000, 2
"""


_PHASE5_CLASSES = {
    "HttpService/Recv", "HttpService/Deliver",
    "HttpService/Send", "HttpService/Close",
    "Quic/ConnectionCreated", "Quic/ConnectionClosed",
    "Quic/PacketRecv", "Quic/PacketSend", "Quic/AckReceived",
}


class TestParseDumperEventsPhase5:
    def test_all_phase5_classes_registered(self):
        for cls in _PHASE5_CLASSES:
            assert cls in EVENT_HANDLERS, f"missing handler for {cls}"

    def test_parses_http_events(self, tmp_path):
        with _patch_xperf_lines(_FIXTURE_HTTP_QUIC_DUMPER):
            results = parse_dumper_events(
                tmp_path / "fake.etl",
                event_classes={
                    "HttpService/Recv", "HttpService/Deliver",
                    "HttpService/Send", "HttpService/Close",
                },
            )
        recv = results["HttpService/Recv"]
        assert len(recv) == 2
        required = {"TimeStamp", "RequestId", "ConnectionId", "Verb", "Url",
                    "Process Name", "PID", "CPU"}
        assert required <= set(recv.columns)
        # 0xabcd = 43981
        assert int(recv.iloc[0]["RequestId"]) == 0xabcd
        assert recv.iloc[0]["Verb"] == "GET"
        assert recv.iloc[0]["Url"] == "/api/test"

        deliver = results["HttpService/Deliver"]
        assert len(deliver) == 1
        assert "UrlGroupId" in deliver.columns
        assert int(deliver.iloc[0]["UrlGroupId"]) == 0x9999

        send = results["HttpService/Send"]
        assert len(send) == 2
        assert "StatusCode" in send.columns
        assert "ContentLength" in send.columns
        statuses = send["StatusCode"].tolist()
        assert 200 in statuses
        assert 500 in statuses

        close = results["HttpService/Close"]
        assert len(close) == 1

    def test_parses_quic_events(self, tmp_path):
        with _patch_xperf_lines(_FIXTURE_HTTP_QUIC_DUMPER):
            results = parse_dumper_events(
                tmp_path / "fake.etl",
                event_classes={
                    "Quic/ConnectionCreated", "Quic/ConnectionClosed",
                    "Quic/PacketRecv", "Quic/PacketSend", "Quic/AckReceived",
                },
            )
        created = results["Quic/ConnectionCreated"]
        # Both Quic/ConnectionCreated and QuicConnectionCreated alias rows.
        assert len(created) == 2
        required = {"TimeStamp", "ConnectionId", "CID", "LocalAddr", "RemoteAddr",
                    "Process Name", "PID", "CPU"}
        assert required <= set(created.columns)
        assert created.iloc[0]["CID"] == "deadbeefcafe"

        closed = results["Quic/ConnectionClosed"]
        assert len(closed) == 1

        recv = results["Quic/PacketRecv"]
        assert len(recv) == 2
        assert "PacketNumber" in recv.columns

        send = results["Quic/PacketSend"]
        assert len(send) == 1

        ack = results["Quic/AckReceived"]
        assert len(ack) == 2
        assert "AckDelay" in ack.columns
        # Verify the alias QuicAckReceived (Quic_AckReceived underscore form)
        # was picked up.
        delays = ack["AckDelay"].tolist()
        assert 500 in delays
        assert 30000 in delays


class TestPhase5HandlersDirect:
    def test_http_recv_handler(self):
        parts = [
            "HttpService/Recv", "1000", "w3wp.exe (4000)", "5000", "4",
            "0xabcd", "0x1111", "GET", "/api/test",
        ]
        row = _handle_http_recv(parts)
        assert row is not None
        assert row["RequestId"] == 0xabcd
        assert row["ConnectionId"] == 0x1111
        assert row["Verb"] == "GET"
        assert row["Url"] == "/api/test"

    def test_http_recv_url_with_commas(self):
        # URLs can contain commas in query strings; we reassemble the tail.
        parts = [
            "HttpService/Recv", "1000", "w3wp.exe (4000)", "5000", "4",
            "0xabcd", "0x1111", "GET", "/api/test?a=1", " b=2", " c=3",
        ]
        row = _handle_http_recv(parts)
        assert row is not None
        assert "a=1" in row["Url"]
        assert "b=2" in row["Url"]
        assert "c=3" in row["Url"]

    def test_http_send_handler(self):
        parts = [
            "HttpService/Send", "1200", "w3wp.exe (4000)", "5000", "4",
            "0xabcd", "200", "1024",
        ]
        row = _handle_http_send(parts)
        assert row is not None
        assert row["StatusCode"] == 200
        assert row["ContentLength"] == 1024

    def test_quic_conn_created_handler(self):
        parts = [
            "Quic/ConnectionCreated", "2000", "secnetperf.exe (3000)", "5500", "8",
            "0x2000", "deadbeefcafe", "10.0.0.1:443", "10.0.0.2:5000",
        ]
        row = _handle_quic_conn_created(parts)
        assert row is not None
        assert row["ConnectionId"] == 0x2000
        assert row["CID"] == "deadbeefcafe"

    def test_quic_packet_handler(self):
        parts = [
            "Quic/PacketRecv", "2100", "secnetperf.exe (3000)", "5500", "8",
            "0x2000", "42", "1200",
        ]
        row = _handle_quic_packet(parts)
        assert row is not None
        assert row["PacketNumber"] == 42
        assert row["Size"] == 1200

    def test_handler_returns_none_on_short_row(self):
        # Fewer columns than the header requires.
        parts = ["HttpService/Recv", "1000", "foo"]
        row = _handle_http_recv(parts)
        assert row is None


# ---------------------------------------------------------------------------
# Tool fixtures
# ---------------------------------------------------------------------------


def _make_df(rows: list[dict], required_cols: list[str]) -> pd.DataFrame:
    df = pd.DataFrame(rows)
    for col in required_cols:
        if col not in df.columns:
            df[col] = "" if col in (
                "Process Name", "Verb", "Url", "CID", "LocalAddr", "RemoteAddr"
            ) else 0
    return df


def _make_http_recv(rows):
    return _make_df(rows, [
        "TimeStamp", "Process Name", "PID", "ThreadID", "CPU",
        "RequestId", "ConnectionId", "Verb", "Url",
    ])


def _make_http_deliver(rows):
    return _make_df(rows, [
        "TimeStamp", "Process Name", "PID", "ThreadID", "CPU",
        "RequestId", "UrlGroupId",
    ])


def _make_http_send(rows):
    return _make_df(rows, [
        "TimeStamp", "Process Name", "PID", "ThreadID", "CPU",
        "RequestId", "StatusCode", "ContentLength",
    ])


def _make_http_close(rows):
    return _make_df(rows, [
        "TimeStamp", "Process Name", "PID", "ThreadID", "CPU", "RequestId",
    ])


def _make_quic_conn_created(rows):
    return _make_df(rows, [
        "TimeStamp", "Process Name", "PID", "ThreadID", "CPU",
        "ConnectionId", "CID", "LocalAddr", "RemoteAddr",
    ])


def _make_quic_conn_closed(rows):
    return _make_df(rows, [
        "TimeStamp", "Process Name", "PID", "ThreadID", "CPU", "ConnectionId",
    ])


def _make_quic_packet(rows):
    return _make_df(rows, [
        "TimeStamp", "Process Name", "PID", "ThreadID", "CPU",
        "ConnectionId", "PacketNumber", "Size",
    ])


def _make_quic_ack(rows):
    return _make_df(rows, [
        "TimeStamp", "Process Name", "PID", "ThreadID", "CPU",
        "ConnectionId", "AckDelay", "LargestAcknowledged",
    ])


def _register_synthetic(
    trace_id: str,
    *,
    http_recv=None,
    http_deliver=None,
    http_send=None,
    http_close=None,
    quic_conn_created=None,
    quic_conn_closed=None,
    quic_packet_recv=None,
    quic_packet_send=None,
    quic_ack_recv=None,
) -> TraceData:
    trace = TraceData(
        trace_id=trace_id,
        etl_path=Path(f"C:\\fake\\{trace_id}.etl"),
        export_dir=Path(f"C:\\fake\\.etw-export-{trace_id}"),
        http_recv_df=http_recv,
        http_deliver_df=http_deliver,
        http_send_df=http_send,
        http_close_df=http_close,
        quic_conn_created_df=quic_conn_created,
        quic_conn_closed_df=quic_conn_closed,
        quic_packet_recv_df=quic_packet_recv,
        quic_packet_send_df=quic_packet_send,
        quic_ack_recv_df=quic_ack_recv,
    )
    trace._dumper_ready.set()
    register_trace(trace)
    return trace


def _register_event_store_synthetic(
    trace_id: str,
    tmp_path: Path,
    rows_by_class: dict[str, list[dict]],
) -> TraceData:
    writer = NativeEventStoreWriter(
        tmp_path / f".etw-export-{trace_id}",
        run_id=f"run-{trace_id}",
        timebase=EventStoreTimebase(qpc_origin=0, perf_freq=1_000_000),
        staging=False,
        max_rows_per_part=2,
    )
    for event_class, rows in rows_by_class.items():
        for row in rows:
            writer.append(event_class, row)
    trace = TraceData(
        trace_id=trace_id,
        etl_path=tmp_path / f"{trace_id}.etl",
        export_dir=tmp_path / f".etw-export-{trace_id}",
        event_store=writer.commit(),
    )
    trace._dumper_ready.set()
    register_trace(trace)
    return trace


# ---------------------------------------------------------------------------
# Tool tests: get_http_requests
# ---------------------------------------------------------------------------


class TestGetHttpRequests:
    def test_pairs_recv_and_send_by_request_id(self):
        recv = _make_http_recv([
            {"TimeStamp": 1000, "RequestId": 1, "ConnectionId": 11,
             "Verb": "GET", "Url": "/foo",
             "Process Name": "w3wp.exe", "PID": 100},
            {"TimeStamp": 1500, "RequestId": 2, "ConnectionId": 12,
             "Verb": "POST", "Url": "/bar",
             "Process Name": "w3wp.exe", "PID": 100},
        ])
        send = _make_http_send([
            # rid=1 takes 200us, rid=2 takes 500us.
            {"TimeStamp": 1200, "RequestId": 1, "StatusCode": 200,
             "ContentLength": 1024, "Process Name": "w3wp.exe", "PID": 100},
            {"TimeStamp": 2000, "RequestId": 2, "StatusCode": 500,
             "ContentLength": 0, "Process Name": "w3wp.exe", "PID": 100},
        ])
        _register_synthetic("h1", http_recv=recv, http_send=send)
        out = get_http_requests("h1")
        assert "HTTP Requests" in out
        assert "Requests observed: 2" in out
        assert "/foo" in out
        assert "/bar" in out
        assert "200" in out
        assert "500" in out

    def test_recv_send_latency_calc(self):
        recv = _make_http_recv([
            {"TimeStamp": 1000, "RequestId": 1, "Verb": "GET", "Url": "/x"},
        ])
        send = _make_http_send([
            {"TimeStamp": 1750, "RequestId": 1, "StatusCode": 200,
             "ContentLength": 100},
        ])
        _register_synthetic("h2", http_recv=recv, http_send=send)
        out = get_http_requests("h2")
        # 1750 - 1000 = 750 us; format_table renders as "750".
        assert "750" in out

    def test_url_filter(self):
        recv = _make_http_recv([
            {"TimeStamp": 1000, "RequestId": 1, "Verb": "GET", "Url": "/api/users"},
            {"TimeStamp": 1100, "RequestId": 2, "Verb": "GET", "Url": "/api/orders"},
        ])
        send = _make_http_send([
            {"TimeStamp": 1200, "RequestId": 1, "StatusCode": 200, "ContentLength": 0},
            {"TimeStamp": 1300, "RequestId": 2, "StatusCode": 200, "ContentLength": 0},
        ])
        _register_synthetic("h3", http_recv=recv, http_send=send)
        out = get_http_requests("h3", url_filter="users")
        assert "/api/users" in out
        assert "/api/orders" not in out

    def test_request_in_flight_no_send(self):
        # Recv with no matching Send — should still appear but with no status.
        recv = _make_http_recv([
            {"TimeStamp": 1000, "RequestId": 1, "Verb": "GET", "Url": "/slow"},
        ])
        _register_synthetic("h4", http_recv=recv, http_send=None)
        out = get_http_requests("h4")
        assert "/slow" in out
        assert "in flight" in out.lower()

    def test_no_data(self):
        _register_synthetic("h5")
        out = get_http_requests("h5")
        assert "No HTTP.sys event data" in out

    def test_event_store_only_lifecycle(self, tmp_path):
        _register_event_store_synthetic(
            "hstore",
            tmp_path,
            {
                "HttpService/Recv": [{
                    "EventSequence": 1,
                    "TimeStamp": 1_000,
                    "CPU": 1,
                    "PID": 100,
                    "ThreadID": 200,
                    "RequestId": 10,
                    "ConnectionId": 99,
                    "Verb": "GET",
                    "Url": "/store",
                }],
                "HttpService/Deliver": [{
                    "EventSequence": 2,
                    "TimeStamp": 1_100,
                    "CPU": 1,
                    "PID": 100,
                    "ThreadID": 200,
                    "RequestId": 10,
                    "UrlGroupId": 7,
                }],
                "HttpService/Send": [{
                    "EventSequence": 3,
                    "TimeStamp": 1_500,
                    "CPU": 1,
                    "PID": 100,
                    "ThreadID": 200,
                    "RequestId": 10,
                    "StatusCode": 201,
                    "ContentLength": 42,
                }],
                "HttpService/Close": [{
                    "EventSequence": 4,
                    "TimeStamp": 1_600,
                    "CPU": 1,
                    "PID": 100,
                    "ThreadID": 200,
                    "RequestId": 10,
                }],
            },
        )

        out = get_http_requests("hstore")
        assert "HTTP Requests" in out
        assert "/store" in out
        assert "201" in out
        assert "500" in out

        queue = get_http_queue_depth("hstore")
        assert "HTTP Queue Depth" in queue
        assert "UrlGroupId" in queue
        assert "7" in queue
        assert "Latency p50" in queue


# ---------------------------------------------------------------------------
# Tool tests: get_http_queue_depth
# ---------------------------------------------------------------------------


class TestGetHttpQueueDepth:
    def test_peak_depth_is_five(self):
        # Construct: 5 concurrent deliveries at t=10s in group A,
        # all completing by t=20s; then 1 more at t=21s alone.
        deliver_rows = []
        send_rows = []
        for i in range(5):
            deliver_rows.append({
                "TimeStamp": 10_000_000 + i,  # microseconds
                "RequestId": 100 + i,
                "UrlGroupId": 1,
            })
            # All five complete after t=20s so peak is 5.
            send_rows.append({
                "TimeStamp": 20_000_000 + i,
                "RequestId": 100 + i,
                "StatusCode": 200,
                "ContentLength": 0,
            })
        # The single-request burst — depth goes back up to 1 at t=21s
        # and then back down.
        deliver_rows.append({
            "TimeStamp": 21_000_000,
            "RequestId": 200,
            "UrlGroupId": 1,
        })
        send_rows.append({
            "TimeStamp": 21_500_000,
            "RequestId": 200,
            "StatusCode": 200,
            "ContentLength": 0,
        })

        deliver = _make_http_deliver(deliver_rows)
        send = _make_http_send(send_rows)
        _register_synthetic("hq1", http_deliver=deliver, http_send=send)
        out = get_http_queue_depth("hq1")
        assert "HTTP Queue Depth" in out
        # Peak Depth column should report 5 for UrlGroupId=1.
        # format_table renders ints with commas — but 5 has none.
        assert "Peak Depth" in out
        # Look for the 5 value in the row content (between pipes).
        # Quick sanity check — peak must be at least 5.
        assert " 5 " in out or "| 5 |" in out

    def test_separate_groups_tracked_independently(self):
        # Two URL groups, each with 2 concurrent requests.
        deliver = _make_http_deliver([
            {"TimeStamp": 1000, "RequestId": 1, "UrlGroupId": 100},
            {"TimeStamp": 1001, "RequestId": 2, "UrlGroupId": 100},
            {"TimeStamp": 1002, "RequestId": 3, "UrlGroupId": 200},
        ])
        send = _make_http_send([
            {"TimeStamp": 2000, "RequestId": 1, "StatusCode": 200, "ContentLength": 0},
            {"TimeStamp": 2001, "RequestId": 2, "StatusCode": 200, "ContentLength": 0},
            {"TimeStamp": 2002, "RequestId": 3, "StatusCode": 200, "ContentLength": 0},
        ])
        _register_synthetic("hq2", http_deliver=deliver, http_send=send)
        out = get_http_queue_depth("hq2")
        # Both group IDs should show up.
        assert "100" in out
        assert "200" in out

    def test_no_data(self):
        _register_synthetic("hq3")
        out = get_http_queue_depth("hq3")
        assert "No HTTP.sys event data" in out


# ---------------------------------------------------------------------------
# Tool tests: get_quic_connections
# ---------------------------------------------------------------------------


class TestGetQuicConnections:
    def test_packet_loss_estimation(self):
        # One connection, 10 sent, 8 received (PNs 1,2,4,5,6,7,9,10 — missing 3 and 8).
        created = _make_quic_conn_created([
            {"TimeStamp": 1000, "ConnectionId": 5,
             "CID": "abcdef0102", "LocalAddr": "10.0.0.1",
             "RemoteAddr": "10.0.0.2:443",
             "Process Name": "secnetperf.exe", "PID": 200},
        ])
        send_pns = list(range(1, 11))
        recv_pns = [1, 2, 4, 5, 6, 7, 9, 10]
        send = _make_quic_packet([
            {"TimeStamp": 1100 + i * 10, "ConnectionId": 5, "PacketNumber": pn,
             "Size": 1200}
            for i, pn in enumerate(send_pns)
        ])
        recv = _make_quic_packet([
            {"TimeStamp": 1200 + i * 10, "ConnectionId": 5, "PacketNumber": pn,
             "Size": 1200, "CPU": 4}
            for i, pn in enumerate(recv_pns)
        ])
        _register_synthetic(
            "q1",
            quic_conn_created=created,
            quic_packet_send=send,
            quic_packet_recv=recv,
        )
        out = get_quic_connections("q1")
        assert "MsQuic Connections" in out
        assert "secnetperf.exe" in out
        # "Lost Pkts" column should show 2 (PNs 3 and 8 missing).
        # format_table renders 2 as "2".
        # Strip "Recv Pkts" and "Send Pkts" headers — but the Lost Pkts cell.
        # Simplest assertion: the literal " 2 " appears in the row.
        assert "Lost Pkts" in out
        # Send count = 10, Recv = 8, Lost = 2.
        assert "10" in out
        assert " 8 " in out or "| 8 |" in out
        assert " 2 " in out or "| 2 |" in out

    def test_lifetime_calc(self):
        created = _make_quic_conn_created([
            {"TimeStamp": 1000, "ConnectionId": 5, "CID": "ab",
             "RemoteAddr": "10.0.0.2:443",
             "Process Name": "secnetperf.exe"},
        ])
        closed = _make_quic_conn_closed([
            {"TimeStamp": 5000, "ConnectionId": 5,
             "Process Name": "secnetperf.exe"},
        ])
        _register_synthetic(
            "q2",
            quic_conn_created=created,
            quic_conn_closed=closed,
        )
        out = get_quic_connections("q2")
        # 5000 - 1000 = 4000 us
        assert "4,000" in out or " 4000 " in out

    def test_no_data(self):
        _register_synthetic("q3")
        out = get_quic_connections("q3")
        assert "No MsQuic event data" in out


# ---------------------------------------------------------------------------
# Tool tests: get_quic_cid_distribution
# ---------------------------------------------------------------------------


class TestGetQuicCidDistribution:
    def test_histogram_buckets_by_hash(self):
        # Create three connections with deterministic CIDs. We'll compute
        # the expected bucket for each based on FNV-1a over the CID bytes
        # modulo the inferred CPU count (max CPU + 1).
        cid_a = "deadbeef"  # 4 bytes
        cid_b = "cafebabe"
        cid_c = "1234abcd"

        created = _make_quic_conn_created([
            {"TimeStamp": 1000, "ConnectionId": 1, "CID": cid_a,
             "RemoteAddr": "10.0.0.2:443",
             "Process Name": "secnetperf.exe"},
            {"TimeStamp": 1001, "ConnectionId": 2, "CID": cid_b,
             "RemoteAddr": "10.0.0.3:443",
             "Process Name": "secnetperf.exe"},
            {"TimeStamp": 1002, "ConnectionId": 3, "CID": cid_c,
             "RemoteAddr": "10.0.0.4:443",
             "Process Name": "secnetperf.exe"},
        ])
        # PacketRecv events on a 4-CPU system (CPUs 0..3).
        recv = _make_quic_packet([
            {"TimeStamp": 1100, "ConnectionId": 1, "PacketNumber": 1,
             "Size": 100, "CPU": 0},
            {"TimeStamp": 1200, "ConnectionId": 2, "PacketNumber": 1,
             "Size": 100, "CPU": 1},
            {"TimeStamp": 1300, "ConnectionId": 3, "PacketNumber": 1,
             "Size": 100, "CPU": 3},
        ])
        _register_synthetic(
            "qcid1",
            quic_conn_created=created,
            quic_packet_recv=recv,
        )
        out = get_quic_cid_distribution("qcid1")
        assert "MsQuic CID Distribution" in out
        assert "FNV-1a" in out
        # CPU count derived from max CPU=3 → 4 CPUs.
        assert "CPU count" in out
        # Verify the expected buckets all show up in the output.
        expected_buckets = {
            _fnv1a_hash(_cid_to_bytes(cid)) % 4
            for cid in (cid_a, cid_b, cid_c)
        }
        for bucket in expected_buckets:
            assert f"| {bucket} " in out or f" {bucket} " in out

    def test_no_data(self):
        _register_synthetic("qcid2")
        out = get_quic_cid_distribution("qcid2")
        assert "No MsQuic event data" in out


# ---------------------------------------------------------------------------
# Tool tests: get_quic_ack_delays
# ---------------------------------------------------------------------------


class TestGetQuicAckDelays:
    def test_flags_high_p99(self):
        # 100 AckDelay samples for connection 1: most low (500us), the top
        # ~5% set above the 25ms threshold. pandas' default quantile is
        # linearly interpolated so we need a thick tail (not a single
        # outlier) for the p99 to land cleanly above 25ms.
        delays = [500] * 95 + [40000] * 5
        ack = _make_quic_ack([
            {"TimeStamp": 1000 + i, "ConnectionId": 1, "AckDelay": d,
             "LargestAcknowledged": i}
            for i, d in enumerate(delays)
        ])
        _register_synthetic("qa1", quic_ack_recv=ack)
        out = get_quic_ack_delays("qa1")
        assert "MsQuic Ack Delays" in out
        assert "HIGH ACK DELAY" in out
        # The flagged connection should be marked HIGH.
        assert "HIGH" in out

    def test_no_high_p99(self):
        # All ack delays under 10ms — none should be flagged.
        ack = _make_quic_ack([
            {"TimeStamp": 1000 + i, "ConnectionId": 1, "AckDelay": 5000,
             "LargestAcknowledged": i}
            for i in range(50)
        ])
        _register_synthetic("qa2", quic_ack_recv=ack)
        out = get_quic_ack_delays("qa2")
        assert "All connections under" in out

    def test_no_data(self):
        _register_synthetic("qa3")
        out = get_quic_ack_delays("qa3")
        assert "No MsQuic event data" in out

    def test_event_store_only_quic_lifecycle_and_ack(self, tmp_path):
        _register_event_store_synthetic(
            "qstore",
            tmp_path,
            {
                "Quic/ConnectionCreated": [{
                    "EventSequence": 1,
                    "TimeStamp": 2_000,
                    "CPU": 2,
                    "PID": 300,
                    "ThreadID": 400,
                    "ConnectionId": 77,
                    "CID": "deadbeef",
                    "LocalAddr": "10.0.0.1:443",
                    "RemoteAddr": "10.0.0.2:5000",
                    "Process Name": "secnetperf.exe",
                }],
                "Quic/PacketRecv": [
                    {
                        "EventSequence": 2,
                        "TimeStamp": 2_100,
                        "CPU": 2,
                        "PID": 300,
                        "ThreadID": 400,
                        "ConnectionId": 77,
                        "PacketNumber": 1,
                        "Size": 1200,
                    },
                    {
                        "EventSequence": 3,
                        "TimeStamp": 2_200,
                        "CPU": 2,
                        "PID": 300,
                        "ThreadID": 400,
                        "ConnectionId": 77,
                        "PacketNumber": 3,
                        "Size": 1200,
                    },
                ],
                "Quic/PacketSend": [{
                    "EventSequence": 4,
                    "TimeStamp": 2_150,
                    "CPU": 2,
                    "PID": 300,
                    "ThreadID": 400,
                    "ConnectionId": 77,
                    "PacketNumber": 1,
                    "Size": 128,
                }],
                "Quic/AckReceived": [
                    {
                        "EventSequence": 5,
                        "TimeStamp": 2_300,
                        "CPU": 2,
                        "PID": 300,
                        "ThreadID": 400,
                        "ConnectionId": 77,
                        "AckDelay": 500,
                        "LargestAcknowledged": 1,
                    },
                    {
                        "EventSequence": 6,
                        "TimeStamp": 2_400,
                        "CPU": 2,
                        "PID": 300,
                        "ThreadID": 400,
                        "ConnectionId": 77,
                        "AckDelay": 30_000,
                        "LargestAcknowledged": 3,
                    },
                ],
                "Quic/ConnectionClosed": [{
                    "EventSequence": 7,
                    "TimeStamp": 5_000,
                    "CPU": 2,
                    "PID": 300,
                    "ThreadID": 400,
                    "ConnectionId": 77,
                }],
            },
        )

        conns = get_quic_connections("qstore")
        assert "MsQuic Connections" in conns
        assert "deadbeef" in conns
        assert "Lost Pkts" in conns
        assert "3,000" in conns or " 3000 " in conns

        acks = get_quic_ack_delays("qstore")
        assert "MsQuic Ack Delays" in acks
        assert "HIGH ACK DELAY" in acks
        assert "30,000" in acks or "30000" in acks

        cids = get_quic_cid_distribution("qstore")
        assert "MsQuic CID Distribution" in cids
        assert "deadbeef" not in cids  # tool reports hashed buckets, not raw CIDs.
        assert "CPU count" in cids
