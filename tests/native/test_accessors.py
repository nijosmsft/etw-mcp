from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from etw_analyzer.native.accessors import (
    build_cswitch_events_for_tid,
    build_cswitch_wait_summary,
    build_readythread_cswitch_waits,
    find_cswitch_tids_for_process,
    has_event_store_dataset,
    has_trace_event_dataset,
    iter_event_batches,
    materialize_event_dataset,
)
from etw_analyzer.native.event_store import EventFilters, EventStoreTimebase, NativeEventStoreWriter
from etw_analyzer.trace_state import TraceData


def _trace(tmp_path: Path, **kwargs) -> TraceData:
    return TraceData(
        trace_id="trace_test",
        etl_path=tmp_path / "sample.etl",
        export_dir=tmp_path / ".etw-export-sample",
        **kwargs,
    )


def _http_row(qpc: int, request_id: int, url: str, cpu: int = 0) -> dict:
    return {
        "EventSequence": request_id,
        "TimeStamp": qpc,
        "CPU": cpu,
        "PID": 100,
        "ThreadID": 200,
        "RequestId": request_id,
        "ConnectionId": 10,
        "Verb": "GET",
        "Url": url,
    }


def test_iter_batches_prefers_raw_csv_over_event_store(tmp_path: Path) -> None:
    writer = NativeEventStoreWriter(
        tmp_path / ".etw-export-store",
        run_id="store",
        staging=False,
    )
    writer.append("HttpService/Recv", _http_row(1_000, 1, "/store"))
    store = writer.commit()

    raw = pd.DataFrame([{
        "TimeStamp": 10,
        "RequestId": 99,
        "Url": "/raw",
        "CPU": 3,
    }])
    trace = _trace(tmp_path, raw_csv={"http_recv": raw}, event_store=store)

    assert has_event_store_dataset(trace, "HttpService/Recv")
    assert has_trace_event_dataset(trace, "HttpService/Recv")

    batches = list(iter_event_batches(trace, "HttpService/Recv"))
    assert len(batches) == 1
    assert batches[0]["Url"].tolist() == ["/raw"]

    materialized = materialize_event_dataset(trace, "http_recv")
    assert materialized is not None
    assert materialized["RequestId"].tolist() == [99]


def test_materialize_prefers_trace_attribute_over_event_store(tmp_path: Path) -> None:
    writer = NativeEventStoreWriter(
        tmp_path / ".etw-export-store",
        run_id="store",
        staging=False,
    )
    writer.append(
        "TcpIp/Recv",
        {
            "TimeStamp": 1_000,
            "CPU": 1,
            "PID": 10,
            "ThreadID": 11,
            "LocalAddr": "10.0.0.1",
            "LocalPort": 443,
            "RemoteAddr": "10.0.0.2",
            "RemotePort": 50000,
            "Size": 100,
            "SeqNo": 1,
            "ConnId": 1,
        },
    )
    store = writer.commit()

    attr_df = pd.DataFrame([{
        "TimeStamp": 20,
        "CPU": 2,
        "LocalAddr": "192.0.2.1",
        "LocalPort": 443,
        "RemoteAddr": "192.0.2.2",
        "RemotePort": 50000,
        "Size": 200,
    }])
    trace = _trace(tmp_path, tcpip_recv_df=attr_df, event_store=store)

    materialized = materialize_event_dataset(trace, "TcpIp/Recv")
    assert materialized is not None
    assert materialized["LocalAddr"].tolist() == ["192.0.2.1"]
    assert materialized["Size"].tolist() == [200]


def test_accessors_fall_back_to_event_store_batches(tmp_path: Path) -> None:
    writer = NativeEventStoreWriter(
        tmp_path / ".etw-export-store",
        run_id="store",
        timebase=EventStoreTimebase(qpc_origin=1_000, perf_freq=1_000_000),
        staging=False,
        max_rows_per_part=1,
    )
    writer.append("HttpService/Recv", _http_row(1_000, 1, "/a", cpu=0))
    writer.append("HttpService/Recv", _http_row(1_500, 2, "/b", cpu=1))
    store = writer.commit()
    trace = _trace(tmp_path, event_store=store)

    batches = list(
        iter_event_batches(
            trace,
            "http_recv",
            filters=EventFilters(cpu_filter="1"),
            columns=["RequestId", "Url"],
            batch_size=1,
        )
    )

    assert len(batches) == 1
    assert batches[0]["RequestId"].tolist() == [2]
    assert batches[0]["Url"].tolist() == ["/b"]
    assert batches[0]["TimeStamp"].tolist() == [500]

    materialized = materialize_event_dataset(trace, "HttpService/Recv", max_rows=10)
    assert materialized is not None
    assert materialized["Url"].tolist() == ["/a", "/b"]


def test_materialize_enforces_row_limit(tmp_path: Path) -> None:
    writer = NativeEventStoreWriter(
        tmp_path / ".etw-export-store",
        run_id="store",
        staging=False,
    )
    writer.append("HttpService/Recv", _http_row(1_000, 1, "/a"))
    writer.append("HttpService/Recv", _http_row(2_000, 2, "/b"))
    trace = _trace(tmp_path, event_store=writer.commit())

    with pytest.raises(ValueError, match="iterate batches instead"):
        materialize_event_dataset(trace, "http_recv", max_rows=1)


def test_xperf_trace_without_event_store_returns_no_dataset(tmp_path: Path) -> None:
    trace = _trace(tmp_path, mode="xperf", raw_csv={})

    assert not has_event_store_dataset(trace, "http_recv")
    assert not has_trace_event_dataset(trace, "http_recv")
    assert list(iter_event_batches(trace, "http_recv")) == []
    assert materialize_event_dataset(trace, "http_recv") is None


def test_scheduler_accessors_join_readythread_to_next_cswitch(tmp_path: Path) -> None:
    writer = NativeEventStoreWriter(
        tmp_path / ".etw-export-store",
        run_id="scheduler",
        timebase=EventStoreTimebase(qpc_origin=1_000, perf_freq=1_000_000),
        staging=False,
    )
    writer.append(
        "readythread",
        {
            "EventSequence": 1,
            "TimeStampQpc": 1_100,
            "CPU": 0,
            "ProcessId": 100,
            "ThreadId": 42,
            "AdjustReason": 1,
            "AdjustIncrement": 0,
            "Flag": 0,
            "Stack": [0x1000, 0x2000],
        },
    )
    writer.append(
        "cswitch",
        {
            "EventSequence": 2,
            "TimeStampQpc": 1_250,
            "CPU": 1,
            "NewTID": 42,
            "OldTID": 7,
            "NewPID": 100,
            "OldPID": 4,
            "WaitReason": "WrQueue",
            "Stack": [],
        },
    )
    store = writer.commit()
    trace = _trace(tmp_path, mode="native", event_store=store)

    class _FakeSymbolizer:
        def bulk_resolve(self, addrs):
            return {
                0x1000: "ntoskrnl.exe!KeAcquireInStackQueuedSpinLock+0x10",
                0x2000: "tcpip.sys!IppDeliverListToProtocol+0x20",
            }

    trace.symbolizer = _FakeSymbolizer()

    joined = build_readythread_cswitch_waits(trace, target_tid=42)

    assert joined is not None
    assert len(joined) == 1
    assert joined.iloc[0]["ThreadID"] == 42
    assert joined.iloc[0]["WaitReason"] == "WrQueue"
    assert joined.iloc[0]["Wait (us)"] == 150
    assert "tcpip.sys!IppDeliverListToProtocol" in joined.iloc[0]["Ready Thread Stack"]


def test_scheduler_accessors_summarize_cswitch_and_process_threads(tmp_path: Path) -> None:
    writer = NativeEventStoreWriter(
        tmp_path / ".etw-export-store",
        run_id="scheduler-summary",
        timebase=EventStoreTimebase(qpc_origin=1_000, perf_freq=1_000_000),
        staging=False,
    )
    writer.append(
        "process",
        {
            "EventSequence": 1,
            "TimeStampQpc": 1_000,
            "CPU": 0,
            "ProcessId": 100,
            "ParentId": 4,
            "SessionId": 0,
            "ImageFileName": "server.exe",
            "CommandLine": "",
            "Type": "DCStart",
        },
    )
    writer.append(
        "thread",
        {
            "EventSequence": 2,
            "TimeStampQpc": 1_000,
            "CPU": 0,
            "ProcessId": 100,
            "ThreadId": 42,
            "ThreadName": "worker",
            "Type": "DCStart",
        },
    )
    for seq, reason in enumerate(["WrQueue", "WrQueue", "WrDispatchInt"], start=3):
        writer.append(
            "cswitch",
            {
                "EventSequence": seq,
                "TimeStampQpc": 1_000 + seq,
                "CPU": 0,
                "NewTID": 42,
                "OldTID": 7,
                "NewPID": 100,
                "OldPID": 4,
                "WaitReason": reason,
                "Stack": [],
            },
        )
    trace = _trace(tmp_path, mode="native", event_store=writer.commit())

    summary = build_cswitch_wait_summary(trace)
    assert summary is not None
    assert summary.iloc[0]["WaitReason"] == "WrQueue"
    assert summary.iloc[0]["Count"] == 2

    events = build_cswitch_events_for_tid(trace, 42)
    assert events is not None
    assert len(events) == 3

    matches = find_cswitch_tids_for_process(trace, "server")
    assert matches == [(42, "server.exe", 3)]
