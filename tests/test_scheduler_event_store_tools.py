from __future__ import annotations

from pathlib import Path

import pytest

from etw_analyzer.native.event_store import EventStoreTimebase, NativeEventStoreWriter
from etw_analyzer.tools.context_switch import get_lock_contention
from etw_analyzer.tools.network_wait_chain import get_network_wait_chain
from etw_analyzer.trace_state import TraceData, clear_traces, register_trace


@pytest.fixture(autouse=True)
def _clean_traces():
    clear_traces()
    yield
    clear_traces()


class _FakeSymbolizer:
    def bulk_resolve(self, addrs):
        return {
            0x1000: "ntoskrnl.exe!KeAcquireInStackQueuedSpinLock+0x10",
            0x2000: "tcpip.sys!IppDeliverListToProtocol+0x20",
        }


def _register_scheduler_trace(tmp_path: Path, trace_id: str = "trace_scheduler") -> TraceData:
    export_dir = tmp_path / ".etw-export-scheduler"
    writer = NativeEventStoreWriter(
        export_dir,
        run_id="scheduler-tools",
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
    trace = TraceData(
        trace_id=trace_id,
        etl_path=tmp_path / "sample.etl",
        export_dir=export_dir,
        mode="native",
        raw_csv={},
        event_store=writer.commit(),
    )
    trace.symbolizer = _FakeSymbolizer()
    register_trace(trace)
    return trace


def test_get_lock_contention_uses_event_store_scheduler_join(tmp_path: Path) -> None:
    trace = _register_scheduler_trace(tmp_path)

    output = get_lock_contention(trace.trace_id, module_filter="tcpip.sys")

    assert "Lock Contention Analysis" in output
    assert "Lock-related switches: 1" in output
    assert "tcpip.sys!IppDeliverListToProtocol" in output
    assert "median=150.0us" in output


def test_get_network_wait_chain_smoke_from_event_store(tmp_path: Path) -> None:
    trace = _register_scheduler_trace(tmp_path)

    output = get_network_wait_chain(trace.trace_id, thread_filter=42)

    assert "Wait-chain analysis" in output
    assert "WaitReason histogram" in output
    assert "WrQueue" in output
    assert "ReadyThread -> next CSwitch waits" in output
