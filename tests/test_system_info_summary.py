from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from etw_analyzer.tools.memory import get_memory_pools
from etw_analyzer.tools.summary import analyze
from etw_analyzer.tools.system_info import (
    get_diskio_summary,
    get_process_info,
    get_sysconfig,
    get_trace_stats,
)
from etw_analyzer.trace_state import TraceData, clear_traces, register_trace


@pytest.fixture(autouse=True)
def _clean_registry():
    clear_traces()
    yield
    clear_traces()


def _register_metadata_trace() -> None:
    trace = TraceData(
        trace_id="trace_meta",
        etl_path=Path(r"C:\traces\meta.etl"),
        export_dir=Path(r"C:\traces\.etw-export-meta"),
        mode="native",
        raw_csv={
            "trace_metadata": pd.DataFrame([{
                "NumberOfProcessors": 80,
                "DurationSeconds": 16.4502142,
                "PerfFreq": 10_000_000,
                "CpuSpeedInMHz": 2295,
                "EventsLost": 0,
                "BuffersLost": 0,
                "BuffersWritten": 42,
                "PointerSize": 8,
            }]),
        },
    )
    trace._dumper_ready.set()
    register_trace(trace)


def test_system_info_uses_structured_trace_metadata_without_raw_text():
    _register_metadata_trace()

    sysconfig = get_sysconfig("trace_meta")
    stats = get_trace_stats("trace_meta")

    assert "ProcessorNum: 80" in sysconfig
    assert "ProcessorSpeed: 2295" in sysconfig
    assert "Number of Processors : 80" in stats
    assert "Trace duration (s)   : 16.4502142" in stats
    assert "Total # Lost Events  : 0" in stats


def test_analyze_uses_trace_metadata_without_xperf_shaped_text():
    _register_metadata_trace()

    out = analyze("trace_meta")

    assert "**System:** **80 LPs**, 2295 MHz" in out
    assert "**Trace:** 16.5s duration, 0 lost events" in out


def test_process_and_disk_tools_use_native_structured_rows_without_raw_text():
    trace = TraceData(
        trace_id="trace_aux",
        etl_path=Path(r"C:\traces\aux.etl"),
        export_dir=Path(r"C:\traces\.etw-export-aux"),
        mode="native",
        raw_csv={
            "Process/DCStart": pd.DataFrame([{
                "ProcessId": 1234,
                "ParentId": 4,
                "SessionId": 0,
                "ImageFileName": "server.exe",
                "CommandLine": "server.exe -listen",
                "TimeStamp": 1,
            }]),
            "DiskIo/Read": pd.DataFrame([{
                "DiskNumber": 0,
                "TransferSize": 4096,
                "TimeStamp": 2,
            }]),
        },
    )
    register_trace(trace)

    processes = get_process_info("trace_aux", process_filter="server")
    disk = get_diskio_summary("trace_aux")

    assert "server.exe" in processes
    assert "1,234" in processes
    assert "Disk 0" in disk
    assert "reads=1" in disk


def test_memory_pools_returns_markdown_when_pool_data_missing(monkeypatch):
    trace = TraceData(
        trace_id="trace_pool",
        etl_path=Path(r"C:\traces\pool.etl"),
        export_dir=Path(r"C:\traces\.etw-export-pool"),
    )
    register_trace(trace)
    monkeypatch.setattr(
        "etw_analyzer.tools.memory._get_pool_df",
        lambda _trace: pd.DataFrame(),
    )

    out = get_memory_pools("trace_pool")

    assert "No pool allocation data available" in out
    assert "xperf-only" in out
