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


def test_diskio_summary_combined_parquet_with_type_column():
    """#14/#18: the combined ``diskio`` parquet (one row per IO, ``Type``
    column) must produce a non-empty summary — not "No disk I/O data"."""
    trace = TraceData(
        trace_id="trace_diskio_combined",
        etl_path=Path(r"C:\traces\diskio_combined.etl"),
        export_dir=Path(r"C:\traces\.etw-export-diskio_combined"),
        mode="native",
        raw_csv={
            "diskio": pd.DataFrame([
                {"DiskNumber": 0, "TransferSize": 4096, "Type": "Read", "TimeStamp": 1},
                {"DiskNumber": 0, "TransferSize": 8192, "Type": "Write", "TimeStamp": 2},
                {"DiskNumber": 0, "TransferSize": 0, "Type": "FlushBuffers", "TimeStamp": 3},
                {"DiskNumber": 1, "TransferSize": 16384, "Type": "Read", "TimeStamp": 4},
            ]),
        },
    )
    register_trace(trace)

    disk = get_diskio_summary("trace_diskio_combined")

    assert "No disk I/O data" not in disk
    assert "Disk 0" in disk
    assert "Disk 1" in disk
    assert "reads=1" in disk
    assert "writes=1" in disk
    assert "flushes=1" in disk
    assert "4,096B" in disk


def test_diskio_summary_combined_parquet_with_kind_column():
    """#14/#18: the real dotnet combined ``diskio`` parquet labels the
    operation in a ``Kind`` column (not ``Type``). Mirror that exact schema
    so the regression is caught without loading a 650MB ETL."""
    trace = TraceData(
        trace_id="trace_diskio_kind",
        etl_path=Path(r"C:\traces\diskio_kind.etl"),
        export_dir=Path(r"C:\traces\.etw-export-diskio_kind"),
        mode="dotnet",
        raw_csv={
            "diskio": pd.DataFrame([
                {"EventSequence": 1, "TimeStampQpc": 10, "CPU": 0, "Kind": "Write",
                 "DiskNumber": 0, "ByteOffset": 0, "TransferSize": 8192, "PID": 4,
                 "FileName": "C:\\pagefile.sys", "ElapsedMicros": 1.0},
                {"EventSequence": 2, "TimeStampQpc": 20, "CPU": 1, "Kind": "Read",
                 "DiskNumber": 0, "ByteOffset": 4096, "TransferSize": 4096, "PID": 8,
                 "FileName": "C:\\Windows\\x.dll", "ElapsedMicros": 2.0},
                {"EventSequence": 3, "TimeStampQpc": 30, "CPU": 0, "Kind": "FlushBuffers",
                 "DiskNumber": 0, "ByteOffset": 0, "TransferSize": 0, "PID": 4,
                 "FileName": "", "ElapsedMicros": 0.5},
            ]),
        },
    )
    register_trace(trace)

    disk = get_diskio_summary("trace_diskio_kind")

    assert "No disk I/O data" not in disk
    assert "Disk 0" in disk
    assert "reads=1" in disk
    assert "writes=1" in disk
    assert "flushes=1" in disk


def test_diskio_summary_underscore_keys():
    """#14/#18: native/dotnet underscore keys (``diskio_read`` /
    ``diskio_write``) must produce a non-empty summary."""
    trace = TraceData(
        trace_id="trace_diskio_underscore",
        etl_path=Path(r"C:\traces\diskio_underscore.etl"),
        export_dir=Path(r"C:\traces\.etw-export-diskio_underscore"),
        mode="native",
        raw_csv={
            "diskio_read": pd.DataFrame([
                {"DiskNumber": 0, "TransferSize": 4096, "TimeStamp": 1},
                {"DiskNumber": 0, "TransferSize": 4096, "TimeStamp": 2},
            ]),
            "diskio_write": pd.DataFrame([
                {"DiskNumber": 0, "TransferSize": 8192, "TimeStamp": 3},
            ]),
        },
    )
    register_trace(trace)

    disk = get_diskio_summary("trace_diskio_underscore")

    assert "No disk I/O data" not in disk
    assert "Disk 0" in disk
    assert "reads=2" in disk
    assert "writes=1" in disk


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
