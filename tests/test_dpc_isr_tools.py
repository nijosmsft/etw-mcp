"""Tests for DPC/ISR tool behavior."""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from etw_analyzer.tools.dpc_isr import get_dpc_per_cpu, get_dpc_summary
from etw_analyzer.trace_state import TraceData, clear_traces, register_trace


class _FakeSymbolizer:
    def __init__(self, mapping):
        self._mapping = mapping

    def bulk_resolve(self, addrs):
        return {int(a): self._mapping.get(int(a), "") for a in addrs}


@pytest.fixture(autouse=True)
def clean_trace_registry():
    clear_traces()
    yield
    clear_traces()


def test_get_dpc_per_cpu_uses_native_structured_events_without_raw_text():
    trace = TraceData(
        trace_id="trace_native_dpc",
        etl_path=Path("C:\\traces\\native_dpc.etl"),
        export_dir=Path("C:\\traces\\.etw-export-native_dpc"),
        raw_csv={
            "_native_dpc_events": pd.DataFrame([
                {"TimeStamp": 150, "InitialTime": 50, "Routine": 0x1, "CPU": 2},
                {"TimeStamp": 500, "InitialTime": 200, "Routine": 0x1, "CPU": 5},
            ]),
        },
        duration_seconds=1.0,
        timestamp_frequency=1_000_000,
        cpu_count=8,
    )
    trace.symbolizer = _FakeSymbolizer({0x1: "mlx5.sys!DpcRoutine+0x0"})
    register_trace(trace)

    output = get_dpc_per_cpu("trace_native_dpc", module_filter="mlx5.sys")

    assert "DPC Per-CPU Usage" in output
    assert "mlx5.sys" in output
    assert "| 2 |" in output
    assert "| 5 |" in output
    assert "400" in output


def _dotnet_dpc_trace(trace_id: str, *, with_metadata: bool = True) -> TraceData:
    """Build a trace whose ``dpc_isr`` slot uses the dotnet sidecar schema
    (``Kind`` / ``Routine`` / ``ElapsedMicros``) — the shape that previously
    triggered the silent-swallow / wrong-message bug (#13)."""
    raw_csv = {
        "dpc_isr": pd.DataFrame([
            {"Kind": "DPC", "Routine": 0xFFFFF80000001000, "ElapsedMicros": 3.0, "CPU": 0},
            {"Kind": "DPC", "Routine": 0xFFFFF80000001000, "ElapsedMicros": 12.0, "CPU": 1},
            {"Kind": "ISR", "Routine": 0xFFFFF80000002000, "ElapsedMicros": 1.0, "CPU": 0},
        ]),
    }
    if with_metadata:
        raw_csv["trace_metadata"] = pd.DataFrame([
            {"DurationSeconds": 11.6881731, "PerfFreq": 10_000_000}
        ])
    return TraceData(
        trace_id=trace_id,
        etl_path=Path(rf"C:\traces\{trace_id}.etl"),
        export_dir=Path(rf"C:\traces\.etw-export-{trace_id}"),
        mode="native",
        raw_csv=raw_csv,
    )


def test_get_dpc_summary_dotnet_schema_with_none_symbolizer_returns_histogram():
    """#13/#16: dotnet ``dpc_isr`` (ElapsedMicros) + ``symbolizer=None`` must
    yield a non-empty histogram with ``module=unknown`` — NOT the misleading
    "No DPC/ISR data available" message."""
    trace = _dotnet_dpc_trace("trace_dotnet_dpc")
    trace.symbolizer = None
    register_trace(trace)

    output = get_dpc_summary("trace_dotnet_dpc")

    assert "No DPC/ISR data" not in output
    assert "DPC/ISR Duration Summary" in output
    assert "unknown" in output
    # All three DPC events must be counted.
    assert "| 3 |" in output


def test_get_dpc_summary_surfaces_resolve_symbols_when_aggregation_raises(monkeypatch):
    """#13: a failure inside aggregation must be logged and surfaced as an
    actionable "call resolve_symbols" message — never the false
    "re-collect with GeneralProfile" advice — when DPC rows are present."""
    trace = _dotnet_dpc_trace("trace_dpc_raises")
    trace.symbolizer = None
    register_trace(trace)

    def _boom(_trace):
        raise RuntimeError("symbolizer exploded")

    monkeypatch.setattr("etw_analyzer.tools.dpc_isr.aggregate_dpc_isr", _boom)

    with pytest.raises(ValueError) as excinfo:
        get_dpc_summary("trace_dpc_raises")

    message = str(excinfo.value)
    assert "resolve_symbols" in message
    assert "GeneralProfile" not in message
    # The row count (3 events) must be reported so the user knows data exists.
    assert "3" in message


def test_get_dpc_summary_no_dpc_rows_keeps_collection_guidance():
    """When the trace genuinely has no DPC events, the message should still
    guide the user to collect with a DPC-capable profile."""
    trace = TraceData(
        trace_id="trace_no_dpc",
        etl_path=Path(r"C:\traces\no_dpc.etl"),
        export_dir=Path(r"C:\traces\.etw-export-no_dpc"),
        mode="native",
        raw_csv={},
    )
    trace.symbolizer = None
    register_trace(trace)

    with pytest.raises(ValueError) as excinfo:
        get_dpc_summary("trace_no_dpc")

    message = str(excinfo.value)
    assert "No DPC/ISR data" in message
    assert "GeneralProfile" in message


def test_get_dpc_per_cpu_uses_metadata_duration_when_duration_seconds_none():
    """#4: per-CPU % must use ``trace_metadata.DurationSeconds`` when
    ``trace.duration_seconds`` is None, keeping percentages bounded by ~100%
    instead of inflating ~11x against a 1-second default denominator."""
    trace = TraceData(
        trace_id="trace_pct",
        etl_path=Path(r"C:\traces\pct.etl"),
        export_dir=Path(r"C:\traces\.etw-export-pct"),
        mode="native",
        raw_csv={
            "dpc_isr": pd.DataFrame([
                {"Kind": "DPC", "Routine": 0xFFFFF80000001000,
                 "ElapsedMicros": 3_144_991.0, "CPU": 0},
            ]),
            "trace_metadata": pd.DataFrame([
                {"DurationSeconds": 11.6881731, "PerfFreq": 10_000_000}
            ]),
        },
    )
    trace.symbolizer = None
    assert trace.duration_seconds is None
    register_trace(trace)

    output = get_dpc_per_cpu("trace_pct")

    # 3,144,991us / 11,688,173us = 26.9% — sane, NOT 278.7%/314%.
    assert "26.9" in output
    # Guard against the old inflated value reappearing.
    assert "314" not in output
    assert "278.7" not in output
