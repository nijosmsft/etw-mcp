"""Tests for DPC/ISR tool behavior."""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from etw_analyzer.tools.dpc_isr import get_dpc_per_cpu
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
