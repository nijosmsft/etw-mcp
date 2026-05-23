"""Tests for the dpcisr aggregator (dpc_isr DataFrame + dpc_isr_raw text)."""

from __future__ import annotations

import types

import pandas as pd

from etw_analyzer.native.aggregators.dpcisr import (
    _bucket_for,
    aggregate_dpc_isr,
    build_dpc_isr_raw_text,
)


class _FakeSymbolizer:
    def __init__(self, mapping):
        self._mapping = mapping

    def bulk_resolve(self, addrs):
        return {int(a): self._mapping.get(int(a), "") for a in addrs}


def _make_trace(
    dpc_rows,
    symbolizer=None,
    duration_seconds=10.0,
    timestamp_frequency=10_000_000,
    mode="xperf",
):
    raw_csv = {}
    if dpc_rows:
        raw_csv["_native_dpc_events"] = pd.DataFrame(dpc_rows)
    trace = types.SimpleNamespace(
        raw_csv=raw_csv,
        symbolizer=symbolizer,
        duration_seconds=duration_seconds,
        timestamp_frequency=timestamp_frequency,
        mode=mode,
    )
    return trace


class TestBucketFor:
    def test_zero_us(self):
        assert _bucket_for(0) == (0, 1)

    def test_three_us(self):
        assert _bucket_for(3) == (2, 4)

    def test_one_hundred_us(self):
        assert _bucket_for(100) == (64, 128)

    def test_tail(self):
        low, high = _bucket_for(50_000_000)
        assert low == 32768


class TestAggregateDpcIsr:
    def test_empty(self):
        assert aggregate_dpc_isr(_make_trace([])) is None

    def test_simple_histogram(self):
        # Three DPC events, all on ndis.sys, with different durations.
        # qpc_hz = 10_000_000 means 1us = 10 QPC ticks.
        rows = [
            {"TimeStamp": 100, "InitialTime": 90, "Routine": 0x1, "CPU": 0},   # 1us → bucket (1,2)
            {"TimeStamp": 200, "InitialTime": 130, "Routine": 0x1, "CPU": 1},  # 7us → (4,8)
            {"TimeStamp": 1000, "InitialTime": 0, "Routine": 0x1, "CPU": 2},   # 100us → (64,128)
        ]
        sym = _FakeSymbolizer({0x1: "ndis.sys!NdisRecv+0x10"})
        trace = _make_trace(rows, symbolizer=sym)
        result = aggregate_dpc_isr(trace)
        assert result is not None
        # We should have per-module rows plus (all) rows.
        modules = set(result["Module"].unique())
        assert "ndis.sys" in modules
        assert "(all)" in modules
        ndis = result[result["Module"] == "ndis.sys"]
        # Three buckets populated
        assert (ndis["Count"] > 0).sum() == 3

    def test_unknown_routine_module(self):
        # No symbolizer → "unknown" module
        rows = [{"TimeStamp": 100, "InitialTime": 90, "Routine": 0x1, "CPU": 0}]
        trace = _make_trace(rows)  # no symbolizer
        result = aggregate_dpc_isr(trace)
        assert result is not None
        assert "unknown" in set(result["Module"].unique())

    def test_duration_uses_trace_timestamp_frequency(self):
        rows = [
            {"TimeStamp": 150, "InitialTime": 50, "Routine": 0x1, "CPU": 0},
        ]
        sym = _FakeSymbolizer({0x1: "ndis.sys!NdisRecv+0x10"})
        trace = _make_trace(rows, symbolizer=sym, timestamp_frequency=1_000_000)
        trace.qpc_frequency_hz = 10_000_000

        result = aggregate_dpc_isr(trace)

        assert result is not None
        ndis = result[result["Module"] == "ndis.sys"]
        populated = ndis[ndis["Count"] > 0].iloc[0]
        assert populated["Bucket_Low_us"] == 64
        assert populated["Bucket_High_us"] == 128

    def test_native_relative_microsecond_duration_not_qpc_scaled(self):
        rows = [
            {"TimeStamp": 150, "InitialTime": 50, "Routine": 0x1, "CPU": 0},
        ]
        sym = _FakeSymbolizer({0x1: "ndis.sys!NdisRecv+0x10"})
        trace = _make_trace(rows, symbolizer=sym, duration_seconds=1.0, mode="native")

        result = aggregate_dpc_isr(trace)

        assert result is not None
        ndis = result[result["Module"] == "ndis.sys"]
        populated = ndis[ndis["Count"] > 0].iloc[0]
        assert populated["Bucket_Low_us"] == 64
        assert populated["Bucket_High_us"] == 128


class TestBuildDpcIsrRawText:
    def test_empty(self):
        assert build_dpc_isr_raw_text(_make_trace([])) is None

    def test_per_cpu_pair_format(self):
        # One DPC on each of CPU 0, 1, 2 (max_cpu=2 → 3 pairs in line).
        rows = [
            {"TimeStamp": 100, "InitialTime": 90, "Routine": 0x1, "CPU": 0},  # 1us
            {"TimeStamp": 200, "InitialTime": 180, "Routine": 0x1, "CPU": 1},  # 2us
            {"TimeStamp": 300, "InitialTime": 280, "Routine": 0x1, "CPU": 2},  # 2us
        ]
        sym = _FakeSymbolizer({0x1: "ndis.sys!NdisRecv+0x0"})
        trace = _make_trace(rows, symbolizer=sym)
        text = build_dpc_isr_raw_text(trace)
        assert text is not None
        assert "ndis.sys" in text.lower()
        assert "Total = 3" in text
        # The trailing pair line must end with the module name so
        # network_dispatch._per_cpu_dpc_rows picks it up.
        last_pair_line = next(
            line for line in text.splitlines()
            if line.strip().endswith("ndis.sys")
        )
        # Three CPU pairs in the line — should contain three commas.
        assert last_pair_line.count(",") == 2

    def test_per_cpu_dpc_rows_parser_roundtrip(self):
        """Generated text must be parseable by network_dispatch._per_cpu_dpc_rows."""
        from etw_analyzer.tools.network_dispatch import _per_cpu_dpc_rows

        rows = [
            {"TimeStamp": 100, "InitialTime": 90, "Routine": 0x1, "CPU": 0},
            {"TimeStamp": 200, "InitialTime": 100, "Routine": 0x1, "CPU": 3},
        ]
        sym = _FakeSymbolizer({0x1: "tcpip.sys!TcpipRecv+0x0"})
        trace = _make_trace(rows, symbolizer=sym)
        text = build_dpc_isr_raw_text(trace)
        assert text is not None

        parsed = _per_cpu_dpc_rows(text)
        # Each non-zero-usec CPU should appear in the parsed output.
        cpu_set = set(r["CPU"] for r in parsed)
        # CPU 0 saw 1us, CPU 3 saw 10us — both > 0.
        assert 0 in cpu_set
        assert 3 in cpu_set

    def test_kernel_uint64_routine_addresses_resolve(self):
        """Regression: real DPC routine addresses live in the kernel half
        of the 64-bit space (``0xFFFFF806...``). The previous aggregator
        forced the Routine column through ``astype("int64")``, which
        overflowed those addresses to negative values that never matched
        any symbolized routine — so every CPU row was dropped and
        ``get_per_nic_queue_arrivals(trace_id, "mlx5.sys")`` returned
        "No DPC/ISR raw text in trace" on the VM-Server trace even
        though 23K DPC events had been decoded. See
        ``udp-perf/docs/wpr-mcp-native-etw-verification.md`` §"Residual
        Issues 3".
        """
        # Two kernel-half addresses — both > 2**63, so int64 overflows.
        ADDR_A = 0xFFFFF806B06A2E30
        ADDR_B = 0xFFFFF80643781120

        rows = [
            {"TimeStamp": 100, "InitialTime": 90, "Routine": ADDR_A, "CPU": 2},
            {"TimeStamp": 200, "InitialTime": 100, "Routine": ADDR_B, "CPU": 5},
        ]
        # Coerce the Routine column to numpy uint64 so the input mirrors
        # what the native consumer produces.
        import numpy as _np
        sym = _FakeSymbolizer({
            ADDR_A: "ntoskrnl.exe!KiDpcWorker+0x30",
            ADDR_B: "mlx5.sys+0x1120",
        })
        trace = _make_trace(rows, symbolizer=sym)
        # Force uint64 dtype on Routine.
        trace.raw_csv["_native_dpc_events"]["Routine"] = (
            trace.raw_csv["_native_dpc_events"]["Routine"].astype(_np.uint64)
        )

        text = build_dpc_isr_raw_text(trace)
        assert text is not None, "raw text must be emitted, not None"
        # Both modules must appear in the per-CPU pair lines.
        assert "ntoskrnl.exe" in text.lower()
        assert "mlx5.sys" in text.lower()

        # And the parser must pick up CPU 2 for ntoskrnl, CPU 5 for mlx5.
        from etw_analyzer.tools.network_dispatch import _per_cpu_dpc_rows
        parsed = _per_cpu_dpc_rows(text)
        mlx5_rows = [r for r in parsed if r["Module"].lower() == "mlx5.sys"]
        assert mlx5_rows, "mlx5.sys must produce per-CPU rows after uint64 fix"
        assert 5 in {r["CPU"] for r in mlx5_rows}
