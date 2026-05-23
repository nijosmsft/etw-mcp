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


def _make_trace(dpc_rows, symbolizer=None, duration_seconds=10.0, qpc_hz=10_000_000):
    raw_csv = {}
    if dpc_rows:
        raw_csv["_native_dpc_events"] = pd.DataFrame(dpc_rows)
    trace = types.SimpleNamespace(
        raw_csv=raw_csv,
        symbolizer=symbolizer,
        duration_seconds=duration_seconds,
    )
    trace.qpc_frequency_hz = qpc_hz
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
