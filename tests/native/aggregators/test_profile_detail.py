"""Tests for the cpu_sampling aggregator."""

from __future__ import annotations

import types

import pandas as pd
import pytest

from etw_analyzer.native.aggregators.profile_detail import (
    _split_resolved,
    aggregate_cpu_sampling,
)


class _FakeSymbolizer:
    """Minimal stand-in for ``Symbolizer.bulk_resolve``."""

    def __init__(self, mapping: dict[int, str]):
        self._mapping = mapping

    def bulk_resolve(self, addrs):
        return {int(a): self._mapping.get(int(a), "") for a in addrs}

    def bulk_resolve_with_source(self, addrs):
        # Tag every resolved label as a "pdb" source so the v0.6
        # aggregator path (SymbolSource column) gets a meaningful value
        # without requiring tests to spin up a real dbghelp instance.
        out: dict[int, tuple[str, str]] = {}
        for a in addrs:
            label = self._mapping.get(int(a), "")
            out[int(a)] = (label, "pdb" if label else "unknown")
        return out


def _make_trace(
    dumper_df,
    process_df=None,
    symbolizer=None,
    raw_csv=None,
    duration_seconds=10.0,
    cpu_count=None,
):
    """Return a tiny namespace that quacks like TraceData for these aggregators."""
    raw_csv = dict(raw_csv or {})
    if process_df is not None:
        raw_csv["_native_process_events"] = process_df
    return types.SimpleNamespace(
        dumper_df=dumper_df,
        raw_csv=raw_csv,
        symbolizer=symbolizer,
        duration_seconds=duration_seconds,
        cpu_count=cpu_count,
    )


class TestSplitResolved:
    def test_module_function_offset(self):
        assert _split_resolved("ntoskrnl.exe!KeYieldProcessor+0x42") == (
            "ntoskrnl.exe",
            "KeYieldProcessor",
        )

    def test_module_function_no_offset(self):
        assert _split_resolved("tcpip.sys!TcpipReceive") == ("tcpip.sys", "TcpipReceive")

    def test_no_function(self):
        assert _split_resolved("foo.sys+0x1234") == ("foo.sys", "")

    def test_unknown(self):
        assert _split_resolved("unknown+0x0") == ("unknown", "")

    def test_empty(self):
        assert _split_resolved("") == ("unknown", "")


class TestAggregateCpuSampling:
    def test_empty_dumper(self):
        trace = _make_trace(pd.DataFrame())
        assert aggregate_cpu_sampling(trace) is None

    def test_none_dumper(self):
        trace = _make_trace(None)
        assert aggregate_cpu_sampling(trace) is None

    def test_happy_path(self):
        # Three samples, two unique IPs, one PID.
        dumper = pd.DataFrame([
            {"TimeStamp": 1, "Process Name": "", "PID": 1000, "CPU": 0,
             "InstructionPointer": 0xAAA, "Weight": 1, "Module": "", "Function": ""},
            {"TimeStamp": 2, "Process Name": "", "PID": 1000, "CPU": 0,
             "InstructionPointer": 0xAAA, "Weight": 1, "Module": "", "Function": ""},
            {"TimeStamp": 3, "Process Name": "", "PID": 1000, "CPU": 1,
             "InstructionPointer": 0xBBB, "Weight": 1, "Module": "", "Function": ""},
        ])
        sym = _FakeSymbolizer({
            0xAAA: "ntoskrnl.exe!Func1+0x10",
            0xBBB: "tcpip.sys!Func2+0x20",
        })
        proc = pd.DataFrame([{"ProcessId": 1000, "ImageFileName": "echo_server.exe"}])
        trace = _make_trace(dumper, process_df=proc, symbolizer=sym)

        result = aggregate_cpu_sampling(trace)
        assert result is not None
        assert set(result.columns) == {"Process Name", "PID", "Weight", "% Weight", "Module", "Function", "SymbolSource"}
        assert len(result) == 2

        ntos_row = result[result["Module"] == "ntoskrnl.exe"].iloc[0]
        assert ntos_row["Function"] == "Func1"
        assert ntos_row["Weight"] == 2
        assert ntos_row["PID"] == 1000
        assert ntos_row["Process Name"] == "echo_server.exe"

        tcpip_row = result[result["Module"] == "tcpip.sys"].iloc[0]
        assert tcpip_row["Weight"] == 1

        # Percentages sum to 100.
        assert abs(result["% Weight"].sum() - 100.0) < 0.01

    def test_payload_thread_id_resolves_pid_and_process_name(self):
        dumper = pd.DataFrame([
            {"TimeStamp": 500_000, "Process Name": "", "PID": 0xFFFFFFFF, "CPU": 0,
             "InstructionPointer": 0xAAA, "PayloadThreadId": 4242, "Weight": 3,
             "Module": "", "Function": ""},
            {"TimeStamp": 600_000, "Process Name": "unknown", "PID": 0xFFFFFFFF, "CPU": 1,
             "InstructionPointer": 0xAAA, "PayloadThreadId": 4242, "Weight": 2,
             "Module": "", "Function": ""},
        ])
        raw_csv = {
            "Thread/DCStart": pd.DataFrame([
                {"TimeStamp": 0, "ThreadId": 4242, "ProcessId": 1234},
            ]),
            "Process/DCStart": pd.DataFrame([
                {"TimeStamp": 0, "ProcessId": 1234, "ImageFileName": "ring.exe"},
            ]),
        }
        sym = _FakeSymbolizer({0xAAA: "ring.exe!busy_loop+0x10"})
        trace = _make_trace(dumper, raw_csv=raw_csv, symbolizer=sym)

        result = aggregate_cpu_sampling(trace)

        assert result is not None
        assert len(result) == 1
        row = result.iloc[0]
        assert row["PID"] == 1234
        assert row["Process Name"] == "ring.exe"
        assert row["Weight"] == 5
        assert trace.dumper_df["PID"].tolist() == [1234, 1234]
        assert trace.dumper_df["Process Name"].tolist() == ["ring.exe", "ring.exe"]

    def test_no_symbolizer_keeps_existing_columns(self):
        dumper = pd.DataFrame([
            {"TimeStamp": 1, "Process Name": "myproc", "PID": 1000, "CPU": 0,
             "InstructionPointer": 0xAAA, "Weight": 1, "Module": "tcpip.sys", "Function": "F1"},
        ])
        trace = _make_trace(dumper)  # no symbolizer
        result = aggregate_cpu_sampling(trace)
        assert result is not None
        assert len(result) == 1
        # Without a symbolizer the existing Module/Function columns are
        # preserved (xperf-style fallback).
        assert result.iloc[0]["Module"] == "tcpip.sys"
        assert result.iloc[0]["Function"] == "F1"

    def test_aggregation_collapses_duplicates(self):
        # 10 samples all hitting the same (PID, Module, Function) → one row.
        rows = []
        for _ in range(10):
            rows.append({
                "TimeStamp": 1, "Process Name": "p", "PID": 1, "CPU": 0,
                "InstructionPointer": 0x1, "Weight": 1, "Module": "m.sys", "Function": "f",
            })
        sym = _FakeSymbolizer({0x1: "m.sys!f+0x0"})
        trace = _make_trace(pd.DataFrame(rows), symbolizer=sym)
        result = aggregate_cpu_sampling(trace)
        assert result is not None
        assert len(result) == 1
        assert result.iloc[0]["Weight"] == 10
        assert result.iloc[0]["% Weight"] == pytest.approx(100.0)

    def test_aggregation_prefers_profile_weight_when_present(self):
        dumper = pd.DataFrame([
            {"TimeStamp": 1, "Process Name": "p", "PID": 1, "CPU": 0,
             "InstructionPointer": 0x1, "Weight": 1, "ProfileWeight": 0x50000,
             "Module": "m.sys", "Function": "f"},
        ])
        sym = _FakeSymbolizer({0x1: "m.sys!f+0x0"})
        trace = _make_trace(dumper, symbolizer=sym)

        result = aggregate_cpu_sampling(trace)

        assert result is not None
        assert len(result) == 1
        assert result.iloc[0]["Weight"] == 0x50000

    def test_profile_weight_synthesizes_idle_when_capacity_is_reliable(self):
        dumper = pd.DataFrame([
            {"TimeStamp": 1, "Process Name": "p", "PID": 1, "CPU": 0,
             "InstructionPointer": 0x1, "Weight": 1, "ProfileWeight": 250_000,
             "Module": "m.sys", "Function": "f"},
        ])
        sym = _FakeSymbolizer({0x1: "m.sys!f+0x0"})
        trace = _make_trace(dumper, symbolizer=sym, duration_seconds=1.0, cpu_count=1)

        result = aggregate_cpu_sampling(trace)

        assert result is not None
        idle = result[result["Process Name"] == "Idle"].iloc[0]
        assert idle["PID"] == 0
        assert idle["Module"] == "<Heuristic Low Power State>"
        assert idle["Function"] == "<C3>"
        assert idle["Weight"] == 750_000
        assert result["Weight"].sum() == 1_000_000
        assert result["% Weight"].sum() == pytest.approx(100.0)

    def test_sample_count_profile_weight_does_not_synthesize_idle(self):
        dumper = pd.DataFrame([
            {"TimeStamp": 1, "Process Name": "p", "PID": 1, "CPU": 0,
             "InstructionPointer": 0x1, "Weight": 1, "ProfileWeight": 1,
             "Module": "m.sys", "Function": "f"},
        ])
        sym = _FakeSymbolizer({0x1: "m.sys!f+0x0"})
        trace = _make_trace(dumper, symbolizer=sym, duration_seconds=1.0, cpu_count=1)

        result = aggregate_cpu_sampling(trace)

        assert result is not None
        assert "Idle" not in result["Process Name"].tolist()
        assert len(result) == 1

    def test_profile_weight_does_not_synthesize_idle_without_cpu_count(self):
        dumper = pd.DataFrame([
            {"TimeStamp": 1, "Process Name": "p", "PID": 1, "CPU": 0,
             "InstructionPointer": 0x1, "Weight": 1, "ProfileWeight": 250_000,
             "Module": "m.sys", "Function": "f"},
        ])
        sym = _FakeSymbolizer({0x1: "m.sys!f+0x0"})
        trace = _make_trace(dumper, symbolizer=sym, duration_seconds=1.0)

        result = aggregate_cpu_sampling(trace)

        assert result is not None
        assert "Idle" not in result["Process Name"].tolist()
        assert len(result) == 1

    def test_profile_weight_does_not_synthesize_idle_when_observed_exceeds_capacity(self):
        dumper = pd.DataFrame([
            {"TimeStamp": 1, "Process Name": "p", "PID": 1, "CPU": 0,
             "InstructionPointer": 0x1, "Weight": 1, "ProfileWeight": 1_250_000,
             "Module": "m.sys", "Function": "f"},
        ])
        sym = _FakeSymbolizer({0x1: "m.sys!f+0x0"})
        trace = _make_trace(dumper, symbolizer=sym, duration_seconds=1.0, cpu_count=1)

        result = aggregate_cpu_sampling(trace)

        assert result is not None
        assert "Idle" not in result["Process Name"].tolist()
        assert len(result) == 1
