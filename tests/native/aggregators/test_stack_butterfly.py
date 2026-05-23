"""Tests for the stack_butterfly aggregator (stacks + stacks_callers)."""

from __future__ import annotations

import types

import pandas as pd

from etw_analyzer.native.event_store import EventStoreTimebase, NativeEventStoreWriter
from etw_analyzer.native.aggregators.stack_butterfly import (
    _split_label,
    aggregate_stack_butterfly,
    aggregate_stack_callers,
    aggregate_stack_data_from_event_store,
    ensure_stack_aggregates,
)
from etw_analyzer.trace_state import TraceData


class _FakeSymbolizer:
    def __init__(self, mapping):
        self._mapping = mapping

    def bulk_resolve(self, addrs):
        return {int(a): self._mapping.get(int(a), "") for a in addrs}


def _make_trace(rows, sym):
    df = pd.DataFrame(rows)
    return types.SimpleNamespace(
        dumper_df=df,
        raw_csv={},
        symbolizer=sym,
        duration_seconds=1.0,
    )


class TestSplitLabel:
    def test_with_offset(self):
        assert _split_label("a.sys!Foo+0xabc") == ("a.sys", "Foo")

    def test_without_offset(self):
        assert _split_label("a.sys!Foo") == ("a.sys", "Foo")

    def test_unknown(self):
        assert _split_label("a.sys+0x42") == ("a.sys", "")


class TestAggregateStackButterfly:
    def test_empty(self):
        df = pd.DataFrame()
        trace = types.SimpleNamespace(dumper_df=df, raw_csv={}, symbolizer=_FakeSymbolizer({}))
        assert aggregate_stack_butterfly(trace) is None

    def test_no_stack_column(self):
        df = pd.DataFrame([{"Weight": 1}])
        trace = types.SimpleNamespace(dumper_df=df, raw_csv={}, symbolizer=_FakeSymbolizer({}))
        assert aggregate_stack_butterfly(trace) is None

    def test_no_symbolizer(self):
        df = pd.DataFrame([{"Stack": (0x1,), "Weight": 1}])
        trace = types.SimpleNamespace(dumper_df=df, raw_csv={}, symbolizer=None)
        assert aggregate_stack_butterfly(trace) is None

    def test_simple_butterfly(self):
        # Two samples, one stack each. Stack A: leaf=A, parent=B.
        # Stack B: leaf=C, parent=B.
        sym = _FakeSymbolizer({
            0xA: "m1.sys!A+0x0",
            0xB: "m1.sys!B+0x0",
            0xC: "m2.sys!C+0x0",
        })
        rows = [
            {"Stack": (0xA, 0xB), "Weight": 1},
            {"Stack": (0xC, 0xB), "Weight": 1},
        ]
        trace = _make_trace(rows, sym)
        result = aggregate_stack_butterfly(trace)
        assert result is not None
        # Three unique frames: A, B, C
        funcs = set(zip(result["Module"], result["Function"]))
        assert ("m1.sys", "A") in funcs
        assert ("m1.sys", "B") in funcs
        assert ("m2.sys", "C") in funcs

        # Inclusive[B] should be 2 (in both stacks). Exclusive[B] = 0
        # (never the leaf).
        b_row = result[(result["Module"] == "m1.sys") & (result["Function"] == "B")].iloc[0]
        assert b_row["Inclusive"] == 2
        assert b_row["Exclusive"] == 0

        # Exclusive[A] = 1 (leaf of one stack).
        a_row = result[(result["Module"] == "m1.sys") & (result["Function"] == "A")].iloc[0]
        assert a_row["Inclusive"] == 1
        assert a_row["Exclusive"] == 1

    def test_cached_list_and_ndarray_stacks(self):
        import numpy as np

        sym = _FakeSymbolizer({
            0xA: "m1.sys!A+0x0",
            0xB: "m1.sys!B+0x0",
            0xC: "m2.sys!C+0x0",
        })
        rows = [
            {"Stack": [0xA, 0xB], "Weight": 1},
            {"Stack": np.array([0xC, 0xB], dtype="uint64"), "Weight": 1},
        ]
        trace = _make_trace(rows, sym)

        result = aggregate_stack_butterfly(trace)

        assert result is not None
        funcs = set(zip(result["Module"], result["Function"]))
        assert ("m1.sys", "A") in funcs
        assert ("m2.sys", "C") in funcs
        assert ("m1.sys", "B") in funcs


class TestAggregateStackCallers:
    def test_empty(self):
        df = pd.DataFrame()
        trace = types.SimpleNamespace(dumper_df=df, raw_csv={}, symbolizer=_FakeSymbolizer({}))
        assert aggregate_stack_callers(trace) is None

    def test_caller_edges(self):
        # Stack: leaf=A, parent=B, grandparent=C → two edges A→B and B→C.
        sym = _FakeSymbolizer({
            0xA: "m.sys!A+0x0",
            0xB: "m.sys!B+0x0",
            0xC: "m.sys!C+0x0",
        })
        rows = [
            {"Stack": (0xA, 0xB, 0xC), "Weight": 1},
        ]
        trace = _make_trace(rows, sym)
        result = aggregate_stack_callers(trace)
        assert result is not None
        # Two caller edges
        edges = set(
            (r["Target_Function"], r["Caller_Function"])
            for _, r in result.iterrows()
        )
        assert ("A", "B") in edges
        assert ("B", "C") in edges

    def test_self_and_callee_edges(self):
        sym = _FakeSymbolizer({
            0xA: "m.sys!A+0x0",
            0xB: "m.sys!B+0x0",
            0xC: "m.sys!C+0x0",
        })
        rows = [
            {"Stack": [0xA, 0xB, 0xC], "Weight": 2},
        ]
        trace = _make_trace(rows, sym)

        result = aggregate_stack_callers(trace)

        assert result is not None
        directions = set(result["Direction"])
        assert {"self", "caller", "callee"}.issubset(directions)
        self_rows = result[result["Direction"] == "self"]
        assert {r["Target_Function"] for _, r in self_rows.iterrows()} == {"A", "B", "C"}
        callee_edges = set(
            (r["Target_Function"], r["Caller_Function"])
            for _, r in result[result["Direction"] == "callee"].iterrows()
        )
        assert ("B", "A") in callee_edges
        assert ("C", "B") in callee_edges


def _make_event_store_trace(tmp_path, rows, sym=None):
    export_dir = tmp_path / ".etw-export-stack"
    writer = NativeEventStoreWriter(
        export_dir,
        run_id="stack-store",
        timebase=EventStoreTimebase(qpc_origin=1_000, perf_freq=1_000_000),
        staging=False,
        max_rows_per_part=1,
    )
    writer.append(
        "image",
        {
            "EventSequence": 1,
            "TimeStampQpc": 1_000,
            "CPU": 0,
            "ProcessId": 4,
            "ImageBase": 0xA000,
            "ImageSize": 0x1000,
            "FileName": r"C:\Windows\System32\drivers\m1.sys",
            "Type": "DCStart",
        },
    )
    writer.append(
        "image",
        {
            "EventSequence": 2,
            "TimeStampQpc": 1_000,
            "CPU": 0,
            "ProcessId": 4,
            "ImageBase": 0xC000,
            "ImageSize": 0x1000,
            "FileName": r"C:\Windows\System32\drivers\m2.sys",
            "Type": "DCStart",
        },
    )
    for index, row in enumerate(rows, start=3):
        writer.append(
            "sampled_profile",
            {
                "EventSequence": index,
                "TimeStampQpc": 1_000 + index,
                "CPU": 0,
                "ProcessId": 100,
                "ThreadId": 200,
                "PayloadThreadId": 200,
                "InstructionPointer": row["Stack"][0],
                "Weight": row.get("Weight", 1),
                "ProfileWeight": row.get("ProfileWeight", row.get("Weight", 1)),
                "Stack": row["Stack"],
            },
        )
    store = writer.commit()
    trace = TraceData(
        trace_id="trace_store_stack",
        etl_path=tmp_path / "stack.etl",
        export_dir=export_dir,
        mode="native",
        raw_csv={},
        event_store=store,
    )
    trace.symbolizer = sym
    return trace


def _sort_df(df: pd.DataFrame, columns: list[str]) -> pd.DataFrame:
    return df.sort_values(columns).reset_index(drop=True)


def test_event_store_stack_aggregates_match_in_memory(tmp_path):
    sym = _FakeSymbolizer({
        0xA010: "m1.sys!A+0x0",
        0xA020: "m1.sys!B+0x0",
        0xC010: "m2.sys!C+0x0",
    })
    rows = [
        {"Stack": [0xA010, 0xA020], "Weight": 1},
        {"Stack": [0xC010, 0xA020], "Weight": 1},
        {"Stack": [0xA010, 0xA020, 0xC010], "Weight": 2},
    ]
    trace = _make_event_store_trace(tmp_path, rows, sym=sym)
    expected = _make_trace(rows, sym)

    result = aggregate_stack_data_from_event_store(trace, batch_size=1)

    assert result.warnings == []
    assert result.stacks is not None
    assert result.callers is not None
    pd.testing.assert_frame_equal(
        _sort_df(result.stacks, ["Module", "Function"]),
        _sort_df(aggregate_stack_butterfly(expected), ["Module", "Function"]),
        check_dtype=False,
    )
    pd.testing.assert_frame_equal(
        _sort_df(result.callers, [
            "Target_Module", "Target_Function", "Direction",
            "Caller_Module", "Caller_Function",
        ]),
        _sort_df(aggregate_stack_callers(expected), [
            "Target_Module", "Target_Function", "Direction",
            "Caller_Module", "Caller_Function",
        ]),
        check_dtype=False,
    )


def test_event_store_stack_aggregates_use_image_fallback(tmp_path):
    rows = [{"Stack": [0xA010, 0xA020], "Weight": 1}]
    trace = _make_event_store_trace(tmp_path, rows, sym=None)

    result = aggregate_stack_data_from_event_store(trace, batch_size=1)

    assert result.stacks is not None
    assert set(result.stacks["Module"]) == {"m1.sys"}
    assert set(result.stacks["Function"]) == {""}


def test_ensure_stack_aggregates_updates_raw_csv_and_cache(tmp_path):
    sym = _FakeSymbolizer({
        0xA010: "m1.sys!A+0x0",
        0xA020: "m1.sys!B+0x0",
    })
    rows = [{"Stack": [0xA010, 0xA020], "Weight": 1}]
    trace = _make_event_store_trace(tmp_path, rows, sym=sym)

    result = ensure_stack_aggregates(trace)

    assert result.stacks is not None
    assert result.callers is not None
    assert "stacks" in trace.raw_csv
    assert "stacks_callers" in trace.raw_csv
    assert (trace.export_dir / "stacks.parquet").exists()
    assert (trace.export_dir / "stacks_callers.parquet").exists()
