"""Tests for the stack_butterfly aggregator (stacks + stacks_callers)."""

from __future__ import annotations

import types

import pandas as pd

from etw_analyzer.native.aggregators.stack_butterfly import (
    _split_label,
    aggregate_stack_butterfly,
    aggregate_stack_callers,
)


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
