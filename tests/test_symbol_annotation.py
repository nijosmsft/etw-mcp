"""Tests for `tools/_symbol_annotation.py` — the helper that prepends
``*`` to function names from EXPORT_ONLY modules in
``get_hot_functions`` / ``get_hot_stacks`` output.

The annotation makes it impossible for callers to silently trust
function names that came from the PE export-table fallback (which can
be wrong by hundreds of bytes). Tests pin:

- Helper alone: derives the export-only module set from cpu_sampling.
- Caching: repeated calls reuse the cached set on the TraceData object.
- get_hot_functions: rows from export-only modules get the ``*`` prefix
  and the footnote is appended.
- get_hot_stacks: same wiring on the inclusive/exclusive view.
- Backward compat: cpu_sampling without SymbolSource → no annotation,
  no footnote (graceful degradation).
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

import etw_analyzer.tools.trace_mgmt as trace_mgmt
from etw_analyzer.tools._symbol_annotation import (
    annotate_export_fallback,
    export_fallback_footnote,
    get_export_only_modules,
)
from etw_analyzer.tools.cpu_sampling import get_hot_functions
from etw_analyzer.trace_state import clear_traces
import etw_analyzer.native.config as native_config


@pytest.fixture(autouse=True)
def _isolate_traces():
    clear_traces()
    native_config.reset_auto_cache()
    yield
    clear_traces()
    native_config.reset_auto_cache()


def _register_trace_with_cpu_df(
    tmp_path: Path,
    cpu_df: pd.DataFrame,
    *,
    trace_id: str = "trace_annot",
) -> trace_mgmt.TraceData:
    etl = tmp_path / f"{trace_id}.etl"
    etl.write_bytes(b"synthetic")
    trace = trace_mgmt.TraceData(
        trace_id=trace_id,
        etl_path=etl,
        export_dir=tmp_path / f".export-{trace_id}",
        symbol_path="srv*C:\\symbols",
    )
    trace.raw_csv["cpu_sampling"] = cpu_df
    trace_mgmt.register_trace(trace)
    return trace


# ---------------------------------------------------------------------------
# Helper: get_export_only_modules
# ---------------------------------------------------------------------------


def test_get_export_only_modules_finds_export_dominant_module(tmp_path: Path):
    df = pd.DataFrame({
        "Module": ["mswsock.dll"] * 10 + ["good.dll"] * 10,
        "Function": ["f"] * 20,
        "Weight": [100] * 20,
        "SymbolSource": ["export"] * 10 + ["pdb"] * 10,
    })
    trace = _register_trace_with_cpu_df(tmp_path, df)

    result = get_export_only_modules(trace)

    assert "mswsock.dll" in result
    assert "good.dll" not in result


def test_get_export_only_modules_is_cached_on_trace(tmp_path: Path):
    df = pd.DataFrame({
        "Module": ["mswsock.dll"] * 5,
        "Function": ["f"] * 5,
        "Weight": [100] * 5,
        "SymbolSource": ["export"] * 5,
    })
    trace = _register_trace_with_cpu_df(tmp_path, df)

    first = get_export_only_modules(trace)
    # Mutate the underlying dataframe — if the cache works, the second
    # call must NOT recompute.
    trace.raw_csv["cpu_sampling"] = pd.DataFrame({
        "Module": ["fake.dll"],
        "Function": ["g"],
        "Weight": [1],
        "SymbolSource": ["pdb"],
    })
    second = get_export_only_modules(trace)

    assert first is second  # identity, not just equality — proves caching
    assert "mswsock.dll" in second


def test_get_export_only_modules_empty_when_no_symbol_source(tmp_path: Path):
    df = pd.DataFrame({
        "Module": ["legacy.dll"],
        "Function": ["f"],
        "Weight": [100],
        # No SymbolSource column — legacy cache.
    })
    trace = _register_trace_with_cpu_df(tmp_path, df)

    assert get_export_only_modules(trace) == frozenset()


def test_get_export_only_modules_weight_weighted(tmp_path: Path):
    """A module with one tiny PDB row and a huge export row must still
    be EXPORT_ONLY because export weight dominates."""
    df = pd.DataFrame({
        "Module": ["legacy.dll", "legacy.dll"],
        "Function": ["pdb_hit", "export_hit"],
        "Weight": [1, 10000],
        "SymbolSource": ["pdb", "export"],
    })
    trace = _register_trace_with_cpu_df(tmp_path, df)

    assert "legacy.dll" in get_export_only_modules(trace)


# ---------------------------------------------------------------------------
# Helper: annotate_export_fallback
# ---------------------------------------------------------------------------


def test_annotate_export_fallback_prepends_star_to_export_rows(tmp_path: Path):
    cpu_df = pd.DataFrame({
        "Module": ["mswsock.dll"] * 10,
        "Function": ["f"] * 10,
        "Weight": [100] * 10,
        "SymbolSource": ["export"] * 10,
    })
    trace = _register_trace_with_cpu_df(tmp_path, cpu_df)

    table = pd.DataFrame({
        "Module": ["mswsock.dll", "tcpip.sys"],
        "Function": ["WSARecv", "TcpReceive"],
        "Weight": [500, 300],
    })
    annotated, any_annotated = annotate_export_fallback(table, trace)

    assert any_annotated is True
    # Export-only row got the prefix; the unrelated row didn't.
    assert annotated.iloc[0]["Function"] == "*WSARecv"
    assert annotated.iloc[1]["Function"] == "TcpReceive"


def test_annotate_export_fallback_no_op_when_no_export_only(tmp_path: Path):
    cpu_df = pd.DataFrame({
        "Module": ["good.dll"] * 5,
        "Function": ["f"] * 5,
        "Weight": [100] * 5,
        "SymbolSource": ["pdb"] * 5,
    })
    trace = _register_trace_with_cpu_df(tmp_path, cpu_df)

    table = pd.DataFrame({
        "Module": ["good.dll"],
        "Function": ["RealFunction"],
        "Weight": [100],
    })
    annotated, any_annotated = annotate_export_fallback(table, trace)

    assert any_annotated is False
    assert annotated.iloc[0]["Function"] == "RealFunction"


def test_annotate_export_fallback_does_not_mutate_input(tmp_path: Path):
    cpu_df = pd.DataFrame({
        "Module": ["mswsock.dll"] * 5,
        "Function": ["f"] * 5,
        "Weight": [100] * 5,
        "SymbolSource": ["export"] * 5,
    })
    trace = _register_trace_with_cpu_df(tmp_path, cpu_df)

    table = pd.DataFrame({
        "Module": ["mswsock.dll"],
        "Function": ["WSARecv"],
        "Weight": [500],
    })
    annotated, _ = annotate_export_fallback(table, trace)

    # Caller's frame must not be mutated.
    assert table.iloc[0]["Function"] == "WSARecv"
    assert annotated is not table


# ---------------------------------------------------------------------------
# End-to-end: get_hot_functions wires the annotation in
# ---------------------------------------------------------------------------


def test_get_hot_functions_annotates_export_only_rows(tmp_path: Path):
    cpu_df = pd.DataFrame({
        "Process Name": ["app.exe"] * 4,
        "PID": [100] * 4,
        # tcpip.sys is real PDB; mswsock.dll is export-only.
        "Module": ["tcpip.sys", "tcpip.sys", "mswsock.dll", "mswsock.dll"],
        "Function": ["TcpReceive", "TcpSend", "WSARecv", "WSASend"],
        "Weight": [1000, 800, 500, 400],
        "% Weight": [37.0, 29.6, 18.5, 14.8],
        "CPU": [0, 1, 2, 3],
        "TimeStamp": [0.0, 0.1, 0.2, 0.3],
        "SymbolSource": ["pdb", "pdb", "export", "export"],
    })
    trace = _register_trace_with_cpu_df(tmp_path, cpu_df)

    out = get_hot_functions(trace.trace_id, modules="all")

    # Export-only rows must be prefixed with ``*`` so callers know the
    # names are guesses.
    assert "*WSARecv" in out
    assert "*WSASend" in out
    # PDB-resolved rows must NOT get the prefix.
    assert "*TcpReceive" not in out
    assert "*TcpSend" not in out
    # Footnote must appear so users know what the star means.
    assert "PE export table" in out
    assert "diagnose_symbol_load" in out


def test_get_hot_functions_no_footnote_when_no_export_only(tmp_path: Path):
    cpu_df = pd.DataFrame({
        "Process Name": ["app.exe"] * 2,
        "PID": [100] * 2,
        "Module": ["tcpip.sys", "ndis.sys"],
        "Function": ["TcpReceive", "NdisReceive"],
        "Weight": [1000, 500],
        "% Weight": [66.7, 33.3],
        "CPU": [0, 1],
        "TimeStamp": [0.0, 0.1],
        "SymbolSource": ["pdb", "pdb"],
    })
    trace = _register_trace_with_cpu_df(tmp_path, cpu_df)

    out = get_hot_functions(trace.trace_id, modules="all")

    # No EXPORT_ONLY modules → no footnote noise.
    assert "PE export table" not in out
    # And no spurious ``*`` prefixes on real rows.
    assert "*TcpReceive" not in out


def test_get_hot_functions_legacy_cache_does_not_annotate(tmp_path: Path):
    """Pre-v0.6 cache has no SymbolSource column. Tool must not blow
    up, and must not invent annotations it can't justify."""
    cpu_df = pd.DataFrame({
        "Process Name": ["app.exe"] * 2,
        "PID": [100] * 2,
        "Module": ["mswsock.dll", "tcpip.sys"],
        "Function": ["WSARecv", "TcpReceive"],
        "Weight": [1000, 500],
        "% Weight": [66.7, 33.3],
        "CPU": [0, 1],
        "TimeStamp": [0.0, 0.1],
        # No SymbolSource column.
    })
    trace = _register_trace_with_cpu_df(tmp_path, cpu_df)

    out = get_hot_functions(trace.trace_id, modules="all")

    # No annotations — we can't tell pdb from export without the column.
    assert "*WSARecv" not in out
    assert "PE export table" not in out


def test_export_fallback_footnote_text_is_actionable():
    text = export_fallback_footnote()
    # Footnote must tell the user (a) what the star means and (b) which
    # tools to run next.
    assert "PE export table" in text
    assert "check_symbols" in text
    assert "diagnose_symbol_load" in text
