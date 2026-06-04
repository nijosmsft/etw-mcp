"""Tests for the 3-category EXPORT_ONLY classification in
:func:`etw_analyzer.tools.trace_mgmt.check_symbols`.

The v0.6 rewrite splits the previous "resolved / unknown" 2-bucket view
into three honest buckets:

- ``OK`` — real PDB hits (``SymbolSource == "pdb"``) dominate.
- ``EXPORT_ONLY`` — names came from the PE export table fallback. The
  function called at the hot address could be ANY internal function
  near the export. Names are low-confidence.
- ``PARTIAL`` / ``MISSING`` — mixed or no resolution.

These tests pin the column shape, status thresholds, and the
backward-compat behaviour for pre-v0.6 parquet caches that do not have
the ``SymbolSource`` column.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

import etw_analyzer.tools.trace_mgmt as trace_mgmt
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
    trace_id: str = "trace_check_symbols",
) -> trace_mgmt.TraceData:
    """Register a minimal TraceData with the given cpu_sampling frame."""
    etl = tmp_path / f"{trace_id}.etl"
    etl.write_bytes(b"synthetic")
    trace = trace_mgmt.TraceData(
        trace_id=trace_id,
        etl_path=etl,
        export_dir=tmp_path / f".export-{trace_id}",
        symbol_path="srv*C:\\symbols*https://msdl.microsoft.com/download/symbols",
    )
    trace.raw_csv["cpu_sampling"] = cpu_df
    trace_mgmt.register_trace(trace)
    return trace


# ---------------------------------------------------------------------------
# Honest 3-category classification (SymbolSource present)
# ---------------------------------------------------------------------------


def test_check_symbols_classifies_pdb_dominant_module_as_ok(tmp_path: Path):
    df = pd.DataFrame({
        "Process Name": ["app.exe"] * 5,
        "PID": [100] * 5,
        "Weight": [100, 100, 100, 100, 100],
        "% Weight": [20.0] * 5,
        "Module": ["good.dll"] * 5,
        "Function": [f"f{i}" for i in range(5)],
        "SymbolSource": ["pdb"] * 5,
    })
    trace = _register_trace_with_cpu_df(tmp_path, df)

    out = trace_mgmt.check_symbols(trace.trace_id)

    assert "good.dll" in out
    assert "OK" in out
    assert "From PDB" in out
    assert "From Export" in out
    # Honest legend must not claim names are EXPORT_ONLY when they are not.
    assert "EXPORT_ONLY" not in out.split("**Per-Module Symbol Resolution:**")[1].split("good.dll")[1].split("\n")[0]


def test_check_symbols_classifies_export_only_module(tmp_path: Path):
    """A module whose names all came from the PE export table must be
    flagged EXPORT_ONLY so callers know not to trust the function
    names."""
    df = pd.DataFrame({
        "Process Name": ["app.exe"] * 10,
        "PID": [100] * 10,
        "Weight": [50] * 10,
        "% Weight": [10.0] * 10,
        "Module": ["mswsock.dll"] * 10,
        "Function": [f"export_guess_{i}" for i in range(10)],
        "SymbolSource": ["export"] * 10,
    })
    trace = _register_trace_with_cpu_df(tmp_path, df)

    out = trace_mgmt.check_symbols(trace.trace_id)

    assert "mswsock.dll" in out
    assert "EXPORT_ONLY" in out
    # Must point users at the diagnose_symbol_load tool for follow-up.
    assert "diagnose_symbol_load" in out
    # Summary must surface the count.
    assert "Export-only" in out


def test_check_symbols_classifies_no_pdb_no_export_as_missing(tmp_path: Path):
    df = pd.DataFrame({
        "Process Name": ["app.exe"] * 4,
        "PID": [100] * 4,
        "Weight": [25] * 4,
        "% Weight": [25.0] * 4,
        "Module": ["nopdb.sys"] * 4,
        "Function": ["Unknown"] * 4,
        "SymbolSource": ["unknown"] * 4,
    })
    trace = _register_trace_with_cpu_df(tmp_path, df)

    out = trace_mgmt.check_symbols(trace.trace_id)

    assert "nopdb.sys" in out
    assert "MISSING" in out


def test_check_symbols_classifies_mixed_module_as_partial(tmp_path: Path):
    df = pd.DataFrame({
        "Process Name": ["app.exe"] * 4,
        "PID": [100] * 4,
        "Weight": [25, 25, 25, 25],
        "% Weight": [25.0] * 4,
        "Module": ["mixed.dll"] * 4,
        "Function": ["a", "b", "c", "d"],
        # 50% pdb, 25% export, 25% unknown — neither >= 90%.
        "SymbolSource": ["pdb", "pdb", "export", "unknown"],
    })
    trace = _register_trace_with_cpu_df(tmp_path, df)

    out = trace_mgmt.check_symbols(trace.trace_id)

    assert "mixed.dll" in out
    assert "PARTIAL" in out


def test_check_symbols_weight_weighted_classification(tmp_path: Path):
    """A module with a few low-weight PDB rows and many high-weight
    export rows should be classified by total weight, not row count."""
    df = pd.DataFrame({
        "Process Name": ["app.exe"] * 4,
        "PID": [100] * 4,
        # Two PDB rows with tiny weight; two export rows that dominate.
        "Weight": [1, 1, 5000, 5000],
        "% Weight": [0.1, 0.1, 49.9, 49.9],
        "Module": ["legacy.dll"] * 4,
        "Function": ["pdb1", "pdb2", "exp1", "exp2"],
        "SymbolSource": ["pdb", "pdb", "export", "export"],
    })
    trace = _register_trace_with_cpu_df(tmp_path, df)

    out = trace_mgmt.check_symbols(trace.trace_id)

    # Total weight = 10002; pdb weight = 2 (~0.02%); export weight = 10000 (~99.98%).
    # Per spec EXPORT_ONLY requires pct_export >= 90 AND pct_pdb < 10 — both hold.
    assert "legacy.dll" in out
    assert "EXPORT_ONLY" in out


def test_check_symbols_export_only_diagnose_hint_only_when_present(tmp_path: Path):
    """If no module is EXPORT_ONLY the diagnose_symbol_load hint section
    must not appear (avoid noisy boilerplate)."""
    df = pd.DataFrame({
        "Process Name": ["app.exe"] * 3,
        "PID": [100] * 3,
        "Weight": [100, 100, 100],
        "% Weight": [33.3, 33.3, 33.3],
        "Module": ["good.dll"] * 3,
        "Function": ["a", "b", "c"],
        "SymbolSource": ["pdb", "pdb", "pdb"],
    })
    trace = _register_trace_with_cpu_df(tmp_path, df)

    out = trace_mgmt.check_symbols(trace.trace_id)

    assert "good.dll" in out
    assert "EXPORT_ONLY" not in out
    # The "Export-only modules (false-positive risk)" subsection
    # should not be emitted when there is nothing to report.
    assert "Export-only modules (false-positive risk)" not in out


# ---------------------------------------------------------------------------
# Backward-compat: cache without SymbolSource column
# ---------------------------------------------------------------------------


def test_check_symbols_legacy_cache_emits_note_and_falls_back(tmp_path: Path):
    """Pre-v0.6 parquet caches do not have the SymbolSource column.
    check_symbols must emit a clear note explaining that the honest
    3-category classification is unavailable, then fall back to the
    legacy resolved-vs-unknown view."""
    df = pd.DataFrame({
        "Process Name": ["app.exe"] * 3,
        "PID": [100] * 3,
        "Weight": [100, 100, 100],
        "% Weight": [33.3, 33.3, 33.3],
        "Module": ["legacy.dll"] * 3,
        "Function": ["a", "b", "c"],
        # No SymbolSource column.
    })
    trace = _register_trace_with_cpu_df(tmp_path, df)

    out = trace_mgmt.check_symbols(trace.trace_id)

    # Note must mention v0.6 and force=True so callers know how to fix it.
    assert "SymbolSource" in out
    assert "force=True" in out
    # Legacy column shape: % Resolved, no From PDB / From Export split.
    assert "% Resolved" in out
    assert "From PDB" not in out
    assert "From Export" not in out
