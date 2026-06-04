"""Tests for the v0.6 ``extra_symbol_paths`` kwarg on load_trace /
check_symbols / resolve_symbols.

Bug 62 was: ``symbol_path`` was the only way to override the
``_NT_SYMBOL_PATH`` env var, and it CLOBBERED the env var entirely.
Users who wanted to add a single local build directory had to copy
the full env var contents into their tool call - and most just
overrode with the local path and lost their symbol server.

The fix adds an ``extra_symbol_paths`` kwarg that is APPENDED to
whichever base path was chosen, so callers can extend without losing.
"""

from __future__ import annotations

import os
from pathlib import Path

import pandas as pd
import pytest

import etw_analyzer.tools.trace_mgmt as trace_mgmt
from etw_analyzer.tools.trace_mgmt import _resolve_sym_path
from etw_analyzer.trace_state import clear_traces
import etw_analyzer.native.config as native_config


@pytest.fixture(autouse=True)
def _isolate_traces():
    clear_traces()
    native_config.reset_auto_cache()
    yield
    clear_traces()
    native_config.reset_auto_cache()


@pytest.fixture
def env_no_symbol_path(monkeypatch):
    """Ensure _NT_SYMBOL_PATH is unset for tests that care about the
    'no env var' branch."""
    monkeypatch.delenv("_NT_SYMBOL_PATH", raising=False)
    yield


@pytest.fixture
def env_symbol_path(monkeypatch):
    monkeypatch.setenv(
        "_NT_SYMBOL_PATH",
        "srv*C:\\symbols*https://msdl.microsoft.com/download/symbols",
    )
    yield "srv*C:\\symbols*https://msdl.microsoft.com/download/symbols"


# ---------------------------------------------------------------------------
# _resolve_sym_path matrix
# ---------------------------------------------------------------------------


def test_resolve_sym_path_returns_none_when_nothing_set(env_no_symbol_path):
    assert _resolve_sym_path(None, None) is None


def test_resolve_sym_path_uses_env_var_when_no_args(env_symbol_path):
    assert _resolve_sym_path(None, None) == env_symbol_path


def test_resolve_sym_path_symbol_path_replaces_env(env_symbol_path):
    """Pre-v0.6 contract: passing symbol_path clobbers the env var."""
    result = _resolve_sym_path("srv*D:\\custom", None)
    assert result == "srv*D:\\custom"
    # Env var must NOT leak into the output.
    assert "C:\\symbols" not in result


def test_resolve_sym_path_extra_paths_append_to_env(env_symbol_path):
    """The new path: env var stays, extra is appended."""
    result = _resolve_sym_path(None, ["C:\\build\\Release"])
    assert result == f"{env_symbol_path};C:\\build\\Release"


def test_resolve_sym_path_extra_paths_append_to_symbol_path(env_symbol_path):
    result = _resolve_sym_path("srv*D:\\custom", ["C:\\build\\Release"])
    assert result == "srv*D:\\custom;C:\\build\\Release"
    # Env var must NOT leak in.
    assert "C:\\symbols" not in result


def test_resolve_sym_path_extra_paths_only_when_no_env(env_no_symbol_path):
    result = _resolve_sym_path(None, ["C:\\build\\Release"])
    assert result == "C:\\build\\Release"


def test_resolve_sym_path_multiple_extras_are_joined(env_symbol_path):
    result = _resolve_sym_path(None, ["A", "B", "C"])
    assert result == f"{env_symbol_path};A;B;C"


def test_resolve_sym_path_strips_whitespace(env_no_symbol_path):
    result = _resolve_sym_path("  srv*D:\\custom  ", ["  C:\\build  "])
    assert result == "srv*D:\\custom;C:\\build"


def test_resolve_sym_path_ignores_none_and_empty_extras(env_symbol_path):
    result = _resolve_sym_path(None, [None, "", "   ", "C:\\real"])
    assert result == f"{env_symbol_path};C:\\real"


def test_resolve_sym_path_empty_extras_list_is_no_op(env_symbol_path):
    assert _resolve_sym_path(None, []) == env_symbol_path


# ---------------------------------------------------------------------------
# check_symbols smoke test for extra_symbol_paths
# ---------------------------------------------------------------------------


def _register_minimal_trace(
    tmp_path: Path,
    *,
    trace_id: str = "trace_extra",
    saved_symbol_path: str | None = None,
) -> trace_mgmt.TraceData:
    etl = tmp_path / f"{trace_id}.etl"
    etl.write_bytes(b"synthetic")
    trace = trace_mgmt.TraceData(
        trace_id=trace_id,
        etl_path=etl,
        export_dir=tmp_path / f".export-{trace_id}",
        symbol_path=saved_symbol_path,
    )
    trace.raw_csv["cpu_sampling"] = pd.DataFrame({
        "Module": ["a.dll"], "Function": ["f"], "Weight": [1],
        "SymbolSource": ["pdb"],
    })
    trace_mgmt.register_trace(trace)
    return trace


def test_check_symbols_extra_symbol_paths_appears_in_output(
    tmp_path: Path,
    env_symbol_path,
):
    trace = _register_minimal_trace(tmp_path, saved_symbol_path=None)

    out = trace_mgmt.check_symbols(
        trace.trace_id,
        extra_symbol_paths=[str(tmp_path / "build_outputs")],
    )

    # The extra path must appear in the reported symbol-path section.
    assert str(tmp_path / "build_outputs") in out
    # And the env-var-derived base must still be present.
    assert "C:\\symbols" in out


def test_check_symbols_without_extra_paths_behaves_as_before(
    tmp_path: Path,
    env_symbol_path,
):
    trace = _register_minimal_trace(tmp_path)
    out = trace_mgmt.check_symbols(trace.trace_id)
    assert "C:\\symbols" in out


def test_check_symbols_saved_symbol_path_replaces_env(
    tmp_path: Path,
    env_symbol_path,
):
    trace = _register_minimal_trace(
        tmp_path,
        saved_symbol_path="srv*D:\\saved",
    )
    out = trace_mgmt.check_symbols(trace.trace_id)
    # The trace's saved path replaces the env var (pre-v0.6 contract).
    assert "D:\\saved" in out


# ---------------------------------------------------------------------------
# load_trace docstring + signature
# ---------------------------------------------------------------------------


def test_load_trace_signature_includes_extra_symbol_paths():
    import inspect
    sig = inspect.signature(trace_mgmt.load_trace)
    assert "extra_symbol_paths" in sig.parameters
    # Default must be None so existing callers are unaffected.
    assert sig.parameters["extra_symbol_paths"].default is None


def test_resolve_symbols_signature_includes_extra_symbol_paths():
    import inspect
    sig = inspect.signature(trace_mgmt.resolve_symbols)
    assert "extra_symbol_paths" in sig.parameters
    assert sig.parameters["extra_symbol_paths"].default is None


def test_check_symbols_signature_includes_extra_symbol_paths():
    import inspect
    sig = inspect.signature(trace_mgmt.check_symbols)
    assert "extra_symbol_paths" in sig.parameters
    assert sig.parameters["extra_symbol_paths"].default is None
