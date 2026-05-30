"""Regression tests for the actionable "what next" error messages in
:mod:`etw_analyzer.tools.trace_mgmt`.

These tests pin the substrings that downstream LLM-driven clients use to
recover from a failed call. The wording can evolve, but the recovery
keywords (``list_traces``, ``mode='native'``, ``mode='dotnet'``,
``WPR_MCP_MODE``, ``WPR_MCP_CSHARP_SIDECAR``, ``dotnet publish``) MUST
stay so a client model can pick the next command without round-tripping
to a human.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import etw_analyzer.parsing.wpa_exporter as wpa_exporter
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


# ---------------------------------------------------------------------------
# load_trace front-door errors
# ---------------------------------------------------------------------------


def test_load_trace_missing_file_suggests_list_traces(tmp_path: Path):
    missing = tmp_path / "does-not-exist.etl"

    result = trace_mgmt.load_trace(str(missing))

    assert "File not found" in result
    assert str(missing) in result
    # Recovery hint must name list_traces so the LLM knows the next call.
    assert "list_traces" in result


def test_load_trace_wrong_suffix_suggests_list_traces(tmp_path: Path):
    wrong = tmp_path / "trace.txt"
    wrong.write_text("not an etl")

    result = trace_mgmt.load_trace(str(wrong))

    assert "Expected .etl file" in result
    assert ".txt" in result
    assert "list_traces" in result


def test_load_trace_no_suffix_reports_no_suffix_label(tmp_path: Path):
    bare = tmp_path / "trace"
    bare.write_text("payload")

    result = trace_mgmt.load_trace(str(bare))

    # An empty suffix would be rendered as "" otherwise; the upgraded
    # error spells it out so the user can see the file lacks an extension.
    assert "Expected .etl file" in result
    assert "(no suffix)" in result


# ---------------------------------------------------------------------------
# load_trace xperf-not-found error names alternative modes
# ---------------------------------------------------------------------------


def test_load_trace_xperf_missing_lists_native_and_csharp_alternatives(
    tmp_path: Path,
    monkeypatch,
):
    etl = tmp_path / "fixture.etl"
    etl.write_bytes(b"synthetic etl payload")

    # Force xperf-not-found and force the resolved mode to "xperf" so the
    # xperf branch of the error is taken (otherwise the native/csharp
    # codepath would handle the missing-xperf condition).
    monkeypatch.setattr(trace_mgmt, "find_xperf", lambda: None)
    monkeypatch.setattr(wpa_exporter, "find_xperf", lambda: None)
    monkeypatch.setenv("WPR_MCP_MODE", "xperf")
    native_config.reset_auto_cache()

    result = trace_mgmt.load_trace(str(etl))

    assert "xperf.exe not found" in result
    # Both alternative pipelines must be named so the model can pick one.
    assert "mode='native'" in result
    assert "WPR_MCP_MODE=native" in result
    assert "mode='dotnet'" in result
    assert "WPR_MCP_CSHARP_SIDECAR" in result
    assert "dotnet publish" in result


# ---------------------------------------------------------------------------
# _native_worker_load_failed branches
# ---------------------------------------------------------------------------


def _make_worker_result(
    *,
    ok: bool = False,
    message: str = "something went wrong",
    failure_kind: str | None = None,
    stderr_tail: str = "",
    invalid_stdout_tail: str = "",
):
    return SimpleNamespace(
        ok=ok,
        message=message,
        failure_kind=failure_kind,
        stderr_tail=stderr_tail,
        invalid_stdout_tail=invalid_stdout_tail,
        aggregation_warnings=[],
    )


def test_native_worker_load_failed_default_producer_suggests_xperf():
    worker_result = _make_worker_result(
        message="native worker crashed",
        failure_kind="exit-code",
    )

    result = trace_mgmt._native_worker_load_failed(worker_result)

    assert "Native ETW worker extraction failed" in result
    assert "exit-code: native worker crashed" in result
    # The default-branch fallback is xperf.
    assert "mode='xperf'" in result
    # Sidecar-specific hints must NOT leak into the default-branch message.
    assert "dotnet publish" not in result
    assert "sidecar" not in result.lower()


def test_native_worker_load_failed_csharp_producer_suggests_rebuild_and_alternatives():
    worker_result = _make_worker_result(
        message="sidecar emitted malformed JSONL",
        failure_kind="invalid-stdout",
        invalid_stdout_tail="not-json-blob",
    )

    result = trace_mgmt._native_worker_load_failed(worker_result, producer="dotnet")

    assert ".NET sidecar ETW worker extraction failed" in result
    assert "invalid-stdout: sidecar emitted malformed JSONL" in result
    # Stale-build hint must point at the dotnet publish command and the env var.
    assert "dotnet publish" in result
    assert "WPR_MCP_CSHARP_SIDECAR" in result
    # Both fallback pipelines must be named.
    assert "mode='native'" in result
    assert "mode='xperf'" in result


def test_native_worker_load_failed_csharp_producer_non_build_failure_omits_rebuild_hint():
    """Non-build-related sidecar failures should not nag about rebuilding."""

    worker_result = _make_worker_result(
        message="cache promotion failed",
        # ``failure_kind=None`` means "no specific kind" — the message is
        # generic so the rebuild hint is misleading and must be omitted.
        failure_kind=None,
    )

    result = trace_mgmt._native_worker_load_failed(worker_result, producer="dotnet")

    assert ".NET sidecar ETW worker extraction failed" in result
    assert "cache promotion failed" in result
    assert "dotnet publish" not in result
    # The cross-pipeline fallback hint must still be present.
    assert "mode='native'" in result
    assert "mode='xperf'" in result


# ---------------------------------------------------------------------------
# resolve_symbols xperf-not-found error
# ---------------------------------------------------------------------------


def test_resolve_symbols_xperf_missing_explains_relationship_to_load_trace(
    tmp_path: Path,
    monkeypatch,
):
    """resolve_symbols still needs xperf; the error must say so without
    misleading the caller into thinking load_trace also broke."""

    # Build a minimal registered trace so require_trace() succeeds.
    etl = tmp_path / "fixture.etl"
    etl.write_bytes(b"synthetic etl payload")
    trace = trace_mgmt.TraceData(
        trace_id="trace_test_resolve_symbols",
        etl_path=etl,
        export_dir=tmp_path / ".etw-export-fixture",
        symbol_path=None,
    )
    trace_mgmt.register_trace(trace)

    monkeypatch.setattr(trace_mgmt, "find_xperf", lambda: None)
    monkeypatch.setattr(wpa_exporter, "find_xperf", lambda: None)

    result = trace_mgmt.resolve_symbols(trace.trace_id)

    assert "xperf.exe not found" in result
    # Must explain why this error matters in this specific tool.
    assert "resolve_symbols uses xperf" in result
    # Must tell the user the rest of the server still works without xperf.
    assert "mode='native'" in result
    assert "mode='dotnet'" in result
