"""Regression tests for export_analysis/analyze filter_query (Bug D).

Root cause: analyze() and export_analysis() had no filter_query parameter.
FastMCP silently drops unknown tool arguments, so any filter_query a client
sent was ignored and the functions returned unfiltered output every time.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from etw_analyzer.tools.summary import analyze, export_analysis
from etw_analyzer.trace_state import TraceData, clear_traces, register_trace


@pytest.fixture(autouse=True)
def _clean_registry():
    clear_traces()
    yield
    clear_traces()


def _make_cpu_sampling_df() -> pd.DataFrame:
    """Synthetic cpu_sampling with three distinct modules."""
    return pd.DataFrame([
        {"Module": "tcpip.sys",       "Function": "TcpReceiveSegment",   "Weight": 500},
        {"Module": "ntoskrnl.exe",    "Function": "KiRetireDpcList",      "Weight": 300},
        {"Module": "echo_server.exe", "Function": "ServerWorker",         "Weight": 100},
    ])


def _register_trace() -> str:
    trace = TraceData(
        trace_id="trace_summary_filter",
        etl_path=Path(r"C:\traces\filter_test.etl"),
        export_dir=Path(r"C:\traces\.etw-export-filter_test"),
        raw_csv={"cpu_sampling": _make_cpu_sampling_df()},
        duration_seconds=10.0,
    )
    trace._dumper_ready.set()
    register_trace(trace)
    return trace.trace_id


class TestAnalyzeFilterQuery:
    """analyze() filter_query regression tests."""

    def test_no_filter_includes_default_hot_modules(self):
        tid = _register_trace()
        out = analyze(tid)
        # tcpip.sys and ntoskrnl.exe are both in _DEFAULT_HOT_MODULES
        assert "tcpip.sys" in out
        assert "ntoskrnl.exe" in out

    def test_no_filter_excludes_non_networking_module(self):
        tid = _register_trace()
        out = analyze(tid)
        # echo_server.exe is not in _DEFAULT_HOT_MODULES
        assert "echo_server.exe" not in out

    def test_filter_query_narrows_to_matching_module(self):
        tid = _register_trace()
        out = analyze(tid, filter_query="tcpip")
        assert "tcpip.sys" in out
        # ntoskrnl.exe does not match "tcpip"
        assert "ntoskrnl.exe" not in out

    def test_filter_query_can_target_non_default_module(self):
        tid = _register_trace()
        # echo_server.exe is outside the default hot-module set;
        # filter_query must be able to reach it
        out = analyze(tid, filter_query="echo_server")
        assert "echo_server.exe" in out
        assert "tcpip.sys" not in out

    def test_filter_query_result_differs_from_unfiltered(self):
        tid = _register_trace()
        out_all = analyze(tid)
        out_filtered = analyze(tid, filter_query="tcpip")
        assert out_filtered != out_all

    def test_filter_query_reflected_in_section_header(self):
        tid = _register_trace()
        out = analyze(tid, filter_query="tcpip")
        # Section header must indicate the active filter
        assert "filter: tcpip" in out

    def test_no_filter_shows_networking_stack_header(self):
        tid = _register_trace()
        out = analyze(tid)
        assert "networking stack" in out


class TestExportAnalysisFilterQuery:
    """export_analysis() filter_query regression tests."""

    def test_filter_query_forwarded_to_analysis(self, tmp_path):
        tid = _register_trace()
        out_path = str(tmp_path / "analysis.md")
        export_analysis(tid, output_path=out_path, filter_query="tcpip")
        content = Path(out_path).read_text(encoding="utf-8")
        assert "tcpip.sys" in content
        assert "ntoskrnl.exe" not in content

    def test_no_filter_writes_full_result(self, tmp_path):
        tid = _register_trace()
        out_path = str(tmp_path / "analysis_full.md")
        export_analysis(tid, output_path=out_path)
        content = Path(out_path).read_text(encoding="utf-8")
        assert "tcpip.sys" in content
        assert "ntoskrnl.exe" in content

    def test_filtered_file_differs_from_unfiltered_file(self, tmp_path):
        tid = _register_trace()
        path_all = str(tmp_path / "all.md")
        path_filtered = str(tmp_path / "filtered.md")
        export_analysis(tid, output_path=path_all)
        export_analysis(tid, output_path=path_filtered, filter_query="tcpip")
        assert Path(path_all).read_text(encoding="utf-8") != Path(path_filtered).read_text(encoding="utf-8")

    def test_export_returns_path_string(self, tmp_path):
        tid = _register_trace()
        out_path = str(tmp_path / "ret.md")
        result = export_analysis(tid, output_path=out_path, filter_query="tcpip")
        assert "Analysis exported to" in result
        assert "ret.md" in result
