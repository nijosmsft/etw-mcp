"""Tests for the ``## Export errors`` section in ``trace_info`` markdown.

The renamed section (previously "**Export warnings:**") makes the count
visible in the H2 header so operators can grep for ``## Export errors``
or count by section header. The same section is rendered both by
``load_trace`` (via ``_format_load_summary``) and by ``trace_info``,
which is what these tests pin.

Also pins the csharp sidecar plumbing: aggregation_warnings from the
worker result must flow through ``_register_cached_trace`` into
``trace.export_errors`` so they actually appear in the rendered
section.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pandas as pd
import pytest

from etw_analyzer.trace_state import TraceData, clear_traces, register_trace
from etw_analyzer.native.worker_supervisor import NativeWorkerResult
from etw_analyzer.tools import trace_mgmt


# ---------------------------------------------------------------------------
# Header / formatting
# ---------------------------------------------------------------------------

def _synthetic_trace(tmp_path: Path, errors: list[str]) -> TraceData:
    etl = tmp_path / "synthetic.etl"
    etl.write_bytes(b"synthetic")
    export_dir = tmp_path / "export"
    export_dir.mkdir()
    trace = TraceData(
        trace_id="trace_synthetic",
        etl_path=etl,
        export_dir=export_dir,
        symbol_path=None,
        mode="dotnet",
        raw_csv={"sampled_profile": pd.DataFrame({"CPU": [0], "Weight": [1]})},
        export_errors=list(errors),
    )
    return trace


def test_trace_info_emits_export_errors_h2_with_count(tmp_path: Path):
    clear_traces()
    try:
        trace = _synthetic_trace(
            tmp_path,
            [
                "first warning from sidecar aggregator",
                "second warning about missing dataset",
                "third notice about cache promotion",
            ],
        )
        register_trace(trace)
        out = trace_mgmt.trace_info(trace.trace_id)
    finally:
        clear_traces()

    assert "## Export errors (3)" in out
    assert "- first warning from sidecar aggregator" in out
    assert "- second warning about missing dataset" in out
    assert "- third notice about cache promotion" in out
    # The old label MUST be gone.
    assert "**Export warnings:**" not in out


def test_trace_info_omits_section_when_no_errors(tmp_path: Path):
    clear_traces()
    try:
        trace = _synthetic_trace(tmp_path, [])
        register_trace(trace)
        out = trace_mgmt.trace_info(trace.trace_id)
    finally:
        clear_traces()

    assert "## Export errors" not in out


def test_trace_info_single_error_renders_count_one(tmp_path: Path):
    clear_traces()
    try:
        trace = _synthetic_trace(tmp_path, ["lone aggregator notice"])
        register_trace(trace)
        out = trace_mgmt.trace_info(trace.trace_id)
    finally:
        clear_traces()

    assert "## Export errors (1)" in out
    assert "- lone aggregator notice" in out


# ---------------------------------------------------------------------------
# aggregation_warnings → export_errors plumbing on csharp success
# ---------------------------------------------------------------------------

def test_native_worker_result_carries_aggregation_warnings_field():
    """Pin the new field on NativeWorkerResult so the contract is explicit."""

    r = NativeWorkerResult(ok=True, message="ok")
    assert r.aggregation_warnings == []
    r2 = NativeWorkerResult(
        ok=True,
        message="ok",
        aggregation_warnings=["warning A", "warning B"],
    )
    assert r2.aggregation_warnings == ["warning A", "warning B"]


def test_csharp_dispatch_merges_aggregation_warnings_into_export_errors(tmp_path: Path):
    """The csharp success path must surface agg_result.warnings via trace.export_errors."""

    etl = tmp_path / "real.etl"
    etl.write_bytes(b"ETL\0synthetic")
    export_dir = etl.parent / f".etw-export-{etl.stem}"

    cached = {"sampled_profile": pd.DataFrame({"CPU": [0], "Weight": [1]})}

    worker_result = NativeWorkerResult(
        ok=True,
        message="dotnet sidecar completed: ok",
        export_dir=export_dir,
        aggregation_warnings=[
            "aggregator missed Foo events",
            "aggregator dropped Bar events",
        ],
    )

    clear_traces()
    try:
        with patch("etw_analyzer.native.config.resolve_mode", return_value="dotnet"), \
             patch.object(trace_mgmt, "_load_csharp_with_worker", return_value=worker_result), \
             patch.object(trace_mgmt, "_load_from_cache", side_effect=[None, cached]), \
             patch.object(trace_mgmt, "_open_native_event_store_from_cache", return_value=None), \
             patch.object(trace_mgmt, "_start_background_dumper", return_value=None), \
             patch.object(trace_mgmt, "_refresh_stack_cache_from_html", return_value=None):
            out = trace_mgmt.load_trace(str(etl), mode="dotnet")

        # The load summary should already show the H2 section with both warnings.
        assert "## Export errors (2)" in out, out
        assert "- aggregator missed Foo events" in out
        assert "- aggregator dropped Bar events" in out

        # And the same warnings must be on the TraceData itself so
        # subsequent trace_info() calls render them too.
        traces = trace_mgmt.get_loaded_traces()
        assert len(traces) == 1
        trace = traces[0]
        assert "aggregator missed Foo events" in trace.export_errors
        assert "aggregator dropped Bar events" in trace.export_errors

        info_out = trace_mgmt.trace_info(trace.trace_id)
        assert "## Export errors (2)" in info_out
    finally:
        clear_traces()


def test_csharp_dispatch_no_aggregation_warnings_no_section(tmp_path: Path):
    """When aggregation_warnings is empty the section MUST be omitted."""

    etl = tmp_path / "real.etl"
    etl.write_bytes(b"ETL\0synthetic")
    export_dir = etl.parent / f".etw-export-{etl.stem}"

    cached = {"sampled_profile": pd.DataFrame({"CPU": [0], "Weight": [1]})}

    worker_result = NativeWorkerResult(
        ok=True,
        message="dotnet sidecar completed: ok",
        export_dir=export_dir,
        aggregation_warnings=[],
    )

    clear_traces()
    try:
        with patch("etw_analyzer.native.config.resolve_mode", return_value="dotnet"), \
             patch.object(trace_mgmt, "_load_csharp_with_worker", return_value=worker_result), \
             patch.object(trace_mgmt, "_load_from_cache", side_effect=[None, cached]), \
             patch.object(trace_mgmt, "_open_native_event_store_from_cache", return_value=None), \
             patch.object(trace_mgmt, "_start_background_dumper", return_value=None), \
             patch.object(trace_mgmt, "_refresh_stack_cache_from_html", return_value=None):
            out = trace_mgmt.load_trace(str(etl), mode="dotnet")
        assert "## Export errors" not in out, out
    finally:
        clear_traces()
