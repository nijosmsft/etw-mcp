"""Tests for the Phase 2 wait-chain walker and the get_network_wait_chain tool."""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from etw_analyzer.parsing.wait_chain import (
    INTERESTING_WAIT_REASONS,
    find_tids_for_process,
    summarize_wait_reasons,
    walk_wait_chain,
)
from etw_analyzer.tools.network_wait_chain import get_network_wait_chain
from etw_analyzer.trace_state import TraceData, clear_traces, register_trace


@pytest.fixture(autouse=True)
def clean_trace_registry():
    clear_traces()
    yield
    clear_traces()


# ---------------------------------------------------------------------------
# Synthetic CSwitch DataFrame helpers
# ---------------------------------------------------------------------------


def _cswitch_row(
    timestamp: int,
    new_tid: int,
    *,
    new_proc: str = "echo_server.exe",
    new_pid: int = 1234,
    old_tid: int = 0,
    old_proc: str = "Idle",
    old_pid: int = 0,
    wait_reason: str = "WrQueue",
    old_state: str = "Waiting",
    cpu: int = 0,
) -> dict:
    return {
        "TimeStamp": timestamp,
        "NewProcessName": new_proc,
        "NewPID": new_pid,
        "NewTID": new_tid,
        "OldProcessName": old_proc,
        "OldPID": old_pid,
        "OldTID": old_tid,
        "WaitReason": wait_reason,
        "OldState": old_state,
        "CPU": cpu,
        "NewPriority": 9,
        "OldPriority": 0,
    }


def _build_cswitch_df(rows: list[dict]) -> pd.DataFrame:
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# walker tests
# ---------------------------------------------------------------------------


class TestWalkWaitChain:
    def test_finds_target_tid_events(self):
        rows = [
            _cswitch_row(100, new_tid=5678, wait_reason="WrQueue"),
            _cswitch_row(200, new_tid=5678, wait_reason="WrQueue"),
            _cswitch_row(300, new_tid=5678, wait_reason="WrQueue"),
            _cswitch_row(400, new_tid=5678, wait_reason="WrDispatchInt"),
            _cswitch_row(500, new_tid=5678, wait_reason="WrPreempted"),
            _cswitch_row(600, new_tid=9999, wait_reason="WrQueue"),  # different TID
        ]
        df = _build_cswitch_df(rows)
        events = walk_wait_chain(df, target_tid=5678)
        assert len(events) == 5
        assert all(e["NewTID"] == 5678 for e in events)

    def test_summary_counts(self):
        rows = [
            _cswitch_row(100, new_tid=5678, wait_reason="WrQueue"),
            _cswitch_row(200, new_tid=5678, wait_reason="WrQueue"),
            _cswitch_row(300, new_tid=5678, wait_reason="WrQueue"),
            _cswitch_row(400, new_tid=5678, wait_reason="WrDispatchInt"),
            _cswitch_row(500, new_tid=5678, wait_reason="WrPreempted"),
        ]
        df = _build_cswitch_df(rows)
        events = walk_wait_chain(df, target_tid=5678)
        summary = summarize_wait_reasons(events)
        assert summary == {"WrQueue": 3, "WrDispatchInt": 1, "WrPreempted": 1}

    def test_target_tid_not_present_returns_empty(self):
        rows = [_cswitch_row(100, new_tid=9999, wait_reason="WrQueue")]
        df = _build_cswitch_df(rows)
        events = walk_wait_chain(df, target_tid=12345)
        assert events == []

    def test_empty_dataframe(self):
        # Should not raise — return [] gracefully.
        assert walk_wait_chain(pd.DataFrame(), target_tid=1) == []

    def test_none_dataframe(self):
        # Defensive: callers should be able to pass None when the trace
        # hasn't extracted CSwitch yet.
        assert walk_wait_chain(None, target_tid=1) == []  # type: ignore[arg-type]

    def test_summarize_empty(self):
        assert summarize_wait_reasons([]) == {}

    def test_interesting_reasons_constant(self):
        # Sanity check: the constant exists and contains the canonical names
        # we surface to users.
        assert "WrQueue" in INTERESTING_WAIT_REASONS
        assert "WrDispatchInt" in INTERESTING_WAIT_REASONS


class TestFindTidsForProcess:
    def test_substring_match(self):
        rows = [
            _cswitch_row(100, new_tid=100, new_proc="echo_server.exe"),
            _cswitch_row(200, new_tid=100, new_proc="echo_server.exe"),
            _cswitch_row(300, new_tid=200, new_proc="dwm.exe"),
            _cswitch_row(400, new_tid=300, new_proc="echo_server.exe"),
        ]
        df = _build_cswitch_df(rows)
        matches = find_tids_for_process(df, "echo_server")
        assert {tid for tid, _, _ in matches} == {100, 300}
        # TID 100 has 2 events, TID 300 has 1, so sorted by count desc:
        assert matches[0][0] == 100
        assert matches[0][2] == 2

    def test_case_insensitive(self):
        rows = [_cswitch_row(100, new_tid=10, new_proc="ECHO_SERVER.EXE")]
        df = _build_cswitch_df(rows)
        matches = find_tids_for_process(df, "echo")
        assert len(matches) == 1
        assert matches[0][0] == 10

    def test_no_match(self):
        rows = [_cswitch_row(100, new_tid=10, new_proc="other.exe")]
        df = _build_cswitch_df(rows)
        assert find_tids_for_process(df, "missing") == []

    def test_empty_df(self):
        assert find_tids_for_process(pd.DataFrame(), "foo") == []


# ---------------------------------------------------------------------------
# get_network_wait_chain MCP tool tests
# ---------------------------------------------------------------------------


def _register_trace_with_cswitch(
    trace_id: str,
    cswitch_df: pd.DataFrame,
) -> TraceData:
    """Register a synthetic trace with a pre-populated cswitch_events_df.

    Sets the dumper-ready event so ``wait_for_dumper`` returns immediately.
    """
    trace = TraceData(
        trace_id=trace_id,
        etl_path=Path(f"C:\\traces\\{trace_id}.etl"),
        export_dir=Path(f"C:\\traces\\.etw-export-{trace_id}"),
        cswitch_events_df=cswitch_df,
    )
    # Don't block in wait_for_dumper — pretend extraction already finished.
    trace._dumper_ready.set()
    register_trace(trace)
    return trace


class TestGetNetworkWaitChainTool:
    def test_int_tid_renders_histogram_and_samples(self):
        rows = [
            _cswitch_row(100, new_tid=5678, wait_reason="WrQueue"),
            _cswitch_row(200, new_tid=5678, wait_reason="WrQueue"),
            _cswitch_row(300, new_tid=5678, wait_reason="WrQueue"),
            _cswitch_row(400, new_tid=5678, wait_reason="WrDispatchInt"),
            _cswitch_row(500, new_tid=5678, wait_reason="WrPreempted"),
        ]
        _register_trace_with_cswitch("trace_wc", _build_cswitch_df(rows))
        out = get_network_wait_chain("trace_wc", thread_filter=5678)
        # Histogram present
        assert "WaitReason histogram" in out
        assert "WrQueue" in out
        assert "WrDispatchInt" in out
        # Sample table present
        assert "Sample switch-in events" in out
        # Total switches reported
        assert "5" in out

    def test_string_filter_resolves_to_matching_tids_only(self):
        rows = [
            _cswitch_row(100, new_tid=100, new_proc="echo_server.exe"),
            _cswitch_row(200, new_tid=100, new_proc="echo_server.exe"),
            _cswitch_row(300, new_tid=200, new_proc="dwm.exe"),
            _cswitch_row(400, new_tid=200, new_proc="dwm.exe"),
        ]
        _register_trace_with_cswitch("trace_wc2", _build_cswitch_df(rows))
        out = get_network_wait_chain("trace_wc2", thread_filter="echo_server")
        # echo_server TID 100 must appear; dwm TID 200 must not.
        assert "100" in out
        assert "echo_server" in out
        # dwm.exe shouldn't be mentioned as a thread section
        assert "Thread 200" not in out
        assert "dwm.exe" not in out

    def test_string_filter_no_match(self):
        rows = [_cswitch_row(100, new_tid=10, new_proc="other.exe")]
        _register_trace_with_cswitch("trace_wc3", _build_cswitch_df(rows))
        out = get_network_wait_chain("trace_wc3", thread_filter="missing_proc")
        assert "No threads matched" in out

    def test_no_cswitch_data_returns_friendly_message(self):
        _register_trace_with_cswitch("trace_wc4", pd.DataFrame())
        out = get_network_wait_chain("trace_wc4", thread_filter=1)
        assert "No CSwitch events" in out

    def test_unknown_tid_renders_no_events_section(self):
        rows = [_cswitch_row(100, new_tid=1, wait_reason="WrQueue")]
        _register_trace_with_cswitch("trace_wc5", _build_cswitch_df(rows))
        out = get_network_wait_chain("trace_wc5", thread_filter=99999)
        assert "No context-switch events found" in out

    def test_empty_string_filter_rejected(self):
        rows = [_cswitch_row(100, new_tid=1, wait_reason="WrQueue")]
        _register_trace_with_cswitch("trace_wc6", _build_cswitch_df(rows))
        out = get_network_wait_chain("trace_wc6", thread_filter="   ")
        assert "must be a TID" in out
