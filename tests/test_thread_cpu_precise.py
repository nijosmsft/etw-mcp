"""Tests for get_thread_cpu_precise (CPU Usage Precise) and Part A wiring."""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from etw_analyzer.tools.thread_cpu_precise import (
    compute_thread_cpu_precise,
    get_thread_cpu_precise,
)
from etw_analyzer.trace_state import TraceData, clear_traces, register_trace


@pytest.fixture(autouse=True)
def clean_trace_registry():
    clear_traces()
    yield
    clear_traces()


# ---------------------------------------------------------------------------
# Synthetic CSwitch helpers. TimeStamps are in the REAL units the tool consumes:
# trace-relative MICROSECONDS with origin 0 (the native extractor already
# converts raw QPC to us — see native/extract.py and native/event_store.py).
# The fixture window is duration_seconds=0.1 (100 ms == 100000 us). No QPC
# frequency is applied by the tool; timestamp_frequency is left only for
# TraceData construction and is ignored by thread_cpu_precise.
# ---------------------------------------------------------------------------


def _cswitch_row(
    timestamp: int,
    *,
    new_tid: int,
    new_pid: int = 0,
    new_proc: str = "",
    old_tid: int = 0,
    old_pid: int = 0,
    old_proc: str = "",
    old_state: str = "Waiting",
    wait_reason: str = "WrQueue",
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
        "OldThreadState": old_state,
        "CPU": cpu,
        "NewPriority": 9,
        "OldPriority": 0,
    }


def _make_trace(
    cswitch_rows: list[dict],
    *,
    trace_id: str = "trace_precise",
    readythread_df: pd.DataFrame | None = None,
    duration_seconds: float = 0.1,
    timestamp_frequency: float = 1000.0,
) -> TraceData:
    trace = TraceData(
        trace_id=trace_id,
        etl_path=Path(f"C:\\traces\\{trace_id}.etl"),
        export_dir=Path(f"C:\\traces\\.etw-export-{trace_id}"),
        cswitch_events_df=pd.DataFrame(cswitch_rows),
        readythread_df=readythread_df,
        duration_seconds=duration_seconds,
        timestamp_frequency=timestamp_frequency,
    )
    trace._dumper_ready.set()
    register_trace(trace)
    return trace


# TID 10: runs 0-10ms, waits 10-40ms (completed), runs 40-70ms,
# waits 70-100ms (clipped/incomplete). Window 100ms. Timestamps are in
# microseconds (0, 10000, 40000, 70000). The "other side" is the idle thread
# (TID 0), which must be excluded.
_SINGLE_THREAD_ROWS = [
    _cswitch_row(0, new_tid=10, new_pid=1234, new_proc="echo.exe",
                 old_tid=0, old_proc="Idle", old_state="Running"),
    _cswitch_row(10_000, new_tid=0, new_proc="Idle",
                 old_tid=10, old_pid=1234, old_proc="echo.exe", old_state="Waiting"),
    _cswitch_row(40_000, new_tid=10, new_pid=1234, new_proc="echo.exe",
                 old_tid=0, old_proc="Idle", old_state="Running"),
    _cswitch_row(70_000, new_tid=0, new_proc="Idle",
                 old_tid=10, old_pid=1234, old_proc="echo.exe", old_state="Waiting"),
]


class TestSingleThreadExactNumbers:
    def test_running_waiting_switches_and_waits(self):
        trace = _make_trace(_SINGLE_THREAD_ROWS)
        agg, meta = compute_thread_cpu_precise(trace)

        assert meta["error"] is None
        assert meta["window_seconds"] == pytest.approx(0.1)
        assert len(agg) == 1
        row = agg.iloc[0]

        assert int(row["tid"]) == 10
        assert row["process"] == "echo.exe"
        assert int(row["pid"]) == 1234

        assert row["running_ms"] == pytest.approx(40.0)
        assert row["running_pct"] == pytest.approx(40.0)
        assert row["waiting_ms"] == pytest.approx(60.0)
        assert row["waiting_pct"] == pytest.approx(60.0)
        assert row["other_ms"] == pytest.approx(0.0)

        assert int(row["switch_ins"]) == 2
        assert row["cswitch_per_s"] == pytest.approx(20.0)

        # Only the 10-40 wait completed (followed by a switch-in). The
        # 70-100 wait is clipped at the window and never completes.
        assert int(row["wait_to_run"]) == 1
        assert row["mean_wait_us"] == pytest.approx(30000.0)
        assert row["p50_wait_us"] == pytest.approx(30000.0)

    def test_idle_tid_excluded(self):
        trace = _make_trace(_SINGLE_THREAD_ROWS)
        agg, _meta = compute_thread_cpu_precise(trace)
        assert 0 not in set(agg["tid"].tolist())
        assert "Idle" not in set(agg["process"].tolist())


class TestClippedWaitExcluded:
    """BLOCKER 2: a wait clipped by the analysis window contributes to Waiting
    ms but must NOT feed wait_to_run or the wait percentiles, even though it is
    followed by a real switch-IN (next_kind == 'in')."""

    # TID 10 (us): runs 0-5000, waits 5000-50000 (a *real* wait that completes
    # at a switch-IN at 50000us), runs 50000-80000, waits 80000-end. With
    # start_time=0.02 (20 ms) the first wait STARTS before the window
    # (ts=5000us < 20000us): its switch-IN at 50000us is inside the window, so
    # next_kind == 'in', yet it must be excluded from the completed count and
    # percentiles while still adding its in-window portion (20-50ms = 30 ms) to
    # Waiting ms.
    _ROWS = [
        _cswitch_row(0, new_tid=10, new_pid=1234, new_proc="echo.exe",
                     old_tid=0, old_proc="Idle", old_state="Running"),
        _cswitch_row(5_000, new_tid=0, new_proc="Idle",
                     old_tid=10, old_pid=1234, old_proc="echo.exe",
                     old_state="Waiting"),
        _cswitch_row(50_000, new_tid=10, new_pid=1234, new_proc="echo.exe",
                     old_tid=0, old_proc="Idle", old_state="Running"),
        _cswitch_row(80_000, new_tid=0, new_proc="Idle",
                     old_tid=10, old_pid=1234, old_proc="echo.exe",
                     old_state="Waiting"),
    ]

    def test_clipped_wait_in_ms_but_not_counted(self):
        trace = _make_trace(self._ROWS)
        agg, meta = compute_thread_cpu_precise(trace, start_time=0.02)

        assert meta["error"] is None
        # Window [20ms, 100ms] = 80 ms.
        assert meta["window_seconds"] == pytest.approx(0.08)
        row = agg.iloc[0]

        # Running: in@0 clipped to 0, in@50000 runs 50-80ms = 30 ms.
        assert row["running_ms"] == pytest.approx(30.0)
        # Waiting: clipped first wait 20-50ms (30 ms) + tail wait 80-100ms
        # (20 ms) = 50 ms.
        assert row["waiting_ms"] == pytest.approx(50.0)

        # The clipped wait (started before window) and the incomplete tail wait
        # are both excluded from the completed count and percentiles.
        assert int(row["wait_to_run"]) == 0
        assert row["mean_wait_us"] == pytest.approx(0.0)
        assert row["p50_wait_us"] == pytest.approx(0.0)
        assert row["p99_wait_us"] == pytest.approx(0.0)


class TestLeadingRunningInterval:
    """BLOCKER 3: when a thread's FIRST observed event in the window is a
    switch-OUT, it was running before it; that leading Running interval (from
    window start to the switch-out) must be counted, without inventing a
    switch-in."""

    # TID 10 (us): first event is a switch-OUT at 30000us (so it was running
    # 0-30ms), then switch-IN at 60000us (runs 60-90ms), then switch-OUT at
    # 90000us. Window is the full 100 ms.
    _ROWS = [
        _cswitch_row(30_000, new_tid=0, new_proc="Idle",
                     old_tid=10, old_pid=1234, old_proc="echo.exe",
                     old_state="Waiting"),
        _cswitch_row(60_000, new_tid=10, new_pid=1234, new_proc="echo.exe",
                     old_tid=0, old_proc="Idle", old_state="Running"),
        _cswitch_row(90_000, new_tid=0, new_proc="Idle",
                     old_tid=10, old_pid=1234, old_proc="echo.exe",
                     old_state="Waiting"),
    ]

    def test_leading_running_counted(self):
        trace = _make_trace(self._ROWS)
        agg, meta = compute_thread_cpu_precise(trace)

        assert meta["error"] is None
        assert len(agg) == 1
        row = agg.iloc[0]
        assert int(row["tid"]) == 10
        assert row["process"] == "echo.exe"

        # Leading run 0-30ms (30 ms) + in@60000 run 60-90ms (30 ms) = 60 ms.
        assert row["running_ms"] == pytest.approx(60.0)
        # Wait 30-60ms (30 ms, completed) + tail wait 90-100ms (10 ms) = 40 ms.
        assert row["waiting_ms"] == pytest.approx(40.0)

        # Only one observed switch-IN (at 60000us); the leading run adds none.
        assert int(row["switch_ins"]) == 1
        # The 30-60ms wait completes inside the window.
        assert int(row["wait_to_run"]) == 1
        assert row["mean_wait_us"] == pytest.approx(30000.0)


class TestFilteredWindowSwitchInCount:
    """Regression: with a start_time/end_time filter, switch-ins that occur
    OUTSIDE the window must not be counted toward switch_ins / CSwitch-per-sec,
    otherwise out-of-window switch-ins get divided by the filtered window and
    inflate the rate."""

    # TID 10 (us): switch-IN at 10000 (before the 20ms window), switch-OUT at
    # 30000 (waiting), switch-IN at 60000 (inside window), switch-OUT at 90000.
    _ROWS = [
        _cswitch_row(10_000, new_tid=10, new_pid=1234, new_proc="echo.exe",
                     old_tid=0, old_proc="Idle", old_state="Running"),
        _cswitch_row(30_000, new_tid=0, new_proc="Idle",
                     old_tid=10, old_pid=1234, old_proc="echo.exe",
                     old_state="Waiting"),
        _cswitch_row(60_000, new_tid=10, new_pid=1234, new_proc="echo.exe",
                     old_tid=0, old_proc="Idle", old_state="Running"),
        _cswitch_row(90_000, new_tid=0, new_proc="Idle",
                     old_tid=10, old_pid=1234, old_proc="echo.exe",
                     old_state="Waiting"),
    ]

    def test_out_of_window_switch_in_excluded(self):
        trace = _make_trace(self._ROWS)
        agg, meta = compute_thread_cpu_precise(trace, start_time=0.02)

        assert meta["error"] is None
        # Window [20ms, 100ms] = 80 ms.
        assert meta["window_seconds"] == pytest.approx(0.08)
        row = agg.iloc[0]

        # Only the switch-IN at 60000us is inside the window; the one at
        # 10000us (before window_start) is excluded.
        assert int(row["switch_ins"]) == 1
        assert row["cswitch_per_s"] == pytest.approx(12.5)

    def test_no_filter_counts_all_switch_ins(self):
        # Without a time filter, every switch-IN counts (fix is a no-op here).
        trace = _make_trace(self._ROWS)
        agg, meta = compute_thread_cpu_precise(trace)
        assert meta["error"] is None
        row = agg.iloc[0]
        assert int(row["switch_ins"]) == 2
        assert row["cswitch_per_s"] == pytest.approx(20.0)


class TestProcessGrouping:
    def test_two_tids_same_process_summed(self):
        rows = list(_SINGLE_THREAD_ROWS)
        # TID 11, same PID/image, runs 5-25ms (20ms), then parks.
        rows += [
            _cswitch_row(5_000, new_tid=11, new_pid=1234, new_proc="echo.exe",
                         old_tid=0, old_proc="Idle", old_state="Running", cpu=1),
            _cswitch_row(25_000, new_tid=0, new_proc="Idle",
                         old_tid=11, old_pid=1234, old_proc="echo.exe",
                         old_state="Waiting", cpu=1),
        ]
        trace = _make_trace(rows)
        agg, meta = compute_thread_cpu_precise(trace, group_by="process")

        assert len(agg) == 1
        row = agg.iloc[0]
        assert row["process"] == "echo.exe"
        assert int(row["pid"]) == 1234
        assert int(row["threads"]) == 2
        # 40ms (tid10) + 20ms (tid11)
        assert row["running_ms"] == pytest.approx(60.0)
        # 2 (tid10) + 1 (tid11)
        assert int(row["switch_ins"]) == 3

    def test_thread_grouping_reports_each_thread(self):
        rows = list(_SINGLE_THREAD_ROWS)
        rows += [
            _cswitch_row(5_000, new_tid=11, new_pid=1234, new_proc="echo.exe",
                         old_tid=0, old_proc="Idle", old_state="Running", cpu=1),
            _cswitch_row(25_000, new_tid=0, new_proc="Idle",
                         old_tid=11, old_pid=1234, old_proc="echo.exe",
                         old_state="Waiting", cpu=1),
        ]
        trace = _make_trace(rows)
        agg, _meta = compute_thread_cpu_precise(trace, group_by="thread")
        assert set(agg["tid"].tolist()) == {10, 11}


class TestReadyThreadAttribution:
    def test_present_readythread_marks_available(self):
        rt = pd.DataFrame(
            {
                "TimeStamp": [8_000, 38_000],
                "CPU": [0, 0],
                "ThreadId": [10, 10],
                "ReadiedThreadId": [10, 10],
                "ReadyingThreadId": [22, 22],
                "ReadyingProcessId": [1234, 1234],
                "AdjustReason": [1, 1],
                "AdjustIncrement": [0, 0],
                "Flag": [0, 0],
            }
        )
        trace = _make_trace(_SINGLE_THREAD_ROWS, readythread_df=rt)
        agg, meta = compute_thread_cpu_precise(trace)
        assert meta["readythread_available"] is True
        assert meta["readythread_events"] == 2
        # Core metrics unchanged whether or not ReadyThread is present.
        assert agg.iloc[0]["running_ms"] == pytest.approx(40.0)

        out = get_thread_cpu_precise(trace.trace_id, process_filter="echo")
        assert "ReadyThread attribution: available" in out
        assert "echo.exe" in out

    def test_missing_readythread_notes_unavailable(self):
        trace = _make_trace(_SINGLE_THREAD_ROWS)
        agg, meta = compute_thread_cpu_precise(trace)
        assert meta["readythread_available"] is False
        assert agg.iloc[0]["running_ms"] == pytest.approx(40.0)

        out = get_thread_cpu_precise(trace.trace_id)
        assert "ReadyThread attribution: unavailable" in out

    def test_empty_readythread_notes_unavailable(self):
        empty_rt = pd.DataFrame(
            columns=["TimeStamp", "CPU", "ThreadId", "ReadiedThreadId"]
        )
        trace = _make_trace(_SINGLE_THREAD_ROWS, readythread_df=empty_rt)
        _agg, meta = compute_thread_cpu_precise(trace)
        assert meta["readythread_available"] is False


class TestToolWrapper:
    def test_renders_markdown_table(self):
        trace = _make_trace(_SINGLE_THREAD_ROWS)
        out = get_thread_cpu_precise(trace.trace_id)
        assert "Thread CPU (Precise)" in out
        assert "| Process |" in out
        assert "echo.exe" in out

    def test_invalid_group_by(self):
        trace = _make_trace(_SINGLE_THREAD_ROWS)
        out = get_thread_cpu_precise(trace.trace_id, group_by="bogus")
        assert "Invalid group_by" in out

    def test_no_cswitch_returns_helpful_message(self):
        trace = TraceData(
            trace_id="trace_empty",
            etl_path=Path("C:\\traces\\trace_empty.etl"),
            export_dir=Path("C:\\traces\\.etw-export-empty"),
        )
        trace._dumper_ready.set()
        register_trace(trace)
        out = get_thread_cpu_precise("trace_empty")
        assert "No CSwitch" in out

    def test_process_filter_substring(self):
        rows = list(_SINGLE_THREAD_ROWS)
        rows += [
            _cswitch_row(5_000, new_tid=11, new_pid=99, new_proc="other.exe",
                         old_tid=0, old_proc="Idle", old_state="Running", cpu=1),
            _cswitch_row(25_000, new_tid=0, new_proc="Idle",
                         old_tid=11, old_pid=99, old_proc="other.exe",
                         old_state="Waiting", cpu=1),
        ]
        trace = _make_trace(rows)
        agg, _meta = compute_thread_cpu_precise(trace, process_filter="echo")
        assert set(agg["process"].tolist()) == {"echo.exe"}


# ---------------------------------------------------------------------------
# Part A regression: ReadyThread co-request wiring.
# ---------------------------------------------------------------------------


class TestSchedulerRequestNormalization:
    def test_dumper_event_classes_contains_readythread(self):
        from etw_analyzer.tools.trace_mgmt import _DUMPER_EVENT_CLASSES

        assert "ReadyThread" in _DUMPER_EVENT_CLASSES
        attr, stem = _DUMPER_EVENT_CLASSES["ReadyThread"]
        assert attr == "readythread_df"
        assert stem == "readythread"

    def test_cswitch_only_request_normalizes_to_include_readythread(self):
        from etw_analyzer.tools.trace_mgmt import _normalize_scheduler_request

        normalized = _normalize_scheduler_request({"CSwitch"})
        assert "CSwitch" in normalized
        assert "ReadyThread" in normalized

    def test_normalization_no_op_without_cswitch(self):
        from etw_analyzer.tools.trace_mgmt import _normalize_scheduler_request

        normalized = _normalize_scheduler_request({"SampledProfile"})
        assert "ReadyThread" not in normalized

    def test_readythread_excluded_from_parquet_join(self):
        from etw_analyzer.tools.trace_mgmt import _PARQUET_EXCLUDED

        assert "readythread" in _PARQUET_EXCLUDED
