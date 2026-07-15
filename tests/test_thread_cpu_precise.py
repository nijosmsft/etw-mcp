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
    """BUG 4 (#36): a wait clipped by the analysis window contributes to Waiting
    ms and — because its switch-IN (wake) lands inside the window — DOES count as
    a Wait->Running park transition, even though the Waiting switch-OUT that
    began it happened before window_start. It must NOT feed the wait-duration
    percentiles (its duration is censored by the window edge)."""

    # TID 10 (us): runs 0-5000, waits 5000-50000 (a *real* wait that completes
    # at a switch-IN at 50000us), runs 50000-80000, waits 80000-end. With
    # start_time=0.02 (20 ms) the first wait STARTS before the window
    # (ts=5000us < 20000us): its switch-IN at 50000us is inside the window, so it
    # IS an in-window Wait->Running transition (park count 1), yet it must be
    # excluded from the percentiles while still adding its in-window portion
    # (20-50ms = 30 ms) to Waiting ms.
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

        # BUG 4: the in-window wake at 50000us (whose prior state was Waiting)
        # DOES count as a Wait->Running park, even though its switch-out (5000us)
        # preceded window_start.
        assert int(row["wait_to_run"]) == 1
        # But the clipped wait's duration is censored, so it does NOT feed the
        # percentiles (the only contained wait — the tail — never completes).
        assert row["mean_wait_us"] == pytest.approx(0.0)
        assert row["p50_wait_us"] == pytest.approx(0.0)
        assert row["p99_wait_us"] == pytest.approx(0.0)


class TestLeadingRunningInterval:
    """A thread whose FIRST in-window event is a switch-OUT is NOT credited with
    a synthesized [window_start, switch-out] running interval. This matches
    WPA's "CPU Usage (Precise)" (which attributes each running interval to the
    switched-IN "New Thread") and the xperf/per-CPU oracle. On real traces a
    thread's first observed event is frequently a LATE switch-out (its pool
    spun up mid-trace), so synthesizing the leading interval grossly
    over-attributes running_ms (#36)."""

    # TID 10 (us): first event is a switch-OUT at 30000us, then switch-IN at
    # 60000us (runs 60-90ms), then switch-OUT at 90000us. Window is 100 ms.
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

    def test_leading_running_not_synthesized(self):
        trace = _make_trace(self._ROWS)
        agg, meta = compute_thread_cpu_precise(trace)

        assert meta["error"] is None
        assert len(agg) == 1
        row = agg.iloc[0]
        assert int(row["tid"]) == 10
        assert row["process"] == "echo.exe"

        # ONLY the observed in@60000 run 60-90ms (30 ms) is counted; the leading
        # switch-out at 30000us does NOT synthesize a 0-30ms running interval.
        assert row["running_ms"] == pytest.approx(30.0)
        # Wait 30-60ms (30 ms, completed) + tail wait 90-100ms (10 ms) = 40 ms.
        assert row["waiting_ms"] == pytest.approx(40.0)

        # Only one observed switch-IN (at 60000us).
        assert int(row["switch_ins"]) == 1
        # The 30-60ms wait completes inside the window and is a Wait->Running park.
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


# ---------------------------------------------------------------------------
# #36 REAL dotnet-sidecar-format regression tests.
#
# The v0.9.0 tool was validated only against SYNTHETIC data in the Python-native
# schema (trace-relative microseconds, OldThreadState present). The dotnet
# sidecar that produced the actual repro ETLs writes a DIFFERENT physical
# format: raw absolute QPC ticks in ``TimeStamp`` (NOT microseconds) and — on
# legacy caches — only ``WaitReason`` with NO ``OldThreadState``. These fixtures
# reproduce that exact wire format so the six #36 bugs cannot regress.
# ---------------------------------------------------------------------------

# Realistic sidecar QPC parameters: 10 MHz perf-counter (PerfFreq=1e7), a large
# absolute QPC origin (~2.2e9 ticks, as seen on the i58 repro), 10 ms trace.
_SIDE_FREQ = 10_000_000.0          # 10 MHz
_SIDE_ORIGIN = 2_195_000_000       # absolute QPC origin (ticks)
_SIDE_DURATION_S = 0.010           # 10 ms


def _qpc(ms_from_start: float) -> int:
    """Absolute QPC tick for a time offset (ms) from trace start."""
    return int(_SIDE_ORIGIN + ms_from_start / 1000.0 * _SIDE_FREQ)


def _side_cswitch_row(
    ms: float,
    *,
    new_tid: int,
    new_pid: int = 0,
    new_proc: str = "",
    old_tid: int = 0,
    old_pid: int = 0,
    old_proc: str = "",
    wait_reason: str | None = "WrQueue",
    old_thread_state: str | None = None,
    cpu: int = 0,
    ts_col: str = "TimeStamp",
) -> dict:
    """A CSwitch row in the exact dotnet-sidecar wire format.

    ``TimeStamp``/``TimeStampQpc`` is a raw absolute QPC tick (NOT microseconds).
    Legacy sidecar caches name the column ``TimeStamp``; the current canonical
    schema (dotnet emitter + native ``schemas.py``) names it ``TimeStampQpc`` —
    the tool must accept both (#36 bug 1). ``WaitReason`` is always present;
    ``OldThreadState`` is only added when explicitly given (legacy sidecar caches
    omit it entirely).
    """
    row = {
        "EventSequence": _side_cswitch_row._seq,
        ts_col: _qpc(ms),
        "CPU": cpu,
        "NewTID": new_tid,
        "OldTID": old_tid,
        "NewPID": new_pid,
        "OldPID": old_pid,
        "WaitReason": wait_reason,
        "Stack": None,
    }
    _side_cswitch_row._seq += 1
    if old_thread_state is not None:
        row["OldThreadState"] = old_thread_state
    return row


_side_cswitch_row._seq = 0


def _make_side_trace(
    rows: list[dict],
    *,
    trace_id: str = "trace_side",
    readythread_df: pd.DataFrame | None = None,
    duration_seconds: float = _SIDE_DURATION_S,
) -> TraceData:
    trace = TraceData(
        trace_id=trace_id,
        etl_path=Path(f"C:\\traces\\{trace_id}.etl"),
        export_dir=Path(f"C:\\traces\\.etw-export-{trace_id}"),
        mode="native",
        cswitch_events_df=pd.DataFrame(rows),
        readythread_df=readythread_df,
        duration_seconds=duration_seconds,
        timestamp_frequency=_SIDE_FREQ,
    )
    trace._dumper_ready.set()
    register_trace(trace)
    return trace


class TestSidecarQpcTimestamps:
    """BUG 1: sidecar TimeStamp is raw absolute QPC ticks, not microseconds."""

    # TID 10: in@0ms -> out@3ms (Waiting) -> in@6ms -> out@9ms. Idle on the
    # other side. Trace window 10 ms.
    def _rows(self, **kw) -> list[dict]:
        return [
            _side_cswitch_row(0.0, new_tid=10, new_pid=1234, new_proc="notify_server.exe",
                              old_tid=0, old_proc="Idle", **kw),
            _side_cswitch_row(3.0, new_tid=0, new_proc="Idle",
                              old_tid=10, old_pid=1234, wait_reason="WrQueue", **kw),
            _side_cswitch_row(6.0, new_tid=10, new_pid=1234, new_proc="notify_server.exe",
                              old_tid=0, old_proc="Idle", **kw),
            _side_cswitch_row(9.0, new_tid=0, new_proc="Idle",
                              old_tid=10, old_pid=1234, wait_reason="WrQueue", **kw),
        ]

    def test_qpc_detected_and_converted(self):
        trace = _make_side_trace(self._rows())
        agg, meta = compute_thread_cpu_precise(trace)

        # BUG 1: the raw ~2.2e9 QPC ticks must be recognized as QPC (not
        # divided by 1e6 as microseconds, which clipped everything to the edge).
        assert meta["timestamp_units"] == "qpc"
        assert meta["perf_freq"] == pytest.approx(_SIDE_FREQ)
        assert meta["window_seconds"] == pytest.approx(0.010)

        row = agg.iloc[0]
        assert int(row["tid"]) == 10
        # Running: in@0->out@3ms (3) + in@6->out@9ms (3) = 6 ms.
        assert row["running_ms"] == pytest.approx(6.0)
        # Waiting: out@3->in@6ms completed (3) + tail out@9->10ms (1) = 4 ms.
        assert row["waiting_ms"] == pytest.approx(4.0)
        # Not the full 10 ms window (the old bug reported running == duration).
        assert row["running_ms"] < meta["window_seconds"] * 1000.0


class TestSidecarWaitReasonFallback:
    """BUG 3: legacy sidecar CSwitch has WaitReason but NO OldThreadState.
    Waiting classification must fall back to WaitReason so waiting_ms != 0."""

    def test_waitreason_only_classifies_waiting(self):
        rows = [
            _side_cswitch_row(0.0, new_tid=10, new_pid=1234, new_proc="notify_server.exe",
                              old_tid=0, old_proc="Idle"),
            # Genuine wait (IOCP dequeue) -> Waiting.
            _side_cswitch_row(3.0, new_tid=0, new_proc="Idle",
                              old_tid=10, old_pid=1234, wait_reason="WrQueue"),
            _side_cswitch_row(6.0, new_tid=10, new_pid=1234, new_proc="notify_server.exe",
                              old_tid=0, old_proc="Idle"),
            # Preemption -> Other, not Waiting.
            _side_cswitch_row(9.0, new_tid=0, new_proc="Idle",
                              old_tid=10, old_pid=1234, wait_reason="WrPreempted"),
        ]
        trace = _make_side_trace(rows)
        agg, meta = compute_thread_cpu_precise(trace)

        assert "OldThreadState" not in trace.cswitch_events_df.columns
        assert meta["state_source"] == "WaitReason"
        row = agg.iloc[0]
        # Waiting: WrQueue out@3->in@6ms = 3 ms.
        assert row["waiting_ms"] == pytest.approx(3.0)
        # Other: WrPreempted tail out@9->10ms = 1 ms (NOT counted as waiting).
        assert row["other_ms"] == pytest.approx(1.0)

    def test_numeric_preemption_ordinal_is_other(self):
        # TraceEvent stringifies WrPreempted=32 numerically when its enum lacks
        # the name; the tool must treat "32" as preemption -> Other.
        rows = [
            _side_cswitch_row(0.0, new_tid=10, new_pid=1234, new_proc="notify_server.exe",
                              old_tid=0, old_proc="Idle"),
            _side_cswitch_row(5.0, new_tid=0, new_proc="Idle",
                              old_tid=10, old_pid=1234, wait_reason="32"),
        ]
        trace = _make_side_trace(rows)
        agg, meta = compute_thread_cpu_precise(trace)
        row = agg.iloc[0]
        assert meta["state_source"] == "WaitReason"
        assert row["waiting_ms"] == pytest.approx(0.0)
        assert row["other_ms"] == pytest.approx(5.0)


class TestSidecarOldThreadStateAuthoritative:
    """BUG 3 (authoritative): the fixed sidecar emits OldThreadState. When the
    column is present it takes priority over the WaitReason heuristic."""

    def test_oldthreadstate_used_when_present(self):
        rows = [
            _side_cswitch_row(0.0, new_tid=10, new_pid=1234, new_proc="notify_server.exe",
                              old_tid=0, old_proc="Idle", old_thread_state="Standby"),
            # WaitReason says WrQueue (would be Waiting), but OldThreadState says
            # "Standby" -> Other. OldThreadState wins.
            _side_cswitch_row(3.0, new_tid=0, new_proc="Idle", old_tid=10, old_pid=1234,
                              wait_reason="WrQueue", old_thread_state="Standby"),
            _side_cswitch_row(6.0, new_tid=10, new_pid=1234, new_proc="notify_server.exe",
                              old_tid=0, old_proc="Idle", old_thread_state="Running"),
            # Real dotnet sidecar spells the waiting state "Wait" (TraceEvent's
            # ThreadState enum), NOT "Waiting" — pin that spelling (#36 bug 3).
            _side_cswitch_row(9.0, new_tid=0, new_proc="Idle", old_tid=10, old_pid=1234,
                              wait_reason="WrQueue", old_thread_state="Wait"),
        ]
        trace = _make_side_trace(rows)
        agg, meta = compute_thread_cpu_precise(trace)

        assert "OldThreadState" in trace.cswitch_events_df.columns
        assert meta["state_source"] == "OldThreadState"
        row = agg.iloc[0]
        # Only out@9ms is Waiting (tail 9->10ms = 1 ms). out@3ms is Standby
        # -> Other (3->6ms = 3 ms).
        assert row["waiting_ms"] == pytest.approx(1.0)
        assert row["other_ms"] == pytest.approx(3.0)


class TestSidecarLeadingRunNotInflated:
    """BUG 1 (running_ms magnitude): on the real repro a thread's first observed
    event is a LATE switch-out (its pool spun up mid-trace). The tool must NOT
    synthesize a [window_start, switch-out] running interval — that inflated
    running_ms ~1.5x vs the xperf/per-CPU oracle."""

    def test_mid_trace_thread_not_credited_from_zero(self):
        # TID 10 first appears at 5 ms (switch-OUT), like tid 8024 @ 5.14 s on
        # the DISABLED repro. It must NOT be credited with running 0..5 ms.
        rows = [
            _side_cswitch_row(5.0, new_tid=0, new_proc="Idle",
                              old_tid=10, old_pid=1234, old_proc="notify_server.exe",
                              wait_reason="WrQueue"),
            _side_cswitch_row(7.0, new_tid=10, new_pid=1234, new_proc="notify_server.exe",
                              old_tid=0, old_proc="Idle"),
            _side_cswitch_row(9.0, new_tid=0, new_proc="Idle",
                              old_tid=10, old_pid=1234, old_proc="notify_server.exe",
                              wait_reason="WrQueue"),
        ]
        trace = _make_side_trace(rows)
        agg, _meta = compute_thread_cpu_precise(trace)
        row = agg.iloc[0]
        # ONLY in@7->out@9ms (2 ms). The leading 0..5ms is NOT synthesized.
        assert row["running_ms"] == pytest.approx(2.0)


class TestSidecarReconciledReadyThreadSchema:
    """BUG 6: native + sidecar ReadyThread schemas are reconciled to the SAME
    columns (readied + readying identity). The tool consumes the unified shape
    from the sidecar's readythread parquet."""

    def test_reconciled_readythread_columns_available(self):
        # Exactly the unified sidecar/native readythread schema.
        rt = pd.DataFrame(
            {
                "EventSequence": [1, 2],
                "TimeStampQpc": [_qpc(3.0), _qpc(6.0)],
                "CPU": [0, 0],
                "ProcessId": [1234, 1234],
                "ThreadId": [10, 10],
                "ReadiedThreadId": [10, 10],
                "ReadyingThreadId": [22, 22],
                "ReadyingProcessId": [4, 4],
                "AdjustReason": [1, 1],
                "AdjustIncrement": [0, 0],
                "Flag": [0, 0],
            }
        )
        rows = [
            _side_cswitch_row(0.0, new_tid=10, new_pid=1234, new_proc="notify_server.exe",
                              old_tid=0, old_proc="Idle"),
            _side_cswitch_row(9.0, new_tid=0, new_proc="Idle",
                              old_tid=10, old_pid=1234, wait_reason="WrQueue"),
        ]
        trace = _make_side_trace(rows, readythread_df=rt)
        _agg, meta = compute_thread_cpu_precise(trace)
        assert meta["readythread_available"] is True
        assert meta["readythread_events"] == 2

    def test_native_dotnet_readythread_schemas_match(self):
        # BUG 6: the native event-store schema and the dotnet sidecar emitter
        # must declare the same ReadyThread columns.
        from etw_analyzer.native.schemas import schema_for_event_class

        native_cols = set(schema_for_event_class("readythread").schema.names)
        expected = {
            "EventSequence", "TimeStampQpc", "CPU", "ProcessId", "ThreadId",
            "ReadiedThreadId", "ReadyingThreadId", "ReadyingProcessId",
            "AdjustReason", "AdjustIncrement", "Flag", "Stack",
        }
        assert native_cols == expected


class TestSidecarCanonicalTimeStampQpcColumn:
    """BUG 1 (#36): the canonical current sidecar/native CSwitch schema names the
    timestamp column ``TimeStampQpc`` (verified against the real re-extracted
    sidecar parquet), not ``TimeStamp``. The tool must parse it — previously it
    only recognized ``TimeStamp`` and returned ``missing-columns`` on every
    current-schema cache."""

    def test_timestampqpc_column_is_parsed(self):
        # Same scenario as TestSidecarQpcTimestamps but with the canonical column
        # name the real fixed sidecar actually emits.
        rows = [
            _side_cswitch_row(0.0, new_tid=10, new_pid=1234, new_proc="notify_server.exe",
                              old_tid=0, old_proc="Idle", ts_col="TimeStampQpc"),
            _side_cswitch_row(3.0, new_tid=0, new_proc="Idle",
                              old_tid=10, old_pid=1234, wait_reason="WrQueue",
                              ts_col="TimeStampQpc"),
            _side_cswitch_row(6.0, new_tid=10, new_pid=1234, new_proc="notify_server.exe",
                              old_tid=0, old_proc="Idle", ts_col="TimeStampQpc"),
            _side_cswitch_row(9.0, new_tid=0, new_proc="Idle",
                              old_tid=10, old_pid=1234, wait_reason="WrQueue",
                              ts_col="TimeStampQpc"),
        ]
        trace = _make_side_trace(rows)
        agg, meta = compute_thread_cpu_precise(trace)
        assert meta["error"] is None
        assert meta["timestamp_units"] == "qpc"
        row = agg[agg["tid"] == 10].iloc[0]
        # Running: in@0->out@3 (3) + in@6->out@9 (3) = 6 ms.
        assert row["running_ms"] == pytest.approx(6.0)
        # Waiting: out@3->in@6 (3) + tail out@9->10 (1) = 4 ms.
        assert row["waiting_ms"] == pytest.approx(4.0)

    def test_oldthreadstate_wait_spelling_from_real_sidecar(self):
        # The real sidecar spells the waiting state "Wait"; ensure the canonical
        # (TimeStampQpc + OldThreadState="Wait") path classifies waiting_ms > 0.
        rows = [
            _side_cswitch_row(0.0, new_tid=10, new_pid=1234, new_proc="notify_server.exe",
                              old_tid=0, old_proc="Idle", old_thread_state="Running",
                              ts_col="TimeStampQpc"),
            _side_cswitch_row(3.0, new_tid=0, new_proc="Idle", old_tid=10, old_pid=1234,
                              wait_reason="WrQueue", old_thread_state="Wait",
                              ts_col="TimeStampQpc"),
            _side_cswitch_row(6.0, new_tid=10, new_pid=1234, new_proc="notify_server.exe",
                              old_tid=0, old_proc="Idle", old_thread_state="Running",
                              ts_col="TimeStampQpc"),
            _side_cswitch_row(9.0, new_tid=0, new_proc="Idle", old_tid=10, old_pid=1234,
                              wait_reason="WrQueue", old_thread_state="Wait",
                              ts_col="TimeStampQpc"),
        ]
        trace = _make_side_trace(rows)
        agg, meta = compute_thread_cpu_precise(trace)
        assert meta["state_source"] == "OldThreadState"
        row = agg[agg["tid"] == 10].iloc[0]
        # Both switch-outs are "Wait": out@3->in@6 (3) + tail out@9->10 (1) = 4 ms.
        assert row["waiting_ms"] == pytest.approx(4.0)
        assert row["other_ms"] == pytest.approx(0.0)
