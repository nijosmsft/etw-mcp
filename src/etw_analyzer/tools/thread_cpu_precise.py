"""Precise per-thread CPU running/waiting analysis from CSwitch events.

This mirrors WPA's "CPU Usage (Precise)" table: it reconstructs how long each
thread was actually *Running* on a CPU versus *Waiting* off-CPU, using only
context-switch (``CSwitch``) events — no CPU sampling required. When the trace
also carries ``ReadyThread`` events (co-requested with CSwitch by the native
extractor), wake attribution is available and noted in the output.

All aggregation is vectorized pandas (sort + groupby + shift); there are no
per-row Python loops and no SQL/DuckDB.
"""

from __future__ import annotations

import pandas as pd

from etw_analyzer.app import mcp
from etw_analyzer.trace_state import TraceData, require_trace
from etw_analyzer.parsing.aggregator import parse_cpu_filter
from etw_analyzer.formatting.markdown import format_table, format_pct
from etw_analyzer.tools.cpu_sampling import _find_col
from etw_analyzer.tools.context_switch import _load_native_cswitch_df


# CSwitch ``TimeStamp`` units differ by producer, so this tool normalizes both:
#
# * **native (in-process) extractor** — ``native/extract.py:_normalize_native_timestamps``
#   converts raw QPC to integer MICROSECONDS relative to trace start (origin 0).
# * **dotnet sidecar** — ``aggregation_worker_adapters.normalize_dotnet_dataframe``
#   only RENAMES ``TimeStampQpc`` -> ``TimeStamp`` and leaves the raw ABSOLUTE
#   QPC ticks (e.g. ~2.2e9) untouched. Dividing those by 1e6 (the old assumption)
#   clipped every event to the window edge and made every metric bogus (#36).
#
# ``_normalize_timestamps`` detects which convention a frame uses (via the trace's
# QPC frequency + authoritative duration) and returns trace-relative SECONDS for
# both, so the rest of the tool is producer-agnostic.
_US_PER_SECOND = 1_000_000.0

# WaitReason values (from the CSwitch OldThreadWaitReason field) that indicate an
# involuntary / still-runnable switch-out (preemption, quantum end) rather than a
# genuine off-CPU Wait. Used ONLY as a fallback to classify Waiting-vs-Other when
# the authoritative ``OldThreadState`` column is absent (legacy dotnet-sidecar
# CSwitch parquet carries WaitReason but not OldThreadState — #36 bug 3). Matches
# both TraceEvent enum names and the raw kernel WAIT_REASON ordinals TraceEvent
# stringifies numerically (30..33) when its own enum lacks the name.
_PREEMPT_WAIT_REASONS = frozenset(
    {
        "wrquantumend", "quantumend",
        "wrdispatchint", "dispatchint",
        "wrpreempted", "preempted",
        "wryieldexecution", "yieldexecution",
        "30", "31", "32", "33",
    }
)

# OldThreadState string values that denote a genuine off-CPU *Wait*. TraceEvent's
# ThreadState enum stringifies the waiting state as ``"Wait"`` (verified on real
# sidecar output); the native/MOF path and some kernels spell it ``"Waiting"``,
# and the raw kernel ordinal for Waiting is 5. Match all spellings, case-insensitive,
# so waiting-vs-other classification works regardless of the producer (#36 bug 3).
_WAIT_STATES = frozenset({"wait", "waiting", "5"})


def _resolve_perf_freq(trace: TraceData) -> float | None:
    """Return the trace's QPC frequency (Hz), or None if unknown.

    Checked in priority order: the ``timestamp_frequency`` attribute (set from
    the ETL header on dotnet caches), then the ``trace_metadata`` /
    ``EventTrace/Header`` frames' ``PerfFreq`` column.
    """
    freq = getattr(trace, "timestamp_frequency", None)
    try:
        if freq and float(freq) > 0:
            return float(freq)
    except (TypeError, ValueError):
        pass
    with trace.lock:
        for key in ("trace_metadata", "EventTrace/Header"):
            df = trace.raw_csv.get(key)
            if df is None or getattr(df, "empty", True):
                continue
            if "PerfFreq" in df.columns:
                try:
                    value = float(pd.to_numeric(df["PerfFreq"], errors="coerce").iloc[0])
                except (TypeError, ValueError, IndexError):
                    continue
                if value > 0:
                    return value
    return None


def _normalize_timestamps(
    raw_ts: pd.Series,
    trace: TraceData,
    meta: dict,
) -> tuple[pd.Series, float]:
    """Convert a CSwitch ``TimeStamp`` column to trace-relative SECONDS.

    Handles both producer conventions (native microseconds vs dotnet-sidecar
    raw absolute QPC ticks). Returns ``(ts_seconds, total_window_seconds)`` and
    records ``timestamp_units`` / ``perf_freq`` on ``meta``.
    """
    numeric = pd.to_numeric(raw_ts, errors="coerce")
    valid = numeric.dropna()
    if valid.empty:
        return numeric * 0.0, 0.0

    raw_min = float(valid.min())
    raw_max = float(valid.max())
    span = raw_max - raw_min

    perf_freq = _resolve_perf_freq(trace)
    meta["perf_freq"] = perf_freq
    dur_meta = getattr(trace, "duration_seconds", None)
    try:
        dur_meta = float(dur_meta) if dur_meta else None
    except (TypeError, ValueError):
        dur_meta = None

    # Decide whether the column is raw QPC ticks or already microseconds.
    is_qpc = False
    if perf_freq and perf_freq > 0 and span > 0:
        us_span_s = span / _US_PER_SECOND
        qpc_span_s = span / perf_freq
        if dur_meta and dur_meta > 0:
            # Pick the interpretation whose implied span best matches the
            # authoritative trace duration from the ETL header.
            is_qpc = abs(qpc_span_s - dur_meta) < abs(us_span_s - dur_meta)
        else:
            # No authoritative duration: absolute QPC-since-boot has a large
            # origin (min >> 1s of ticks); native microseconds are relative
            # (min ~ 0). Treat a large origin as absolute QPC ticks.
            is_qpc = raw_min > perf_freq

    if is_qpc and perf_freq:
        meta["timestamp_units"] = "qpc"
        ts_sec = (numeric - raw_min) / perf_freq
        span_s = span / perf_freq
    else:
        meta["timestamp_units"] = "us"
        ts_sec = numeric / _US_PER_SECOND
        span_s = raw_max / _US_PER_SECOND

    total_window = dur_meta if (dur_meta and dur_meta > 0) else span_s
    if total_window <= 0:
        total_window = max(span_s, 1e-9)
    return ts_sec, total_window

_SORT_COLUMNS = {
    "running_ms",
    "running_pct",
    "waiting_ms",
    "waiting_pct",
    "other_ms",
    "switch_ins",
    "cswitch_per_s",
    "wait_to_run",
    "wait_to_run_per_s",
    "mean_wait_us",
    "p50_wait_us",
    "p90_wait_us",
    "p99_wait_us",
}

_GROUP_BY_CHOICES = {"thread", "process", "process+thread"}


def _get_precise_cswitch_df(trace: TraceData) -> pd.DataFrame | None:
    """Return a CSwitch events frame without triggering an xperf on-demand run.

    Checks the pre-loaded raw_csv keys and the native ``cswitch_events_df`` /
    ``cswitch_events.parquet`` sidecar. Unlike ``context_switch._get_cswitch_df``
    this never falls back to ``run_readythread`` (which would fail on native
    caches and is slow).
    """
    with trace.lock:
        for key in ("cswitch", "CSwitch", "context_switch"):
            df = trace.raw_csv.get(key)
            if df is not None and "raw_text" not in df.columns and not df.empty:
                return df.copy()

    native = _load_native_cswitch_df(trace)
    if native is not None and not native.empty:
        return native.copy()

    # Empty placeholders (0-row cswitch/readythread) mean "decoded, but no such
    # events" — return them so the caller reports "no data" rather than erroring.
    with trace.lock:
        for key in ("cswitch", "CSwitch", "context_switch"):
            df = trace.raw_csv.get(key)
            if df is not None and "raw_text" not in df.columns:
                return df.copy()
    return None


def _get_precise_readythread_df(trace: TraceData) -> pd.DataFrame | None:
    """Return the ReadyThread frame (dedicated attr, raw_csv, or parquet)."""
    df = getattr(trace, "readythread_df", None)
    if df is not None:
        return df
    with trace.lock:
        for key in ("readythread", "ReadyThread", "ready_thread"):
            d = trace.raw_csv.get(key)
            if d is not None and "raw_text" not in getattr(d, "columns", []):
                return d
    export_dir = getattr(trace, "export_dir", None)
    if export_dir is not None:
        parquet = export_dir / "readythread.parquet"
        if parquet.exists():
            try:
                return pd.read_parquet(parquet)
            except Exception:
                return None
    return None


def compute_thread_cpu_precise(
    trace: TraceData,
    *,
    process_filter: str | None = None,
    tid: int | None = None,
    cpu_filter: str | None = None,
    start_time: float | None = None,
    end_time: float | None = None,
    group_by: str = "thread",
    sort_by: str = "running_ms",
) -> tuple[pd.DataFrame, dict]:
    """Compute per-thread (or per-process) precise CPU stats.

    Returns ``(result_df, meta)``. ``result_df`` carries raw numeric columns
    (running_ms, running_pct, waiting_ms, waiting_pct, other_ms, switch_ins,
    cswitch_per_s, wait_to_run, wait_to_run_per_s, mean_wait_us, p50/p90/p99
    wait_us) plus identity columns (process, pid, and either tid or threads).
    ``meta`` carries window_seconds, lost_intervals, readythread_available,
    readythread_events, frequency_assumed and any error string.
    """
    meta: dict = {
        "window_seconds": 0.0,
        "lost_intervals": 0,
        "readythread_available": False,
        "readythread_events": 0,
        "frequency_assumed": False,
        "timestamp_units": None,
        "perf_freq": None,
        "state_source": None,
        "group_by": group_by,
        "error": None,
    }

    rt = _get_precise_readythread_df(trace)
    meta["readythread_available"] = rt is not None and not rt.empty
    meta["readythread_events"] = int(len(rt)) if rt is not None else 0

    cswitch = _get_precise_cswitch_df(trace)
    if cswitch is None or cswitch.empty:
        meta["error"] = "no-cswitch"
        return pd.DataFrame(), meta

    ts_col = _find_col(cswitch, ["TimeStampQpc", "TimeStamp", "Time", "Timestamp"])
    new_tid_col = _find_col(cswitch, ["NewTID", "NewThreadId", "New TID"])
    old_tid_col = _find_col(cswitch, ["OldTID", "OldThreadId", "Old TID"])
    new_pid_col = _find_col(cswitch, ["NewPID", "NewProcessId", "New PID"])
    old_pid_col = _find_col(cswitch, ["OldPID", "OldProcessId", "Old PID"])
    new_proc_col = _find_col(cswitch, ["NewProcessName", "NewProcess"])
    old_proc_col = _find_col(cswitch, ["OldProcessName", "OldProcess"])
    state_col = _find_col(cswitch, ["OldThreadState", "OldState"])
    wait_col = _find_col(cswitch, ["WaitReason", "OldThreadWaitReason", "Wait Reason"])
    cpu_col = _find_col(cswitch, ["CPU", "Cpu", "Processor"])
    # Nit: native microsecond rounding can collapse distinct QPC events to the
    # same us. When a raw ordering column is present, use it as the sort
    # tiebreak so a same-us OUT->IN pair still pairs in emission order.
    seq_col = _find_col(cswitch, ["EventSequence", "Event Sequence", "Sequence"])

    if ts_col is None or new_tid_col is None or old_tid_col is None:
        meta["error"] = "missing-columns"
        return pd.DataFrame(), meta

    # CPU filter (approximate: filters rows before pairing switch-in/out, which
    # can split cross-CPU intervals — noted in the tool output).
    if cpu_filter and cpu_col is not None:
        cpus = parse_cpu_filter(cpu_filter)
        if cpus:
            cswitch = cswitch[
                pd.to_numeric(cswitch[cpu_col], errors="coerce").isin(cpus)
            ]
        if cswitch.empty:
            meta["error"] = "no-rows-after-cpu-filter"
            return pd.DataFrame(), meta

    # BUG 1 FIX (#36): normalize CSwitch timestamps to trace-relative seconds,
    # detecting native microseconds vs dotnet-sidecar raw QPC ticks. Previously
    # the raw QPC ticks were divided by 1e6 (treated as microseconds), clipping
    # every event to the window edge and zeroing every metric on real sidecar
    # parquet.
    raw_ts = pd.to_numeric(cswitch[ts_col], errors="coerce")
    ts_sec, total_window = _normalize_timestamps(raw_ts, trace, meta)
    meta["frequency_assumed"] = (
        meta.get("timestamp_units") == "qpc" and not meta.get("perf_freq")
    )

    # Window is anchored at trace start (0s), not the first observed CSwitch.
    # start_time/end_time are seconds from trace start; the rate denominator is
    # the FILTERED window width, not the whole trace.
    window_start = float(start_time) if start_time is not None else 0.0
    window_end = float(end_time) if end_time is not None else total_window
    window_seconds = window_end - window_start
    if window_seconds <= 0:
        window_seconds = max(total_window - window_start, 1e-9)
        window_end = window_start + window_seconds
    meta["window_seconds"] = window_seconds

    def _side(tid_col, pid_col, proc_col, kind: str) -> pd.DataFrame:
        frame = pd.DataFrame(
            {
                "tid": pd.to_numeric(cswitch[tid_col], errors="coerce"),
                "pid": (
                    pd.to_numeric(cswitch[pid_col], errors="coerce")
                    if pid_col
                    else 0
                ),
                "process": (
                    cswitch[proc_col].astype(str) if proc_col else ""
                ),
                "ts": ts_sec.to_numpy(),
                "kind": kind,
                "seq": (
                    pd.to_numeric(cswitch[seq_col], errors="coerce").to_numpy()
                    if seq_col
                    else 0
                ),
                "old_state": (
                    cswitch[state_col].astype(str)
                    if (kind == "out" and state_col)
                    else ""
                ),
                "wait_reason": (
                    cswitch[wait_col].astype(str)
                    if (kind == "out" and wait_col)
                    else ""
                ),
            }
        )
        return frame

    in_ev = _side(new_tid_col, new_pid_col, new_proc_col, "in")
    out_ev = _side(old_tid_col, old_pid_col, old_proc_col, "out")
    events = pd.concat([in_ev, out_ev], ignore_index=True)

    events = events.dropna(subset=["tid", "ts"])
    if events.empty:
        meta["error"] = "no-events"
        return pd.DataFrame(), meta
    events["tid"] = events["tid"].astype("int64")
    events = events[events["tid"] > 0]  # exclude idle / invalid TIDs
    if events.empty:
        meta["error"] = "no-events"
        return pd.DataFrame(), meta

    events["pid"] = (
        pd.to_numeric(events["pid"], errors="coerce").fillna(0).astype("int64")
    )
    events["process"] = events["process"].fillna("").astype(str)

    # Canonicalize each thread's pid/process from its switch-IN rows: the
    # CSwitch payload only carries reliable New* identity (OldPID is 0 on the
    # native decoder), so a thread's real process is taken from where it ran.
    in_rows = events[events["kind"] == "in"]
    pid_map = (
        in_rows[in_rows["pid"] > 0].groupby("tid")["pid"].first()
    )
    proc_map = (
        in_rows[in_rows["process"].str.len() > 0]
        .groupby("tid")["process"]
        .first()
    )
    events["pid"] = (
        events["tid"].map(pid_map).fillna(events["pid"]).astype("int64")
    )
    events["process"] = (
        events["tid"].map(proc_map).fillna(events["process"]).astype(str)
    )

    if tid is not None:
        events = events[events["tid"] == int(tid)]
        if events.empty:
            meta["error"] = "no-events-for-tid"
            return pd.DataFrame(), meta

    # Order events per thread; ties at equal timestamps resolve switch-IN
    # before switch-OUT so a same-instant park pairs correctly. When a raw
    # EventSequence is available it is the primary tiebreak (native us-rounding
    # can collapse distinct events onto the same microsecond).
    events["korder"] = (events["kind"] == "out").astype(int)
    if seq_col:
        events = events.sort_values(
            ["tid", "ts", "seq", "korder"]
        ).reset_index(drop=True)
    else:
        events = events.sort_values(
            ["tid", "ts", "korder"]
        ).reset_index(drop=True)
    grp = events.groupby("tid", sort=False)
    events["next_ts"] = grp["ts"].shift(-1)
    events["next_kind"] = grp["kind"].shift(-1)
    # A thread still on-CPU / still waiting at the last event runs until the
    # window end.
    events["next_ts"] = events["next_ts"].fillna(window_end)

    raw_dur = events["next_ts"] - events["ts"]
    lost_mask = raw_dur < 0
    meta["lost_intervals"] = int(lost_mask.sum())

    ts_clip = events["ts"].clip(lower=window_start, upper=window_end)
    next_clip = events["next_ts"].clip(lower=window_start, upper=window_end)
    dur = (next_clip - ts_clip).clip(lower=0.0)
    dur = dur.mask(lost_mask, 0.0)
    events["dur"] = dur

    is_run = events["kind"] == "in"
    is_out = events["kind"] == "out"

    # BUG 3 FIX (#36): classify Waiting vs other off-CPU. The authoritative
    # signal is ``OldThreadState == "Waiting"``. The legacy dotnet-sidecar
    # CSwitch parquet lacks OldThreadState and carries only ``WaitReason``, so
    # fall back to it: every switch-out with a genuine wait reason is Waiting,
    # except involuntary/preemption reasons (quantum end, preempted, dispatch
    # interrupt, yield). Without this fallback waiting_ms was always 0 on
    # sidecar traces.
    state_vals = events["old_state"].astype(str).str.strip()
    has_state = state_col is not None and bool((state_vals.str.len() > 0).any())
    if has_state:
        meta["state_source"] = "OldThreadState"
        is_wait = is_out & state_vals.str.lower().isin(_WAIT_STATES)
    else:
        meta["state_source"] = "WaitReason"
        wait_vals = events["wait_reason"].astype(str).str.strip()
        is_preempt = wait_vals.str.lower().isin(_PREEMPT_WAIT_REASONS)
        is_wait = is_out & (wait_vals.str.len() > 0) & ~is_preempt
    is_other = is_out & ~is_wait
    events["is_wait_row"] = is_wait

    # Percentiles / mean cover only waits FULLY CONTAINED in the window (a wait
    # clipped by a window edge still adds to Waiting ms but its duration is
    # censored, so it must not skew the distribution).
    is_contained_wait = (
        is_wait
        & (events["next_kind"] == "in")
        & (events["ts"] >= window_start)
        & (events["next_ts"] <= window_end)
    )

    # BUG 4 FIX (#36): the Wait->Running (park/wake) transition count is a
    # switch-IN inside the window whose immediately-preceding thread event was a
    # Waiting switch-OUT — regardless of WHEN that switch-out happened. The old
    # code reused the fully-contained-wait predicate, so it missed an in-window
    # wake whose prior Waiting switch-out was before window_start.
    prev_is_wait = (
        events.groupby("tid", sort=False)["is_wait_row"].shift(1).fillna(False)
    )

    # NOTE: running time is attributed only from an OBSERVED switch-IN, exactly
    # like WPA's "CPU Usage (Precise)" (which keys each interval on the
    # switched-in "New Thread"). A thread whose first in-window event is a
    # switch-OUT is NOT credited with a synthesized [window_start, switch-out]
    # running interval: on real traces a thread's first observed event is often
    # a LATE switch-out (the thread's pool spun up mid-trace — see #36), so
    # synthesizing that leading interval grossly over-attributes running_ms
    # (measured ~1.5x inflation vs the xperf/per-CPU oracle on the i58 repro).
    events["run_s"] = events["dur"].where(is_run, 0.0)
    events["wait_s"] = events["dur"].where(is_wait, 0.0)
    events["other_s"] = events["dur"].where(is_other, 0.0)
    # Only switch-ins that occur WITHIN the (possibly time-filtered) window count
    # toward switch_ins / CSwitch-per-sec; otherwise a start_time/end_time filter
    # would divide out-of-window switch-ins by the filtered window and inflate the
    # rate. With no filter, window is [0, total], so every event counts.
    in_window = (events["ts"] >= window_start) & (events["ts"] <= window_end)
    events["switch_in"] = (is_run & in_window).astype("int64")
    # Wait->Running park count (in-window wake preceded by a Waiting switch-out).
    events["wait_to_run"] = (is_run & in_window & prev_is_wait).astype("int64")
    # Fully-contained waits feed the wait-duration percentiles only.
    events["completed"] = is_contained_wait.astype("int64")

    if group_by == "process":
        keys = ["pid", "process"]
        agg = (
            events.groupby(keys, sort=False)
            .agg(
                run_s=("run_s", "sum"),
                wait_s=("wait_s", "sum"),
                other_s=("other_s", "sum"),
                switch_ins=("switch_in", "sum"),
                wait_to_run=("wait_to_run", "sum"),
                threads=("tid", "nunique"),
            )
            .reset_index()
        )
    else:
        agg = (
            events.groupby("tid", sort=False)
            .agg(
                run_s=("run_s", "sum"),
                wait_s=("wait_s", "sum"),
                other_s=("other_s", "sum"),
                switch_ins=("switch_in", "sum"),
                wait_to_run=("wait_to_run", "sum"),
                pid=("pid", "first"),
                process=("process", "first"),
            )
            .reset_index()
        )

    # Percentiles over fully-contained wait intervals only.
    completed = events[is_contained_wait]
    if group_by == "process":
        pgrp = completed.groupby(["pid", "process"])["dur"]
        pkeys = ["pid", "process"]
    else:
        pgrp = completed.groupby("tid")["dur"]
        pkeys = ["tid"]

    if len(completed) > 0:
        pstats = pd.DataFrame(
            {
                "mean_wait_us": pgrp.mean() * 1e6,
                "p50_wait_us": pgrp.quantile(0.5) * 1e6,
                "p90_wait_us": pgrp.quantile(0.9) * 1e6,
                "p99_wait_us": pgrp.quantile(0.99) * 1e6,
            }
        ).reset_index()
        agg = agg.merge(pstats, on=pkeys, how="left")
    for col in ("mean_wait_us", "p50_wait_us", "p90_wait_us", "p99_wait_us"):
        if col not in agg.columns:
            agg[col] = 0.0
        agg[col] = agg[col].fillna(0.0)

    agg["running_ms"] = agg["run_s"] * 1000.0
    agg["waiting_ms"] = agg["wait_s"] * 1000.0
    agg["other_ms"] = agg["other_s"] * 1000.0
    agg["running_pct"] = agg["run_s"] / window_seconds * 100.0
    agg["waiting_pct"] = agg["wait_s"] / window_seconds * 100.0
    agg["cswitch_per_s"] = agg["switch_ins"] / window_seconds
    agg["wait_to_run_per_s"] = agg["wait_to_run"] / window_seconds

    if process_filter:
        needle = process_filter.lower()
        agg = agg[agg["process"].str.lower().str.contains(needle, na=False)]

    sort_col = sort_by if sort_by in _SORT_COLUMNS else "running_ms"
    agg = agg.sort_values(sort_col, ascending=False).reset_index(drop=True)

    return agg, meta


def _render(agg: pd.DataFrame, meta: dict, group_by: str, max_rows: int) -> str:
    disp = pd.DataFrame()
    disp["Process"] = agg["process"].replace("", "<unknown>")
    disp["PID"] = agg["pid"].astype("int64")
    if group_by == "process":
        disp["Threads"] = agg["threads"].astype("int64")
    else:
        disp["ThreadID"] = agg["tid"].astype("int64")
    disp["Running ms"] = agg["running_ms"].round(3)
    disp["Running %"] = agg["running_pct"].map(format_pct)
    disp["Waiting ms"] = agg["waiting_ms"].round(3)
    disp["Waiting %"] = agg["waiting_pct"].map(format_pct)
    disp["Other off-CPU ms"] = agg["other_ms"].round(3)
    disp["Switch-ins"] = agg["switch_ins"].astype("int64")
    disp["CSwitch/s"] = agg["cswitch_per_s"].round(1)
    disp["Wait->Run"] = agg["wait_to_run"].astype("int64")
    disp["Wait->Run/s"] = agg["wait_to_run_per_s"].round(1)
    disp["Mean wait us"] = agg["mean_wait_us"].round(1)
    disp["P50 wait us"] = agg["p50_wait_us"].round(1)
    disp["P90 wait us"] = agg["p90_wait_us"].round(1)
    disp["P99 wait us"] = agg["p99_wait_us"].round(1)
    return format_table(disp, max_rows=max_rows)


@mcp.tool()
def get_thread_cpu_precise(
    trace_id: str,
    process_filter: str | None = None,
    tid: int | None = None,
    cpu_filter: str | None = None,
    start_time: float | None = None,
    end_time: float | None = None,
    group_by: str = "thread",
    sort_by: str = "running_ms",
    max_rows: int = 50,
) -> str:
    """Precise per-thread CPU running/waiting analysis from context switches.

    Reconstructs, per thread, how long it was actually Running on a CPU versus
    Waiting off-CPU — the WPA "CPU Usage (Precise)" view — using only CSwitch
    events (no CPU sampling required). Useful for spotting threads that park and
    wake frequently (lock contention, IO waits) or that are CPU-bound.

    A thread is Running from a switch-IN (NewTID) until its next switch-OUT
    (OldTID). It is Waiting when it switches out with OldThreadState==Waiting,
    until its next switch-in; other off-CPU states are reported separately.
    Wait durations (mean/p50/p90/p99) cover completed waits only. When the trace
    carries ReadyThread events, wake attribution is available.

    Args:
        trace_id: ID returned by load_trace.
        process_filter: Case-insensitive substring match on the image name.
        tid: Restrict to a single thread ID.
        cpu_filter: CPU range filter, e.g. '0' or '0-7,16'.
        start_time: Start of analysis window in seconds from trace start.
        end_time: End of analysis window in seconds from trace start.
        group_by: 'thread', 'process', or 'process+thread'. Default 'thread'.
        sort_by: Column to sort by (running_ms, waiting_ms, switch_ins,
            cswitch_per_s, wait_to_run, mean_wait_us, ...). Default 'running_ms'.
        max_rows: Maximum rows to return. Default 50.
    """
    trace = require_trace(trace_id)
    trace.wait_for_dumper()

    if group_by not in _GROUP_BY_CHOICES:
        return (
            f"*Invalid group_by '{group_by}'. Choose one of: "
            f"{', '.join(sorted(_GROUP_BY_CHOICES))}.*"
        )

    agg, meta = compute_thread_cpu_precise(
        trace,
        process_filter=process_filter,
        tid=tid,
        cpu_filter=cpu_filter,
        start_time=start_time,
        end_time=end_time,
        group_by=group_by,
        sort_by=sort_by,
    )

    if meta.get("error") == "no-cswitch":
        return (
            "*No CSwitch (context-switch) data available. The trace was likely "
            "captured with a CPU-sampling-only profile. Recollect with a "
            "cswitch/GeneralProfile capture (includes CSwitch + ReadyThread) to "
            "use get_thread_cpu_precise.*"
        )
    if meta.get("error") == "missing-columns":
        return "*CSwitch data is present but missing TimeStamp/NewTID/OldTID columns.*"
    if agg.empty or meta.get("error"):
        return "*No threads match the specified filters.*"

    window_seconds = meta["window_seconds"]
    header = f"**Thread CPU (Precise)** (grouped by {group_by})"
    filters = []
    if process_filter:
        filters.append(f"process~='{process_filter}'")
    if tid is not None:
        filters.append(f"tid={tid}")
    if cpu_filter:
        filters.append(f"cpu={cpu_filter}")
    if start_time is not None or end_time is not None:
        filters.append(
            f"window=[{start_time if start_time is not None else 0:.4f}, "
            f"{end_time if end_time is not None else window_seconds:.4f}]s"
        )
    if filters:
        header += "\n" + ", ".join(filters)
    header += f"\nAnalysis window: {window_seconds:.4f}s"

    if meta["readythread_available"]:
        header += (
            f"\nReadyThread attribution: available "
            f"({meta['readythread_events']:,} ready events)"
        )
    else:
        header += (
            "\nReadyThread attribution: unavailable "
            "(computed from CSwitch only)"
        )
    if meta["lost_intervals"]:
        header += (
            f"\n*Warning: dropped {meta['lost_intervals']:,} negative/overlapping "
            "intervals (lost switch events).*"
        )

    return f"{header}\n\n{_render(agg, meta, group_by, max_rows)}"
