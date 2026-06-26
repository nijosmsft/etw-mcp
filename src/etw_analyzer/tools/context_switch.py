"""Context switch / lock contention analysis tools."""

from __future__ import annotations

from etw_analyzer.app import mcp
from etw_analyzer.trace_state import TraceData, require_trace
from etw_analyzer.parsing.aggregator import apply_filters, group_and_sum
from etw_analyzer.parsing.csv_loader import normalize_duration_column
from etw_analyzer.formatting.markdown import format_table, format_pct
from etw_analyzer.tools.cpu_sampling import _find_col
from etw_analyzer.native.accessors import (
    has_event_store_dataset,
    iter_readythread_cswitch_waits,
)
from etw_analyzer.native.event_store import EventFilters

import pandas as pd


def _get_cswitch_df(
    trace: TraceData,
    start_time: float | None = None,
    end_time: float | None = None,
) -> pd.DataFrame:
    """Get context switch / ReadyThread DataFrame.

    Checks for pre-loaded data first (from WPA export or prior on-demand run).
    Falls back to running ``xperf -a readythread -stacks -symbols`` on-demand,
    caching the result for future calls.
    """
    # Check for pre-loaded data
    with trace.lock:
        for key in ["readythread", "cswitch", "CSwitch", "CPU Usage (Precise)", "context_switch"]:
            if key in trace.raw_csv:
                df = trace.raw_csv[key]
                # Skip raw-text wrapper DataFrames (single "raw_text" column)
                # and empty placeholders (e.g. a 0-row readythread the sidecar
                # wrote when no ReadyThread events were captured).
                if "raw_text" not in df.columns and not df.empty:
                    return df.copy()

        # Native/dotnet sidecar: the CSwitch events live on a dedicated
        # attribute / parquet (excluded from raw_csv), not under the keys
        # above. Surface them so the context-switch summary works even
        # though the capture lacks ReadyThread readying stacks.
        native_cswitch = _load_native_cswitch_df(trace)
        if native_cswitch is not None and not native_cswitch.empty:
            trace.raw_csv["cswitch"] = native_cswitch
            return native_cswitch.copy()

        # An empty pre-loaded placeholder (e.g. a 0-row readythread/cswitch)
        # means the trace was decoded but carried no such events. Return it
        # gracefully so callers report "no data" rather than triggering an
        # xperf on-demand pass (which would fail on native/dotnet caches).
        for key in ["readythread", "cswitch", "CSwitch", "CPU Usage (Precise)", "context_switch"]:
            if key in trace.raw_csv and "raw_text" not in trace.raw_csv[key].columns:
                return trace.raw_csv[key].copy()

        # On-demand: run xperf -a readythread -stacks -symbols
        from etw_analyzer.parsing.wpa_exporter import run_readythread

        df = run_readythread(
            trace.etl_path,
            symbol_path=trace.symbol_path,
            start_time=start_time,
            end_time=end_time,
            timeout_seconds=300,
        )
        if df.empty:
            raise ValueError(
                "No ReadyThread data found. The trace was likely collected with "
                "`wpr -start CPU` which only captures CPU sampling.\n\n"
                "To capture context switch and ReadyThread data, use:\n"
                "  wpr -start GeneralProfile    (includes CSwitch + ReadyThread)\n\n"
                "ReadyThread stacks are needed for lock contention analysis."
            )

        # Cache for future calls
        trace.raw_csv["readythread"] = df
        return df.copy()


def _ensure_cswitch_process_names(trace: TraceData, df: pd.DataFrame) -> pd.DataFrame:
    """Synthesize ``OldProcessName``/``NewProcessName`` when the frame lacks them.

    The dotnet sidecar CSwitch schema is
    ``{EventSequence, TimeStamp, CPU, NewTID, OldTID, NewPID, OldPID,
    WaitReason, Stack}`` — it has no process-name columns, unlike the native
    schema (issue #12). Without them, process-name filtering / grouping in
    ``get_lock_contention`` silently produces nothing. Build a PID→name map
    from the process-event table and add the missing columns so both schemas
    behave the same. Best-effort: if no PID columns or no process data are
    available, the frame is returned unchanged.
    """
    if df is None or df.empty:
        return df
    has_new = "NewProcessName" in df.columns
    has_old = "OldProcessName" in df.columns
    if has_new and has_old:
        return df
    pid_col_new = _find_col(df, ["NewPID", "NewProcessId", "New PID"])
    pid_col_old = _find_col(df, ["OldPID", "OldProcessId", "Old PID"])
    if not pid_col_new and not pid_col_old:
        return df
    try:
        from etw_analyzer.native.aggregators.profile_detail import (
            _build_pid_to_name_map,
        )
        pid_map = _build_pid_to_name_map(trace)
    except Exception:
        pid_map = {}
    if not pid_map:
        return df
    df = df.copy()
    if not has_new and pid_col_new:
        df["NewProcessName"] = (
            pd.to_numeric(df[pid_col_new], errors="coerce")
            .map(pid_map)
            .fillna("")
            .astype(str)
        )
    if not has_old and pid_col_old:
        df["OldProcessName"] = (
            pd.to_numeric(df[pid_col_old], errors="coerce")
            .map(pid_map)
            .fillna("")
            .astype(str)
        )
    return df


def _load_native_cswitch_df(trace: TraceData) -> pd.DataFrame | None:
    """Return the native/dotnet CSwitch events frame, if present.

    The sidecar persists CSwitch events (NewTID/OldTID/NewPID/OldPID/
    WaitReason/CPU/TimeStamp) on ``trace.cswitch_events_df`` or in
    ``cswitch_events.parquet`` (excluded from raw_csv). This capture form has
    no readying stacks, so only a context-switch / WaitReason summary is
    possible — but that is far better than reporting no data at all.

    The dotnet CSwitch schema lacks ``OldProcessName``/``NewProcessName``;
    they are synthesized here from the PID→name map so process-level grouping
    works on both schemas (issue #12).
    """
    df = getattr(trace, "cswitch_events_df", None)
    if df is not None and not df.empty:
        return _ensure_cswitch_process_names(trace, df)
    export_dir = getattr(trace, "export_dir", None)
    if export_dir is None:
        return None
    parquet_path = export_dir / "cswitch_events.parquet"
    if not parquet_path.exists():
        return None
    try:
        df = pd.read_parquet(parquet_path)
    except Exception:
        return None
    if df is None or df.empty:
        return None
    return _ensure_cswitch_process_names(trace, df)


@mcp.tool()
def get_lock_contention(
    trace_id: str,
    module_filter: str | None = None,
    function_filter: str | None = None,
    cpu_filter: str | None = None,
    start_time: float | None = None,
    end_time: float | None = None,
    max_rows: int = 30,
) -> str:
    """Analyze lock contention from ReadyThread stacks.

    Looks at context switch data for spinlock wait patterns. High contention
    on KeAcquireInStackQueuedSpinLock in CPUMAP code indicates the per-CPU
    ring spinlock is a bottleneck.

    Requires ReadyThread stacks, either from the xperf on-demand
    ``readythread -stacks`` path or a native event-store loaded with
    ``ETW_MCP_NATIVE_STREAMING_PROFILE=all``. Native mode is a coverage
    subset and does not yet implement every xperf CSwitch view.

    Args:
        trace_id: ID returned by load_trace.
        module_filter: Filter by module in the readying stack, e.g. 'xdp.sys'.
        function_filter: Filter by function in the readying stack.
        cpu_filter: CPU range filter, e.g. '18-39'.
        start_time: Start of analysis window (seconds from trace start).
        end_time: End of analysis window (seconds from trace start).
        max_rows: Maximum rows to return. Default: 30.
    """
    trace = require_trace(trace_id)

    if (
        has_event_store_dataset(trace, "readythread")
        and has_event_store_dataset(trace, "cswitch")
    ):
        return _get_lock_contention_from_event_store(
            trace,
            module_filter=module_filter,
            function_filter=function_filter,
            cpu_filter=cpu_filter,
            start_time=start_time,
            end_time=end_time,
            max_rows=max_rows,
        )

    df = _get_cswitch_df(trace, start_time=start_time, end_time=end_time)

    # Find relevant columns
    cpu_col = _find_col(df, ["CPU", "Cpu", "New CPU"]) or "CPU"
    time_col = _find_col(df, ["TimeStamp", "Time", "Switch-In Time"]) or "TimeStamp"
    ready_stack_col = _find_col(df, [
        "ReadyThread Stack", "Ready Thread Stack", "Readying Stack",
        "ReadyingProcess Stack",
    ])
    wait_col = _find_col(df, [
        "Wait (us)", "Wait Duration", "Time Since Last",
        "Ready Time", "Wait Time",
    ])
    new_process_col = _find_col(df, [
        "New Process Name", "NewProcessName", "New Process", "Process Name",
    ]) or "New Process Name"
    ready_process_col = _find_col(df, ["Readying Process Name", "Readying Process"]) or "Readying Process Name"

    # Normalize wait time
    if wait_col:
        df = normalize_duration_column(df, wait_col)

    # Apply base filters
    df = apply_filters(
        df,
        cpu_filter=cpu_filter, cpu_col=cpu_col,
        start_time=start_time, end_time=end_time, time_col=time_col,
    )

    if df.empty:
        return "*No context switch events match the specified filters.*"

    # Look for spinlock-related patterns in ReadyThread stacks
    spinlock_patterns = [
        "KeAcquireInStackQueuedSpinLock",
        "KeAcquireSpinLock",
        "KeTryToAcquireSpinLock",
        "ExAcquireResourceExclusiveLite",
        "ExAcquireResourceSharedLite",
        "ExAcquireFastMutex",
    ]

    if ready_stack_col and ready_stack_col in df.columns:
        # Filter to entries where readying stack contains lock functions
        if module_filter:
            df = df[df[ready_stack_col].astype(str).str.contains(
                module_filter, case=False, na=False
            )]
        if function_filter:
            df = df[df[ready_stack_col].astype(str).str.contains(
                function_filter, case=False, na=False
            )]

        # Identify spinlock contention
        lock_mask = df[ready_stack_col].astype(str).apply(
            lambda s: any(p.lower() in s.lower() for p in spinlock_patterns)
        )
        lock_df = df[lock_mask]
        nonlock_df = df[~lock_mask]

        total_events = len(df)
        lock_events = len(lock_df)
        lock_pct = lock_events / total_events * 100 if total_events > 0 else 0

        lines = [
            "**Lock Contention Analysis**",
            "",
            f"Total context switches: {total_events:,}",
            f"Lock-related switches: {lock_events:,} ({lock_pct:.1f}%)",
            "",
        ]

        if lock_events > 0 and wait_col and wait_col in lock_df.columns:
            wait_times = lock_df[wait_col].dropna()
            if not wait_times.empty:
                lines.append(f"Lock wait time: median={wait_times.median():.1f}us, "
                           f"p99={wait_times.quantile(0.99):.1f}us, "
                           f"max={wait_times.max():.1f}us")
                lines.append("")

        # Group by readying stack to find top contention sites
        if lock_events > 0:
            # Extract module!function from the top frame of readying stack
            lock_df = lock_df.copy()
            lock_df["_contention_site"] = lock_df[ready_stack_col].astype(str).apply(
                _extract_contention_site
            )
            site_counts = lock_df.groupby("_contention_site").size().reset_index(name="Count")
            site_counts["% of Lock Waits"] = (site_counts["Count"] / lock_events * 100).apply(format_pct)
            site_counts = site_counts.sort_values("Count", ascending=False).head(max_rows)
            site_counts = site_counts.rename(columns={"_contention_site": "Contention Site"})

            lines.append("**Top Contention Sites:**")
            lines.append("")
            lines.append(format_table(site_counts))

        # CPUMAP-specific assessment
        if lock_pct > 10:
            lines.append(f"\n**ALERT:** Lock contention at {lock_pct:.1f}% — above 10% threshold. "
                        "Consider lock-free SPSC rings for CPUMAP.")
        elif lock_pct > 5:
            lines.append(f"\nLock contention at {lock_pct:.1f}% — moderate. Monitor under higher load.")
        else:
            lines.append(f"\nLock contention at {lock_pct:.1f}% — within healthy range.")

        return "\n".join(lines)

    else:
        # No ReadyThread stack column — fall back to basic process-level analysis
        lines = [
            "**Context Switch Summary** (no ReadyThread stacks available)",
            "",
            f"Total context switches: {len(df):,}",
            "",
            "For lock contention analysis, collect a trace with ReadyThread "
            "stacks (e.g. the cpu_dpc_isr profile with ReadyThread keyword + "
            "stacks); readying stacks are required to attribute lock holders.",
            "",
        ]

        # WaitReason distribution — the one contention signal a stackless
        # native CSwitch frame carries (why threads were switched out).
        wait_reason_col = _find_col(df, ["WaitReason", "Wait Reason", "OldThreadWaitReason"])
        if wait_reason_col and wait_reason_col in df.columns:
            wr = (
                df[wait_reason_col].astype(str).replace("", "(unset)")
                .value_counts().head(max_rows)
            )
            if not wr.empty:
                total = int(wr.sum())
                wr_df = pd.DataFrame({
                    "Wait Reason": wr.index,
                    "Count": wr.values,
                    "% of Switches": [format_pct(c / total * 100) for c in wr.values],
                })
                lines.append("**Switch-Out Wait Reasons:**")
                lines.append("")
                lines.append(format_table(wr_df))
                lines.append("")

        # Group by process. Without a numeric wait column there is nothing to
        # sum, so count switches per process instead (summing the string
        # process-name column raised "cannot insert ... already exists").
        if new_process_col in df.columns:
            if wait_col and wait_col in df.columns:
                result = group_and_sum(df, [new_process_col], sum_col=wait_col)
            else:
                counts = (
                    df[new_process_col].astype(str).replace("", "(unknown)")
                    .value_counts().head(max_rows)
                )
                result = pd.DataFrame({
                    new_process_col: counts.index,
                    "Count": counts.values,
                }) if not counts.empty else pd.DataFrame()
            if not result.empty:
                lines.append("**Context Switches by Process:**")
                lines.append("")
                lines.append(format_table(result.head(max_rows)))

        return "\n".join(lines)


def _get_lock_contention_from_event_store(
    trace: TraceData,
    *,
    module_filter: str | None,
    function_filter: str | None,
    cpu_filter: str | None,
    start_time: float | None,
    end_time: float | None,
    max_rows: int,
) -> str:
    filters = EventFilters(
        cpu_filter=cpu_filter,
        start_time=start_time,
        end_time=end_time,
    )
    spinlock_patterns = [
        "KeAcquireInStackQueuedSpinLock",
        "KeAcquireSpinLock",
        "KeTryToAcquireSpinLock",
        "ExAcquireResourceExclusiveLite",
        "ExAcquireResourceSharedLite",
        "ExAcquireFastMutex",
    ]

    total_events = 0
    lock_events = 0
    wait_values: list[float] = []
    site_counts: dict[str, int] = {}

    for batch in iter_readythread_cswitch_waits(trace, filters=filters):
        if batch.empty:
            continue
        stack_col = _find_col(batch, [
            "ReadyThread Stack", "Ready Thread Stack", "Readying Stack",
            "ReadyingProcess Stack",
        ])
        if stack_col is None:
            total_events += len(batch)
            continue
        stacks = batch[stack_col].astype(str)
        if module_filter:
            batch = batch[stacks.str.contains(module_filter, case=False, na=False)]
            stacks = batch[stack_col].astype(str)
        if function_filter:
            batch = batch[stacks.str.contains(function_filter, case=False, na=False)]
            stacks = batch[stack_col].astype(str)
        if batch.empty:
            continue

        total_events += len(batch)
        lock_mask = stacks.apply(
            lambda s: any(p.lower() in s.lower() for p in spinlock_patterns)
        )
        lock_df = batch[lock_mask]
        lock_events += len(lock_df)
        if not lock_df.empty and "Wait (us)" in lock_df.columns:
            wait_values.extend(
                pd.to_numeric(lock_df["Wait (us)"], errors="coerce")
                .dropna()
                .astype(float)
                .tolist()
            )
        if not lock_df.empty:
            for site, count in (
                lock_df[stack_col]
                .astype(str)
                .apply(_extract_contention_site)
                .value_counts()
                .items()
            ):
                site_counts[str(site)] = site_counts.get(str(site), 0) + int(count)

    if total_events == 0:
        return "*No context switch events match the specified filters.*"

    lock_pct = lock_events / total_events * 100 if total_events > 0 else 0
    lines = [
        "**Lock Contention Analysis**",
        "",
        f"Total context switches: {total_events:,}",
        f"Lock-related switches: {lock_events:,} ({lock_pct:.1f}%)",
        "",
    ]

    if wait_values:
        waits = pd.Series(wait_values)
        lines.append(
            f"Lock wait time: median={waits.median():.1f}us, "
            f"p99={waits.quantile(0.99):.1f}us, "
            f"max={waits.max():.1f}us"
        )
        lines.append("")

    if site_counts:
        site_rows = pd.DataFrame([
            {
                "Contention Site": site,
                "Count": count,
                "% of Lock Waits": format_pct(count / lock_events * 100 if lock_events else 0),
            }
            for site, count in site_counts.items()
        ]).sort_values("Count", ascending=False).head(max_rows)
        lines.append("**Top Contention Sites:**")
        lines.append("")
        lines.append(format_table(site_rows))

    if lock_pct > 10:
        lines.append(f"\n**ALERT:** Lock contention at {lock_pct:.1f}% — above 10% threshold. "
                    "Consider lock-free SPSC rings for CPUMAP.")
    elif lock_pct > 5:
        lines.append(f"\nLock contention at {lock_pct:.1f}% — moderate. Monitor under higher load.")
    else:
        lines.append(f"\nLock contention at {lock_pct:.1f}% — within healthy range.")
    return "\n".join(lines)


def _extract_contention_site(stack_str: str) -> str:
    """Extract the most relevant lock function from a stack string."""
    lock_funcs = [
        "KeAcquireInStackQueuedSpinLock",
        "KeAcquireSpinLock",
        "ExAcquireResourceExclusiveLite",
        "ExAcquireFastMutex",
    ]

    frames = []
    if " / " in stack_str:
        frames = stack_str.split(" / ")
    elif "\n" in stack_str:
        frames = stack_str.split("\n")
    elif " <- " in stack_str:
        frames = stack_str.split(" <- ")

    # Find the lock acquisition frame and its caller
    for i, frame in enumerate(frames):
        for func in lock_funcs:
            if func.lower() in frame.lower():
                # Return the lock function and its caller
                caller = frames[i + 1].strip() if i + 1 < len(frames) else "?"
                return f"{frame.strip()} <- {caller}"

    # Fall back to first frame
    return frames[0].strip() if frames else stack_str[:80]
