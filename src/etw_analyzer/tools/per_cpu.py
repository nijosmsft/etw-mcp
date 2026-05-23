"""Per-CPU distribution analysis tools."""

from __future__ import annotations

import re

import numpy as np

from etw_analyzer.app import mcp
from etw_analyzer.trace_state import TraceData, require_trace
from etw_analyzer.parsing.aggregator import apply_filters, time_bucket
from etw_analyzer.tools.cpu_sampling import _get_sampling_df, _find_col
from etw_analyzer.formatting.markdown import format_table, format_pct

import pandas as pd


def _get_cpu_timeline_df(trace: TraceData) -> pd.DataFrame | None:
    """Get the cpu_timeline DataFrame.

    This dataset has columns: StartTime, EndTime, Cpu 0, Cpu 1, ..., Cpu N
    where each Cpu column contains utilization % for that time bucket.
    Returns None if not available.
    """
    return trace.raw_csv.get("cpu_timeline")


def _parse_cpu_range(cpu_filter: str) -> set[int]:
    """Parse a CPU range string like '0-7,16,18-20' into a set of CPU IDs."""
    cpus: set[int] = set()
    for part in cpu_filter.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            cpus.update(range(int(lo), int(hi) + 1))
        else:
            cpus.add(int(part))
    return cpus


@mcp.tool()
def get_per_cpu_summary(
    trace_id: str,
    start_time: float | None = None,
    end_time: float | None = None,
    max_rows: int = 80,
) -> str:
    """Get per-CPU utilization breakdown.

    Uses per-CPU utilization timeline data to show average
    utilization per CPU. Identifies hot CPUs (RSS, CPUMAP targets)
    vs idle CPUs.

    Args:
        trace_id: ID returned by load_trace.
        start_time: Start of analysis window (seconds from trace start).
        end_time: End of analysis window (seconds from trace start).
        max_rows: Maximum CPUs to show. Default: 80.
    """
    trace = require_trace(trace_id)
    timeline_df = _get_cpu_timeline_df(trace)

    if timeline_df is not None and not timeline_df.empty:
        return _per_cpu_from_timeline(timeline_df, start_time, end_time, max_rows)

    # Fall back to cpu_sampling if cpu_timeline not available
    return _per_cpu_from_sampling(trace, start_time, end_time, max_rows)


def _per_cpu_from_timeline(
    df: pd.DataFrame,
    start_time: float | None,
    end_time: float | None,
    max_rows: int,
) -> str:
    """Build per-CPU summary from utilization timeline data."""
    # Columns: StartTime, EndTime, Cpu 0, Cpu 1, ...
    # Times are in microseconds
    start_col = _find_col(df, ["StartTime", "Start Time"]) or "StartTime"
    end_col = _find_col(df, ["EndTime", "End Time"]) or "EndTime"

    if start_col not in df.columns:
        return f"*cpu_timeline missing StartTime column. Available: {', '.join(df.columns)}*"

    # Apply time filter (convert seconds to microseconds)
    filtered = df.copy()
    if start_time is not None:
        filtered = filtered[filtered[start_col] >= start_time * 1_000_000]
    if end_time is not None:
        filtered = filtered[filtered[end_col] <= end_time * 1_000_000]

    if filtered.empty:
        return "*No data in the specified time range.*"

    # Find CPU columns (pattern: "Cpu N" or "Cpu  N")
    cpu_cols = {}
    for col in filtered.columns:
        m = re.match(r"Cpu\s+(\d+)", col, re.IGNORECASE)
        if m:
            cpu_cols[int(m.group(1))] = col

    if not cpu_cols:
        return f"*No CPU columns found. Available: {', '.join(df.columns)}*"

    # Compute average utilization per CPU across time buckets
    rows = []
    for cpu_id in sorted(cpu_cols.keys()):
        col = cpu_cols[cpu_id]
        vals = pd.to_numeric(filtered[col], errors="coerce").dropna()
        if vals.empty:
            avg_util = 0.0
            max_util = 0.0
        else:
            avg_util = float(vals.mean())
            max_util = float(vals.max())

        # Classify CPU role by utilization level
        if avg_util >= 80:
            role = "Saturated"
        elif avg_util >= 20:
            role = "Active"
        elif avg_util >= 2:
            role = "Low activity"
        else:
            role = "Idle"

        rows.append({
            "CPU": cpu_id,
            "Avg %": f"{avg_util:.1f}%",
            "Max %": f"{max_util:.1f}%",
            "_avg": avg_util,  # for sorting
            "Role": role,
        })

    result = pd.DataFrame(rows)

    # Sort by avg utilization descending, show busiest CPUs first
    result = result.sort_values("_avg", ascending=False).head(max_rows).reset_index(drop=True)
    result = result.drop(columns=["_avg"])

    # Summary stats
    all_avgs = [r["_avg"] if "_avg" in r else 0 for r in rows]
    role_counts = pd.Series([r["Role"] for r in rows]).value_counts()
    summary = ", ".join(f"{role}: {count}" for role, count in role_counts.items())

    active_cpus = sum(1 for r in rows if float(r["Avg %"].rstrip("%")) >= 2)
    total_cpus = len(rows)

    footer = (
        f"\n**CPU Roles:** {summary}"
        f"\n**Active CPUs:** {active_cpus}/{total_cpus}"
    )

    return f"**Per-CPU Summary** (from utilization data)\n\n{format_table(result, max_rows=max_rows)}{footer}"


def _per_cpu_from_sampling(
    trace: TraceData,
    start_time: float | None,
    end_time: float | None,
    max_rows: int,
) -> str:
    """Fallback: build per-CPU summary from cpu_sampling data (less precise)."""
    try:
        df = _get_sampling_df(trace)
    except ValueError as e:
        return f"*{e}*"

    weight_col = _find_col(df, ["Weight", "Count", "Sample Count"]) or "Weight"
    cpu_col = _find_col(df, ["CPU", "Cpu"]) or "CPU"
    time_col = _find_col(df, ["TimeStamp", "Time"]) or "TimeStamp"
    module_col = _find_col(df, ["Module", "Image"]) or "Module"

    df = apply_filters(df, start_time=start_time, end_time=end_time, time_col=time_col)

    if df.empty:
        return "*No sampling data in the specified time range.*"

    if cpu_col not in df.columns:
        return f"*No CPU column found in sampling data. Available: {', '.join(df.columns)}*"

    total_weight = df[weight_col].sum() if weight_col in df.columns else len(df)

    rows = []
    for cpu, group in df.groupby(cpu_col, dropna=False):
        cpu_weight = group[weight_col].sum() if weight_col in group.columns else len(group)
        cpu_pct = cpu_weight / total_weight * 100 if total_weight > 0 else 0

        row = {"CPU": cpu, "Weight": cpu_weight, "% Total": format_pct(cpu_pct)}
        rows.append(row)

    result = pd.DataFrame(rows)
    result = result.sort_values("CPU").head(max_rows).reset_index(drop=True)
    return f"**Per-CPU Summary** (from sampling data)\n\n{format_table(result, max_rows=max_rows)}"


@mcp.tool()
def get_cpu_timeline(
    trace_id: str,
    cpu_filter: str | None = None,
    bucket_seconds: float = 1.0,
    start_time: float | None = None,
    end_time: float | None = None,
    max_rows: int = 60,
) -> str:
    """Get per-CPU utilization timeline.

    Shows per-CPU utilization % for each time bucket. Use to identify
    which CPUs are hot (RSS queues, CPUMAP targets) vs idle, and find
    steady-state windows.

    Args:
        trace_id: ID returned by load_trace.
        cpu_filter: CPU range filter, e.g. '0-15' for RSS CPUs only.
        bucket_seconds: Used by sampling fallback; utilization timelines keep their source bucket size.
        start_time: Start of analysis window (seconds from trace start).
        end_time: End of analysis window (seconds from trace start).
        max_rows: Maximum time buckets to show. Default: 60.
    """
    trace = require_trace(trace_id)
    timeline_df = _get_cpu_timeline_df(trace)

    if timeline_df is not None and not timeline_df.empty:
        return _timeline_from_util(timeline_df, cpu_filter, start_time, end_time, max_rows)

    # Fall back to sampling-based timeline
    return _timeline_from_sampling(trace, cpu_filter, bucket_seconds, start_time, end_time, max_rows)


def _timeline_from_util(
    df: pd.DataFrame,
    cpu_filter: str | None,
    start_time: float | None,
    end_time: float | None,
    max_rows: int,
) -> str:
    """Build timeline from utilization data."""
    start_col = _find_col(df, ["StartTime", "Start Time"]) or "StartTime"
    end_col = _find_col(df, ["EndTime", "End Time"]) or "EndTime"

    if start_col not in df.columns:
        return f"*cpu_timeline missing StartTime column. Available: {', '.join(df.columns)}*"

    # Find CPU columns
    cpu_cols = {}
    for col in df.columns:
        m = re.match(r"Cpu\s+(\d+)", col, re.IGNORECASE)
        if m:
            cpu_cols[int(m.group(1))] = col

    if not cpu_cols:
        return f"*No CPU columns found. Available: {', '.join(df.columns)}*"

    # Filter to requested CPUs
    if cpu_filter:
        requested = _parse_cpu_range(cpu_filter)
        cpu_cols = {k: v for k, v in cpu_cols.items() if k in requested}
        if not cpu_cols:
            return f"*No matching CPUs for filter '{cpu_filter}'.*"

    # Apply time filter (times are in microseconds)
    filtered = df.copy()
    if start_time is not None:
        filtered = filtered[filtered[start_col] >= start_time * 1_000_000]
    if end_time is not None:
        filtered = filtered[filtered[end_col] <= end_time * 1_000_000]

    if filtered.empty:
        return "*No data in the specified time range.*"

    # Build output table: Time(s), then each CPU column
    rows = []
    for _, row in filtered.head(max_rows).iterrows():
        t_start = row[start_col] / 1_000_000  # us → s
        t_end = row[end_col] / 1_000_000
        out = {"Time (s)": f"{t_start:.0f}-{t_end:.0f}"}

        for cpu_id in sorted(cpu_cols.keys()):
            val = row[cpu_cols[cpu_id]]
            try:
                val = float(val)
                out[f"CPU {cpu_id}"] = f"{val:.1f}%" if val >= 0.1 else "-"
            except (ValueError, TypeError):
                out[f"CPU {cpu_id}"] = "-"

        rows.append(out)

    result = pd.DataFrame(rows)

    header = "**CPU Timeline** (per-CPU utilization %)"
    if cpu_filter:
        header += f" — CPUs: {cpu_filter}"

    # Add summary: which CPUs are hot in the last bucket
    if rows:
        hot_cpus = []
        last_row = rows[-1] if len(rows) == 1 else rows[0]  # Use first steady-state row
        for cpu_id in sorted(cpu_cols.keys()):
            key = f"CPU {cpu_id}"
            if key in last_row and last_row[key] != "-":
                val = float(last_row[key].rstrip("%"))
                if val >= 10:
                    hot_cpus.append((cpu_id, val))
        if hot_cpus:
            hot_cpus.sort(key=lambda x: x[1], reverse=True)
            hot_desc = ", ".join(f"CPU {c}: {v:.0f}%" for c, v in hot_cpus[:20])
            footer = f"\n**Hot CPUs (>=10%):** {hot_desc}"
        else:
            footer = "\n*No CPUs above 10% utilization.*"
    else:
        footer = ""

    return f"{header}\n\n{format_table(result, max_rows=max_rows)}{footer}"


def _timeline_from_sampling(
    trace: TraceData,
    cpu_filter: str | None,
    bucket_seconds: float,
    start_time: float | None,
    end_time: float | None,
    max_rows: int,
) -> str:
    """Fallback: build timeline from cpu_sampling data."""
    try:
        df = _get_sampling_df(trace)
    except ValueError as e:
        return f"*{e}*"

    weight_col = _find_col(df, ["Weight", "Count", "Sample Count"]) or "Weight"
    cpu_col = _find_col(df, ["CPU", "Cpu"]) or "CPU"
    time_col = _find_col(df, ["TimeStamp", "Time"]) or "TimeStamp"

    if time_col not in df.columns:
        return f"*No timestamp column found. Available: {', '.join(df.columns)}*"

    df = apply_filters(
        df,
        cpu_filter=cpu_filter, cpu_col=cpu_col,
        start_time=start_time, end_time=end_time, time_col=time_col,
    )

    if df.empty:
        return "*No data in the specified range.*"

    df[time_col] = pd.to_numeric(df[time_col], errors="coerce")
    df = df.dropna(subset=[time_col])

    if df.empty:
        return "*No valid timestamps in the data.*"

    df = time_bucket(df, time_col, bucket_seconds)

    timeline = df.groupby("TimeBucket").agg(
        **{weight_col: (weight_col, "sum") if weight_col in df.columns else ("TimeBucket", "count")}
    ).reset_index()

    if weight_col not in timeline.columns:
        timeline[weight_col] = df.groupby("TimeBucket").size().values

    timeline = timeline.rename(columns={"TimeBucket": "Time (s)"})
    timeline = timeline.sort_values("Time (s)")

    max_weight = timeline[weight_col].max()
    bar_width = 30
    timeline["Bar"] = timeline[weight_col].apply(
        lambda w: "#" * int(w / max_weight * bar_width) if max_weight > 0 else ""
    )

    weights = timeline[weight_col].values
    if len(weights) > 3:
        median_w = np.median(weights)
        threshold = median_w * 0.2
        steady = [i for i, w in enumerate(weights) if abs(w - median_w) < threshold]
        if steady:
            ss_start = timeline.iloc[steady[0]]["Time (s)"]
            ss_end = timeline.iloc[steady[-1]]["Time (s)"] + bucket_seconds
            footer = f"\n**Suggested steady-state window:** {ss_start:.1f}s – {ss_end:.1f}s"
        else:
            footer = "\n*Could not identify a clear steady-state window.*"
    else:
        footer = ""

    timeline = timeline.head(max_rows)

    header = f"**CPU Timeline** (bucket: {bucket_seconds}s)"
    if cpu_filter:
        header += f" CPUs: {cpu_filter}"

    return f"{header}\n\n{format_table(timeline, max_rows=max_rows)}{footer}"
