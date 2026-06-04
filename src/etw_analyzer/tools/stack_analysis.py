"""Stack analysis tools — function-level inclusive/exclusive weight from butterfly data."""

from __future__ import annotations

import csv
import io
import re

from etw_analyzer.app import mcp
from etw_analyzer.trace_state import TraceData, require_trace
from etw_analyzer.parsing.aggregator import apply_filters, parse_cpu_filter
from etw_analyzer.tools.cpu_sampling import _get_sampling_df, _find_col
from etw_analyzer.tools._symbol_annotation import (
    annotate_export_fallback,
    export_fallback_footnote,
)
from etw_analyzer.formatting.markdown import format_table, format_pct

import pandas as pd


def _get_stacks_df(trace: TraceData) -> pd.DataFrame | None:
    """Get the butterfly stack DataFrame if available."""
    for key in ["stacks", "stack_butterfly"]:
        if key in trace.raw_csv:
            df = trace.raw_csv[key]
            if not df.empty and "Module" in df.columns:
                return df.copy()
    _ensure_lazy_stack_aggregates(trace, include_callers=False)
    for key in ["stacks", "stack_butterfly"]:
        if key in trace.raw_csv:
            df = trace.raw_csv[key]
            if not df.empty and "Module" in df.columns:
                return df.copy()
    return None


def _get_callers_df(trace: TraceData) -> pd.DataFrame | None:
    """Get caller/callee edge data if available."""
    df = trace.raw_csv.get("stacks_callers")
    if df is None or df.empty:
        _ensure_lazy_stack_aggregates(trace, include_callers=True)
        df = trace.raw_csv.get("stacks_callers")
    if df is None or df.empty:
        return None
    return df.copy()


def _ensure_lazy_stack_aggregates(
    trace: TraceData,
    *,
    include_callers: bool,
) -> None:
    if getattr(trace, "mode", None) != "native" or getattr(trace, "event_store", None) is None:
        return
    try:
        from etw_analyzer.native.aggregators.stack_butterfly import ensure_stack_aggregates
    except Exception:
        return
    ensure_stack_aggregates(trace, include_callers=include_callers)


def _stack_warning_text(trace: TraceData) -> str:
    warnings = list(getattr(trace, "_native_stack_aggregate_warnings", []) or [])
    if not warnings:
        return ""
    return "\n".join(f"Warning: {warning}" for warning in warnings)


def _no_callers_message(trace: TraceData) -> str:
    message = (
        "*No caller/callee data available. Re-load the trace with stack detail "
        "enabled to generate butterfly stack analysis.*"
    )
    warning = _stack_warning_text(trace)
    if warning:
        message += "\n\n" + warning
    return message


def _split_stack_ref(ref: tuple[str, str] | list[str] | str) -> tuple[str | None, str]:
    """Normalize a stack-frame reference from MCP input."""
    if isinstance(ref, str):
        if "!" in ref:
            module, function = ref.split("!", 1)
            return module.strip() or None, function.strip()
        return None, ref.strip()
    if len(ref) != 2:
        raise ValueError(f"Stack frame must be 'module!function' or [module, function], got: {ref}")
    module = str(ref[0]).strip()
    function = str(ref[1]).strip()
    return module or None, function


def _node_label(module: str, function: str) -> str:
    return f"{module}!{function}"


def _parse_pct_value(value: object) -> float:
    if value is None or pd.isna(value):
        return 0.0
    if isinstance(value, str):
        value = value.replace("%", "").replace(",", "").strip()
        if not value:
            return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _contains_literal(series: pd.Series, value: object) -> pd.Series:
    """Case-insensitive literal substring match for user-provided filters."""
    return series.astype(str).str.contains(str(value), case=False, na=False, regex=False)


def _contains_module_filter(series: pd.Series, value: object) -> pd.Series:
    """Match module filters, preserving wrapper-built regex module sets."""
    text = str(value)
    use_regex = "|" in text or "\\" in text
    return series.astype(str).str.contains(text, case=False, na=False, regex=use_regex)


def _stack_total_weight(trace: TraceData, stacks_df: pd.DataFrame | None = None) -> float:
    """Estimate the trace-wide stack sample denominator from aggregate percentages."""
    stacks_df = stacks_df if stacks_df is not None else _get_stacks_df(trace)
    if stacks_df is not None and not stacks_df.empty:
        if "Total %" in stacks_df.columns and "Inclusive" in stacks_df.columns:
            for _, row in stacks_df.sort_values("Inclusive", ascending=False).iterrows():
                pct = _parse_pct_value(row.get("Total %"))
                incl = float(row.get("Inclusive", 0) or 0)
                if pct > 0 and incl > 0:
                    return incl / (pct / 100.0)
            estimates = []
            for _, row in stacks_df.iterrows():
                pct = _parse_pct_value(row.get("Total %"))
                incl = float(row.get("Inclusive", 0) or 0)
                if pct > 0 and incl > 0:
                    estimates.append(incl / (pct / 100.0))
            if estimates:
                return float(pd.Series(estimates).median())
        if "Exclusive" in stacks_df.columns:
            total = float(stacks_df["Exclusive"].sum())
            if total > 0:
                return total

    cpu_df = trace.raw_csv.get("cpu_sampling")
    if cpu_df is not None and "Weight" in cpu_df.columns:
        return float(cpu_df["Weight"].sum())
    return 1.0


def _cpu_denominator_info(
    trace: TraceData,
    cpu_filter: str | None,
) -> tuple[int | None, int | None, float | None, float | None]:
    """Return (total_lps, active_lps, active_avg_util_pct, duration_seconds)."""
    timeline = trace.raw_csv.get("cpu_timeline")
    if timeline is None or timeline.empty:
        return None, None, None, trace.duration_seconds

    cpu_cols: dict[int, str] = {}
    for col in timeline.columns:
        m = re.match(r"Cpu\s+(\d+)", str(col), re.IGNORECASE)
        if m:
            cpu_cols[int(m.group(1))] = col
    if not cpu_cols:
        return None, None, None, trace.duration_seconds

    total_lps = len(cpu_cols)
    if cpu_filter:
        requested = set(parse_cpu_filter(cpu_filter) or [])
    else:
        requested = set(cpu_cols)

    avg_utils = []
    for cpu_id, col in cpu_cols.items():
        if cpu_id not in requested:
            continue
        vals = pd.to_numeric(timeline[col], errors="coerce").dropna()
        if vals.empty:
            continue
        avg = float(vals.mean())
        if cpu_filter or avg >= 2.0:
            avg_utils.append(avg)

    active_lps = len(avg_utils)
    active_avg = float(pd.Series(avg_utils).mean()) if avg_utils else None

    duration = trace.duration_seconds
    start_col = _find_col(timeline, ["StartTime", "Start Time"])
    end_col = _find_col(timeline, ["EndTime", "End Time"])
    if start_col and end_col:
        try:
            duration = float(
                (pd.to_numeric(timeline[end_col], errors="coerce").max()
                 - pd.to_numeric(timeline[start_col], errors="coerce").min())
                / 1_000_000
            )
        except Exception:
            pass

    return total_lps, active_lps, active_avg, duration


def _denominator_weight(
    trace: TraceData,
    denominator: str,
    cpu_filter: str | None = None,
    denominator_lps: int | None = None,
    denominator_seconds: float | None = None,
    stacks_df: pd.DataFrame | None = None,
) -> tuple[float, str]:
    """Compute denominator weight and display label."""
    base = _stack_total_weight(trace, stacks_df)
    denominator = (denominator or "trace").lower()

    if denominator == "trace":
        return base, "% trace"

    total_lps, active_lps, active_avg, duration = _cpu_denominator_info(trace, cpu_filter)
    if denominator == "active_cpus":
        if total_lps and active_lps:
            return base * active_lps / total_lps, "% active_cpus"
        return base, "% active_cpus"

    if denominator == "active_busy":
        if total_lps and active_lps and active_avg:
            return base * active_lps / total_lps * active_avg / 100.0, "% active_busy"
        return base, "% active_busy"

    if denominator == "custom":
        if not denominator_lps or not denominator_seconds:
            raise ValueError("denominator='custom' requires denominator_lps and denominator_seconds.")
        if total_lps and duration and duration > 0:
            return base * denominator_lps * denominator_seconds / (total_lps * duration), "% custom"
        return base, "% custom"

    raise ValueError("denominator must be one of: trace, active_cpus, active_busy, custom")


def _pct_of(value: float, denominator_weight: float) -> str:
    pct = value / denominator_weight * 100 if denominator_weight > 0 else 0.0
    return format_pct(pct)


def _find_stack_node(
    trace: TraceData,
    function_filter: str,
    module_filter: str | None = None,
) -> tuple[str, str] | None:
    """Find the best matching stack node by inclusive weight."""
    stacks_df = _get_stacks_df(trace)
    if stacks_df is not None and not stacks_df.empty:
        df = stacks_df
        mask = _contains_literal(df["Function"], function_filter)
        if module_filter:
            mask &= _contains_module_filter(df["Module"], module_filter)
        matches = df[mask]
        if not matches.empty:
            row = matches.sort_values("Inclusive", ascending=False).iloc[0]
            return str(row["Module"]), str(row["Function"])

    callers_df = _get_callers_df(trace)
    if callers_df is None:
        return None
    candidates = []
    for module_col, function_col in [
        ("Target_Module", "Target_Function"),
        ("Caller_Module", "Caller_Function"),
    ]:
        mask = _contains_literal(callers_df[function_col], function_filter)
        if module_filter:
            mask &= _contains_module_filter(callers_df[module_col], module_filter)
        for _, row in callers_df[mask].iterrows():
            candidates.append((str(row[module_col]), str(row[function_col]), int(row.get("Weight", 0))))
    if not candidates:
        return None
    candidates.sort(key=lambda item: item[2], reverse=True)
    return candidates[0][0], candidates[0][1]


def _node_inclusive(trace: TraceData, module: str, function: str) -> int:
    stacks_df = _get_stacks_df(trace)
    if stacks_df is not None and not stacks_df.empty:
        mask = (
            stacks_df["Module"].astype(str).str.lower().eq(module.lower())
            & stacks_df["Function"].astype(str).str.lower().eq(function.lower())
        )
        if mask.any():
            return int(stacks_df.loc[mask, "Inclusive"].max())

    callers_df = _get_callers_df(trace)
    if callers_df is not None and not callers_df.empty:
        mask = (
            callers_df["Target_Module"].astype(str).str.lower().eq(module.lower())
            & callers_df["Target_Function"].astype(str).str.lower().eq(function.lower())
            & callers_df["Direction"].astype(str).eq("self")
        )
        if mask.any():
            return int(callers_df.loc[mask, "Weight"].max())
    return 0


def _edges_from_node(
    trace: TraceData,
    module: str,
    function: str,
    direction: str,
) -> pd.DataFrame:
    callers_df = _get_callers_df(trace)
    if callers_df is None or callers_df.empty:
        return pd.DataFrame()
    direction = "caller" if direction == "callers" else "callee"
    mask = (
        callers_df["Target_Module"].astype(str).str.lower().eq(module.lower())
        & callers_df["Target_Function"].astype(str).str.lower().eq(function.lower())
        & callers_df["Direction"].astype(str).eq(direction)
    )
    return callers_df[mask].copy().sort_values("Weight", ascending=False)


@mcp.tool()
def get_hot_stacks(
    trace_id: str,
    module_filter: str | None = None,
    function_filter: str | None = None,
    cpu_filter: str | None = None,
    start_time: float | None = None,
    end_time: float | None = None,
    max_depth: int = 10,
    min_weight_pct: float = 1.0,
    dpc_only: bool = False,
    max_rows: int = 50,
    denominator: str = "trace",
    denominator_lps: int | None = None,
    denominator_seconds: float | None = None,
) -> str:
    """Show hottest functions with inclusive and exclusive CPU weight.

    Uses aggregate butterfly stack data when available (includes caller/callee
    relationships and inclusive hit counts). Falls back to flat
    module!function view from CPU sampling data.

    Inclusive = time in function + all functions it calls.
    Exclusive = time in just this function (not callees).

    Args:
        trace_id: ID returned by load_trace.
        module_filter: Focus on specific module (e.g. 'xdp.sys', 'tcpip.sys').
        function_filter: Focus on specific function (e.g. 'XdpCpuMapDrainDpc').
        cpu_filter: CPU range filter, e.g. '18-39'.
        start_time: Start of analysis window (seconds from trace start).
        end_time: End of analysis window (seconds from trace start).
        max_depth: Not used (kept for API compat). Default: 10.
        min_weight_pct: Prune functions below this % of total. Default: 1.0.
        dpc_only: Not used with aggregate butterfly data. Default: false.
        max_rows: Max rows to return. Default: 50.
        denominator: Percentage denominator: 'trace', 'active_cpus', 'active_busy', or 'custom'.
        denominator_lps: Logical processor count for denominator='custom'.
        denominator_seconds: Duration for denominator='custom'.
    """
    trace = require_trace(trace_id)

    # Try butterfly stack data first (has inclusive/exclusive)
    # But butterfly data has no CPU column, so fall back to flat when cpu_filter is set
    if not cpu_filter:
        stacks_df = _get_stacks_df(trace)
        if stacks_df is not None and not stacks_df.empty:
            return _render_butterfly_stacks(
                trace, stacks_df, module_filter, function_filter,
                min_weight_pct, max_rows, denominator, cpu_filter,
                denominator_lps, denominator_seconds,
            )

    # Fall back to CPU sampling data (flat module!function only, but supports CPU filter)
    return _render_flat_stacks(
        trace,
        module_filter, function_filter,
        cpu_filter, start_time, end_time,
        min_weight_pct, max_rows, denominator,
        denominator_lps, denominator_seconds,
    )


def _render_butterfly_stacks(
    trace: TraceData,
    df: pd.DataFrame,
    module_filter: str | None,
    function_filter: str | None,
    min_weight_pct: float,
    max_rows: int,
    denominator: str,
    cpu_filter: str | None,
    denominator_lps: int | None,
    denominator_seconds: float | None,
) -> str:
    """Render butterfly stack data as a table with inclusive/exclusive weights."""
    # Apply filters
    if module_filter:
        df = df[_contains_module_filter(df["Module"], module_filter)]
    if function_filter:
        df = df[_contains_literal(df["Function"], function_filter)]

    if df.empty:
        return "*No matching functions found with the specified filters.*"

    denominator_weight, pct_label = _denominator_weight(
        trace, denominator, cpu_filter, denominator_lps, denominator_seconds, df
    )

    # Filter by min weight
    if min_weight_pct > 0 and denominator_weight > 0:
        threshold = denominator_weight * min_weight_pct / 100
        df = df[df["Inclusive"] >= threshold]

    if df.empty:
        return f"*No functions above {min_weight_pct}% threshold.*"

    # Sort by inclusive weight
    df = df.sort_values("Inclusive", ascending=False).head(max_rows).reset_index(drop=True)

    # Format columns
    result = df[["Module", "Function"]].copy()
    result["Inclusive"] = df["Inclusive"]
    result[f"Incl {pct_label}"] = df["Inclusive"].apply(lambda v: _pct_of(float(v), denominator_weight))
    if "Exclusive" in df.columns:
        result["Exclusive"] = df["Exclusive"]
        result[f"Excl {pct_label}"] = df["Exclusive"].apply(lambda v: _pct_of(float(v), denominator_weight))

    # Annotate rows whose modules came from PE export-table fallback so
    # the caller knows the names are nearest-neighbour guesses.
    result, any_annotated = annotate_export_fallback(result, trace)

    header_parts = ["**Hot Functions (with inclusive/exclusive weight)**"]
    if module_filter:
        header_parts.append(f"Module: {module_filter}")
    if function_filter:
        header_parts.append(f"Function: {function_filter}")
    header = "\n".join(header_parts)

    output = f"{header}\n\n{format_table(result, max_rows=max_rows)}"
    if any_annotated:
        output += "\n\n" + export_fallback_footnote()
    return output


@mcp.tool()
def get_function_callers(
    trace_id: str,
    function_filter: str,
    module_filter: str | None = None,
    direction: str = "callers",
    max_rows: int = 30,
    cpu_filter: str | None = None,
    denominator: str = "trace",
    denominator_lps: int | None = None,
    denominator_seconds: float | None = None,
) -> str:
    """Show callers or callees of a function with hit counts.

    Use this to identify which specific code paths call into a function.
    Example: get_function_callers(trace_id, "KeAcquireInStackQueuedSpinLock")
    shows which functions acquire spinlocks and how often.

    Args:
        trace_id: ID returned by load_trace.
        function_filter: Function name to search for (substring match).
        module_filter: Optional module filter for the target function.
        direction: "callers" (who calls this), "callees" (what this calls), or "both".
        max_rows: Maximum rows to return.
        cpu_filter: Optional CPU range for denominator calculations. Butterfly edges are not per-CPU filtered.
        denominator: Percentage denominator: 'trace', 'active_cpus', 'active_busy', or 'custom'.
        denominator_lps: Logical processor count for denominator='custom'.
        denominator_seconds: Duration for denominator='custom'.
    """
    trace = require_trace(trace_id)

    df = _get_callers_df(trace)
    if df is None or df.empty:
        return _no_callers_message(trace)

    if direction not in {"callers", "callees", "both"}:
        raise ValueError("direction must be one of: callers, callees, both")

    # Find entries where this function is the center (Target_Function)
    mask = _contains_literal(df["Target_Function"], function_filter)
    if module_filter:
        mask &= _contains_module_filter(df["Target_Module"], module_filter)

    matched = df[mask]

    # If not found as center, try as a related function
    if matched.empty:
        mask2 = _contains_literal(df["Caller_Function"], function_filter)
        if module_filter:
            mask2 &= _contains_module_filter(df["Caller_Module"], module_filter)
        related = df[mask2]
        if related.empty:
            return f"*No entries found matching '{function_filter}'.*"

        # Show which center functions reference this as caller/callee
        if direction == "callers":
            result = related[related["Direction"] == "caller"]
            dir_label = "Caller references"
        elif direction == "callees":
            result = related[related["Direction"] == "callee"]
            dir_label = "Callee references"
        else:
            result = related[related["Direction"].isin(["caller", "callee"])]
            dir_label = "Caller/callee references"

        if result.empty:
            return f"*No {direction} found for '{function_filter}'.*"

        relation_total = float(result["Weight"].sum())
        denominator_weight, pct_label = _denominator_weight(
            trace, denominator, cpu_filter, denominator_lps, denominator_seconds
        )
        result = result.sort_values("Weight", ascending=False).head(max_rows)

        out = result[["Target_Module", "Target_Function", "Direction",
                       "Caller_Module", "Caller_Function"]].copy()
        out["Hits"] = result["Weight"].values
        out["% of Parent"] = (
            result["Weight"].astype(float).values / relation_total * 100
        ).round(1).astype(str) + "%"
        out[pct_label] = result["Weight"].apply(lambda v: _pct_of(float(v), denominator_weight)).values

        header = f"**{dir_label} to `{function_filter}` (found as caller/callee)**\n"
        header += f"Relation hits: {relation_total:,.0f}\n"
        return header + "\n" + format_table(out, max_rows=max_rows)

    # Filter by direction
    if direction == "callers":
        result = matched[matched["Direction"] == "caller"]
        dir_label = "Callers"
    elif direction == "callees":
        result = matched[matched["Direction"] == "callee"]
        dir_label = "Callees"
    else:
        result = matched[matched["Direction"].isin(["caller", "callee"])]
        dir_label = "Callers & Callees"

    if result.empty:
        return f"*No {direction} found for '{function_filter}'.*"

    # Get center function name for header
    center = matched.iloc[0]
    center_name = f"{center['Target_Module']}!{center['Target_Function']}"

    relation_total = float(result["Weight"].sum())
    denominator_weight, pct_label = _denominator_weight(
        trace, denominator, cpu_filter, denominator_lps, denominator_seconds
    )
    result = result.sort_values("Weight", ascending=False).head(max_rows)

    out = pd.DataFrame()
    out["Function"] = result["Caller_Function"].values
    out["Module"] = result["Caller_Module"].values
    if direction == "both":
        out["Direction"] = result["Direction"].values
    out["Hits"] = result["Weight"].values
    out["% of Parent"] = (
        result["Weight"].astype(float).values / relation_total * 100
    ).round(1).astype(str) + "%"
    out[pct_label] = result["Weight"].apply(lambda v: _pct_of(float(v), denominator_weight)).values

    header = f"**{dir_label} of `{center_name}`**\n"
    header += f"Relation hits: {relation_total:,.0f}\n"
    if cpu_filter:
        header += "Note: butterfly caller/callee edges are trace-wide; cpu_filter only changes denominator.\n"
    return header + "\n" + format_table(out, max_rows=max_rows)


def _render_flat_stacks(
    trace: TraceData,
    module_filter: str | None,
    function_filter: str | None,
    cpu_filter: str | None,
    start_time: float | None,
    end_time: float | None,
    min_weight_pct: float,
    max_rows: int,
    denominator: str,
    denominator_lps: int | None,
    denominator_seconds: float | None,
) -> str:
    """Fall back to flat module!function view from CPU sampling."""
    df = _get_sampling_df(trace)

    weight_col = _find_col(df, ["Weight", "Count", "Sample Count"]) or "Weight"
    module_col = _find_col(df, ["Module", "Image"]) or "Module"
    function_col = _find_col(df, ["Function", "Function Name", "Symbol"]) or "Function"
    cpu_col = _find_col(df, ["CPU", "Cpu"]) or "CPU"
    time_col = _find_col(df, ["TimeStamp", "Time"]) or "TimeStamp"

    # Apply filters
    df = apply_filters(
        df,
        cpu_filter=cpu_filter, cpu_col=cpu_col,
        start_time=start_time, end_time=end_time, time_col=time_col,
        module_filter=module_filter, module_col=module_col,
        function_filter=function_filter, function_col=function_col,
    )

    if df.empty:
        return "*No matching samples found with the specified filters.*"

    denominator_weight, pct_label = _denominator_weight(
        trace, denominator, cpu_filter, denominator_lps, denominator_seconds
    )

    # Filter by min weight
    if min_weight_pct > 0 and denominator_weight > 0:
        threshold = denominator_weight * min_weight_pct / 100
        # Group first, then filter
        group_cols = [c for c in [module_col, function_col] if c in df.columns]
        grouped = df.groupby(group_cols, dropna=False)[weight_col].sum().reset_index()
        grouped = grouped[grouped[weight_col] >= threshold]
    else:
        group_cols = [c for c in [module_col, function_col] if c in df.columns]
        grouped = df.groupby(group_cols, dropna=False)[weight_col].sum().reset_index()

    if grouped.empty:
        return f"*No functions above {min_weight_pct}% threshold.*"

    grouped = grouped.sort_values(weight_col, ascending=False).head(max_rows).reset_index(drop=True)
    grouped[pct_label] = grouped[weight_col].apply(lambda v: _pct_of(float(v), denominator_weight))

    header_parts = ["**Hot Functions (exclusive weight only — no call stack data)**"]
    if module_filter:
        header_parts.append(f"Module: {module_filter}")
    if function_filter:
        header_parts.append(f"Function: {function_filter}")
    header = "\n".join(header_parts)
    header += f"\nDenominator ({denominator}): {denominator_weight:,.0f}"
    warning = _stack_warning_text(trace)
    if warning:
        header += "\n" + warning
    header += "\n*Tip: For inclusive/exclusive breakdown, load stack detail to generate butterfly stacks.*"

    return f"{header}\n\n{format_table(grouped, max_rows=max_rows)}"


def _select_branch_edges(
    edges: pd.DataFrame,
    branch_policy: str,
    branch_threshold_pct: float,
) -> pd.DataFrame:
    if edges.empty:
        return edges
    branch_policy = branch_policy.lower()
    if branch_policy == "dominant":
        return edges.head(1)
    if branch_policy == "all":
        return edges
    if branch_policy == "threshold":
        total = float(edges["Weight"].sum())
        if total <= 0:
            return edges.head(0)
        pct = edges["Weight"].astype(float) / total * 100
        return edges[pct >= branch_threshold_pct]
    raise ValueError("branch_policy must be one of: dominant, all, threshold")


def _walk_stack_rows(
    trace: TraceData,
    function_filter: str,
    module_filter: str | None,
    direction: str,
    branch_policy: str,
    branch_threshold_pct: float,
    max_depth: int,
    stop_at_modules: list[str] | None,
) -> list[dict[str, object]]:
    direction = direction.lower()
    if direction not in {"callers", "callees"}:
        raise ValueError("direction must be one of: callers, callees")
    if max_depth < 0:
        raise ValueError("max_depth must be >= 0")

    root = _find_stack_node(trace, function_filter, module_filter)
    if root is None:
        return []

    stop_modules = {m.lower() for m in (stop_at_modules or [])}
    root_hits = _node_inclusive(trace, root[0], root[1])
    rows: list[dict[str, object]] = [{
        "Depth": 0,
        "Module": root[0],
        "Function": root[1],
        "Frame": _node_label(root[0], root[1]),
        "Frame Hits": root_hits,
        "% Parent": "100.0%",
        "Chain Hits": root_hits,
        "Branch": "root",
    }]

    queue: list[tuple[int, str, str, float, tuple[tuple[str, str], ...]]] = [
        (0, root[0], root[1], float(root_hits), ((root[0].lower(), root[1].lower()),))
    ]

    while queue:
        depth, module, function, chain_hits, path = queue.pop(0)
        if depth >= max_depth:
            continue
        if depth > 0 and module.lower() in stop_modules:
            continue

        edges = _edges_from_node(trace, module, function, direction)
        if edges.empty:
            continue

        selected = _select_branch_edges(edges, branch_policy, branch_threshold_pct)
        relation_total = float(edges["Weight"].sum())
        for _, edge in selected.iterrows():
            next_module = str(edge["Caller_Module"])
            next_function = str(edge["Caller_Function"])
            next_key = (next_module.lower(), next_function.lower())
            if next_key in path:
                continue

            weight = float(edge.get("Weight", 0) or 0)
            parent_pct = _parse_pct_value(edge.get("Parent %"))
            if parent_pct <= 0 and relation_total > 0:
                parent_pct = weight / relation_total * 100
            next_chain_hits = chain_hits * parent_pct / 100 if chain_hits else weight

            sibling_count = int(len(edges))
            branch_note = branch_policy
            if sibling_count > 1:
                branch_note = f"{branch_policy}; {sibling_count} siblings"

            rows.append({
                "Depth": depth + 1,
                "Module": next_module,
                "Function": next_function,
                "Frame": _node_label(next_module, next_function),
                "Frame Hits": int(weight),
                "% Parent": format_pct(parent_pct),
                "Chain Hits": int(round(next_chain_hits)),
                "Branch": branch_note,
            })
            queue.append((depth + 1, next_module, next_function, next_chain_hits, path + (next_key,)))

    return rows


@mcp.tool()
def walk_stack(
    trace_id: str,
    function_filter: str,
    module_filter: str | None = None,
    direction: str = "callers",
    branch_policy: str = "dominant",
    branch_threshold_pct: float = 5.0,
    max_depth: int = 64,
    stop_at_modules: list[str] | None = None,
) -> str:
    """Recursively walk caller/callee edges from a function in WPA butterfly data.

    Args:
        trace_id: ID returned by load_trace.
        function_filter: Function substring to use as the starting node.
        module_filter: Optional module substring for the starting node.
        direction: 'callers' walks toward callers; 'callees' walks toward callees.
        branch_policy: 'dominant', 'all', or 'threshold'.
        branch_threshold_pct: Minimum sibling share for branch_policy='threshold'.
        max_depth: Maximum recursion depth.
        stop_at_modules: Optional module names/substrings where traversal should stop.
    """
    trace = require_trace(trace_id)
    if _get_callers_df(trace) is None:
        return _no_callers_message(trace)

    rows = _walk_stack_rows(
        trace, function_filter, module_filter, direction, branch_policy,
        branch_threshold_pct, max_depth, stop_at_modules,
    )
    if not rows:
        return f"*No stack node found matching '{function_filter}'.*"

    df = pd.DataFrame(rows)
    header = (
        f"**Stack walk ({direction}) from `{rows[0]['Frame']}`**\n"
        f"Branch policy: {branch_policy}"
    )
    if branch_policy == "threshold":
        header += f" >= {branch_threshold_pct:.1f}%"
    return header + "\n\n" + format_table(
        df[["Depth", "Frame", "Frame Hits", "% Parent", "Chain Hits", "Branch"]],
        max_rows=len(df),
    )


def _frame_weight(trace: TraceData, ref: tuple[str | None, str]) -> int:
    module, function = ref
    stacks_df = _get_stacks_df(trace)
    if stacks_df is None or stacks_df.empty:
        return 0
    mask = _contains_literal(stacks_df["Function"], function)
    if module:
        mask &= _contains_module_filter(stacks_df["Module"], module)
    if not mask.any():
        return 0
    return int(stacks_df.loc[mask, "Inclusive"].max())


def _best_edge_weight(
    trace: TraceData,
    source: tuple[str | None, str],
    target: tuple[str | None, str],
) -> tuple[float, float]:
    source_module, source_function = source
    target_module, target_function = target
    callers_df = _get_callers_df(trace)
    if callers_df is None or callers_df.empty:
        return 0.0, 0.0

    mask = (
        _contains_literal(callers_df["Target_Function"], source_function)
        & _contains_literal(callers_df["Caller_Function"], target_function)
        & callers_df["Direction"].astype(str).eq("caller")
    )
    if source_module:
        mask &= _contains_module_filter(callers_df["Target_Module"], source_module)
    if target_module:
        mask &= _contains_module_filter(callers_df["Caller_Module"], target_module)
    matches = callers_df[mask]
    if matches.empty:
        return 0.0, 0.0
    row = matches.sort_values("Weight", ascending=False).iloc[0]
    return float(row.get("Weight", 0) or 0), _parse_pct_value(row.get("Parent %"))


def _estimate_ordered_contains(trace: TraceData, contains: list[tuple[str | None, str]]) -> float:
    if not contains:
        return 0.0
    if len(contains) == 1:
        return float(_frame_weight(trace, contains[0]))

    first_weight, first_pct = _best_edge_weight(trace, contains[0], contains[1])
    if first_weight <= 0:
        return 0.0
    chain = first_weight
    for source, target in zip(contains[1:], contains[2:]):
        edge_weight, parent_pct = _best_edge_weight(trace, source, target)
        if edge_weight <= 0:
            return 0.0
        if parent_pct <= 0:
            parent_base = _frame_weight(trace, source)
            parent_pct = edge_weight / parent_base * 100 if parent_base > 0 else 0.0
        chain *= parent_pct / 100
    return chain


@mcp.tool()
def count_stacks(
    trace_id: str,
    contains: list[tuple[str, str]],
    contains_in_order: bool = True,
    excludes: list[tuple[str, str]] | None = None,
    cpu_filter: str | None = None,
    start_time: float | None = None,
    end_time: float | None = None,
) -> str:
    """Estimate how many aggregate butterfly samples match a stack predicate.

    Args:
        trace_id: ID returned by load_trace.
        contains: Ordered frames as [module, function] pairs.
        contains_in_order: When true, adjacent frames are matched as caller edges.
        excludes: Optional frames to subtract when present in the same aggregate chain.
        cpu_filter: Optional CPU filter for denominator only; butterfly stacks are trace-wide.
        start_time: Reserved for future raw-stack exports.
        end_time: Reserved for future raw-stack exports.
    """
    trace = require_trace(trace_id)
    parsed_contains = [_split_stack_ref(ref) for ref in contains]
    parsed_excludes = [_split_stack_ref(ref) for ref in (excludes or [])]
    if not parsed_contains:
        raise ValueError("contains must include at least one frame.")

    if contains_in_order:
        matching_samples = _estimate_ordered_contains(trace, parsed_contains)
    else:
        weights = [_frame_weight(trace, ref) for ref in parsed_contains]
        matching_samples = float(min(weights)) if all(w > 0 for w in weights) else 0.0

    excluded_samples = 0.0
    for excluded in parsed_excludes:
        excluded_samples += _estimate_ordered_contains(trace, parsed_contains + [excluded])
    matching_samples = max(0.0, matching_samples - excluded_samples)

    denominator_weight, pct_label = _denominator_weight(trace, "trace", cpu_filter)
    out = pd.DataFrame([{
        "Contains": " -> ".join(
            _node_label(module or "*", function) for module, function in parsed_contains
        ),
        "Order": "ordered" if contains_in_order else "unordered",
        "Matching Samples": int(round(matching_samples)),
        pct_label: _pct_of(matching_samples, denominator_weight),
        "Excluded Samples": int(round(excluded_samples)),
        "Method": "aggregate-butterfly-estimate",
    }])

    header = "**Stack predicate count**\n"
    header += (
        "Note: current butterfly data is aggregate edge data, so this estimates "
        "sample counts rather than distinct raw stack instances.\n"
    )
    warning = _stack_warning_text(trace)
    if warning:
        header += warning + "\n"
    if cpu_filter:
        header += "Note: cpu_filter only changes denominator; aggregate butterfly stacks are trace-wide.\n"
    if start_time is not None or end_time is not None:
        header += "Note: start_time/end_time require raw stack-keyed exports and are not applied to aggregate butterfly data.\n"
    return header + "\n" + format_table(out, max_rows=1)


def _rows_to_csv(rows: list[dict[str, object]], wpa_csv: bool = False) -> str:
    output = io.StringIO()
    if not rows:
        return ""
    fieldnames = ["Depth", "Frame", "Frame Hits", "% Parent", "Chain Hits", "Branch"]
    if wpa_csv:
        fieldnames = ["Level", "Function", "Inclusive Hits", "Parent %", "Chain Hits", "Branch"]
        mapped = []
        for row in rows:
            mapped.append({
                "Level": row["Depth"],
                "Function": row["Frame"],
                "Inclusive Hits": row["Frame Hits"],
                "Parent %": row["% Parent"],
                "Chain Hits": row["Chain Hits"],
                "Branch": row["Branch"],
            })
        rows = mapped
    writer = csv.DictWriter(output, fieldnames=fieldnames, lineterminator="\n", extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


@mcp.tool()
def butterfly_chain(
    trace_id: str,
    target_function: str,
    target_module: str | None = None,
    direction: str = "callers",
    max_depth: int = 64,
    branch_policy: str = "dominant",
    denominator: str = "active_cpus",
    output_format: str = "table",
    branch_threshold_pct: float = 5.0,
    denominator_lps: int | None = None,
    denominator_seconds: float | None = None,
) -> str:
    """One-shot WPA-style butterfly chain export for a target function.

    Args:
        trace_id: ID returned by load_trace.
        target_function: Function substring to start from.
        target_module: Optional module substring for the starting node.
        direction: 'callers', 'callees', or 'both'.
        max_depth: Maximum recursion depth.
        branch_policy: 'dominant', 'all', or 'threshold'.
        denominator: Percentage denominator: 'trace', 'active_cpus', 'active_busy', or 'custom'.
        output_format: 'table', 'csv', or 'wpa_csv'.
        branch_threshold_pct: Minimum sibling share for branch_policy='threshold'.
        denominator_lps: Logical processor count for denominator='custom'.
        denominator_seconds: Duration for denominator='custom'.
    """
    trace = require_trace(trace_id)
    if direction not in {"callers", "callees", "both"}:
        raise ValueError("direction must be one of: callers, callees, both")
    if output_format not in {"table", "csv", "wpa_csv"}:
        raise ValueError("output_format must be one of: table, csv, wpa_csv")
    if _get_callers_df(trace) is None:
        return _no_callers_message(trace)

    directions = ["callers", "callees"] if direction == "both" else [direction]
    all_sections: list[str] = []
    for one_direction in directions:
        rows = _walk_stack_rows(
            trace, target_function, target_module, one_direction, branch_policy,
            branch_threshold_pct, max_depth, None,
        )
        if not rows:
            all_sections.append(f"*No stack node found matching '{target_function}'.*")
            continue

        denominator_weight, pct_label = _denominator_weight(
            trace, denominator, None, denominator_lps, denominator_seconds
        )
        for row in rows:
            row[pct_label] = _pct_of(float(row["Frame Hits"]), denominator_weight)

        if output_format == "csv":
            all_sections.append(_rows_to_csv(rows))
        elif output_format == "wpa_csv":
            all_sections.append(_rows_to_csv(rows, wpa_csv=True))
        else:
            df = pd.DataFrame(rows)
            header = (
                f"**Butterfly chain ({one_direction}) from `{rows[0]['Frame']}`**\n"
                f"Branch policy: {branch_policy}; Denominator ({denominator}): {denominator_weight:,.0f}"
            )
            cols = ["Depth", "Frame", "Frame Hits", pct_label, "% Parent", "Chain Hits", "Branch"]
            all_sections.append(header + "\n\n" + format_table(df[cols], max_rows=len(df)))

    return "\n\n".join(all_sections)
