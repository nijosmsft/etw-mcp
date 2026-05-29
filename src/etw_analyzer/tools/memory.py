"""Memory pool analysis tools — kernel pool allocations by tag/module."""

from __future__ import annotations

from etw_analyzer.app import mcp
from etw_analyzer.trace_state import TraceData, require_trace
from etw_analyzer.formatting.markdown import format_table, format_pct

import pandas as pd


def _get_pool_df(trace: TraceData) -> pd.DataFrame:
    """Get the pool allocation DataFrame, extracting on-demand if needed."""
    import os
    from etw_analyzer.parsing.wpa_exporter import _run_xperf, _parse_pool

    with trace.lock:
        # Return cached data if already extracted
        for key in ["pool", "Pool"]:
            if key in trace.raw_csv:
                df = trace.raw_csv[key]
                if not df.empty and "Tag" in df.columns:
                    return df.copy()

        # Extract on-demand from the trace
        sym_path = trace.symbol_path or os.environ.get("_NT_SYMBOL_PATH", "")
        try:
            text = _run_xperf(
                trace.etl_path, "pool",
                ["-pooltags", "-images", "so", "-top", "500"],
                symbol_path=sym_path or None,
                symbols=True,
                timeout_seconds=300,
            )
            df = _parse_pool(text)
            if not df.empty:
                # Cache for future calls
                trace.raw_csv["pool"] = df
                return df.copy()
        except Exception:
            pass

    return pd.DataFrame()


@mcp.tool()
def get_memory_pools(
    trace_id: str,
    tag_filter: str | None = None,
    module_filter: str | None = None,
    pool_type: str | None = None,
    sort_by: str = "bytes",
    max_rows: int = 50,
) -> str:
    """Show kernel pool allocations by pool tag and module.

    Requires trace collected with Pool profiling (wpr -start Pool).
    Shows which drivers are allocating kernel memory, how much is
    outstanding, and the pool tags used. Native mode currently decodes a
    coverage subset and may not include xperf's pool allocation tables;
    use ``mode="xperf"`` when pool parity is required.

    Args:
        trace_id: ID returned by load_trace.
        tag_filter: Filter by pool tag substring (e.g. 'Ndis', 'Xdp', 'Mdl', 'NBL').
        module_filter: Filter by module name (e.g. 'ndis.sys', 'xdp.sys').
        pool_type: Filter by pool type: 'paged', 'nonpaged', 'nx'. Default: all.
        sort_by: Sort by 'bytes' (outstanding KB), 'allocs' (allocation count),
                 or 'total' (total allocated KB). Default: 'bytes'.
        max_rows: Maximum rows to return. Default: 50.
    """
    trace = require_trace(trace_id)
    df = _get_pool_df(trace)
    if df.empty:
        return (
            "*No pool allocation data available.*\n\n"
            "Pool analysis is xperf-only and requires a trace collected with "
            "pool profiling enabled, for example:\n"
            "  wpr -start Pool -filemode; Start-Sleep 1; "
            "wpr -stop C:\\traces\\pool-trace.etl"
        )

    # Apply filters
    if tag_filter:
        df = df[df["Tag"].astype(str).str.contains(tag_filter, case=False, na=False)]
    if module_filter:
        df = df[df["Module"].astype(str).str.contains(module_filter, case=False, na=False)]
    if pool_type:
        pt = pool_type.lower()
        if "nx" in pt:
            df = df[df["PoolType"].str.contains("NX", case=False, na=False)]
        elif "nonpaged" in pt or "non-paged" in pt:
            df = df[df["PoolType"].str.contains("NonPaged", case=False, na=False)]
        elif "paged" in pt:
            df = df[df["PoolType"].str.contains("Paged", case=False, na=False)]

    if df.empty:
        filters = []
        if tag_filter:
            filters.append(f"tag='{tag_filter}'")
        if module_filter:
            filters.append(f"module='{module_filter}'")
        if pool_type:
            filters.append(f"pool_type='{pool_type}'")
        return f"*No pool allocations match filters: {', '.join(filters) or 'none'}.*"

    # Compute totals for percentage
    total_outstanding_kb = df["Outstanding KB"].sum()
    total_allocs = df["Allocs"].sum()

    # Sort
    sort_col = {
        "bytes": "Outstanding KB",
        "allocs": "Allocs",
        "total": "Alloc KB",
    }.get(sort_by, "Outstanding KB")

    df = df.sort_values(sort_col, ascending=False).head(max_rows).reset_index(drop=True)

    # Format output
    result = pd.DataFrame({
        "Tag": df["Tag"],
        "Module": df["Module"],
        "Pool": df["PoolType"],
        "Allocs": df["Allocs"],
        "Frees": df["Allocs"] - df["Outstanding"],
        "Active": df["Outstanding"],
        "Active KB": df["Outstanding KB"].apply(lambda x: f"{x:,.1f}"),
        "% of Total": df["Outstanding KB"].apply(
            lambda x: format_pct(x / total_outstanding_kb * 100) if total_outstanding_kb > 0 else "0%"
        ),
    })

    header = "**Kernel Pool Allocations**"
    filters_desc = []
    if tag_filter:
        filters_desc.append(f"Tag: {tag_filter}")
    if module_filter:
        filters_desc.append(f"Module: {module_filter}")
    if pool_type:
        filters_desc.append(f"Pool: {pool_type}")
    if filters_desc:
        header += f"\nFilters: {', '.join(filters_desc)}"
    header += f"\nTotal outstanding: {total_outstanding_kb:,.1f} KB across {int(total_allocs):,} allocations"

    return f"{header}\n\n{format_table(result, max_rows=max_rows)}"
