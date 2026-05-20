"""DPC/ISR analysis tools — based on xperf -a dpcisr histogram output."""

from __future__ import annotations

from etw_analyzer.app import mcp
from etw_analyzer.trace_state import TraceData, require_trace
from etw_analyzer.formatting.markdown import format_table, format_pct

import pandas as pd


def _get_dpc_df(trace: TraceData) -> pd.DataFrame:
    """Get the DPC/ISR histogram DataFrame.

    Expected columns: Module, Bucket_Low_us, Bucket_High_us, Count, Pct
    """
    # Try parsed histogram data
    for key in ["dpc_isr", "DpcIsr", "DPC/ISR", "dpc"]:
        if key in trace.raw_csv:
            df = trace.raw_csv[key]
            if "Module" in df.columns and "Count" in df.columns:
                return df.copy()

    raise ValueError(
        "No DPC/ISR data available. The trace was likely collected with "
        "`wpr -start CPU` which only captures CPU sampling, not DPC/ISR events.\n\n"
        "To capture DPC/ISR data, use a profile that includes DPC/ISR recording:\n"
        "  wpr -start GeneralProfile    (includes DPC/ISR + context switches)\n"
        "  wpr -start CPU -start DPC    (CPU sampling + DPC events)\n\n"
        "Or use a custom .wprp profile with the DPC/ISR kernel flag enabled."
    )


@mcp.tool()
def get_dpc_summary(
    trace_id: str,
    module_filter: str | None = None,
    max_rows: int = 30,
) -> str:
    """Get DPC/ISR duration summary per module with histogram distribution.

    Shows total DPC count per module and duration distribution buckets.
    Critical for detecting DPC watchdog timeout risk (>20us is concerning).

    Args:
        trace_id: ID returned by load_trace.
        module_filter: Filter by module, e.g. 'xdp.sys'.
        max_rows: Maximum rows to return. Default: 30.
    """
    trace = require_trace(trace_id)
    df = _get_dpc_df(trace)

    if df.empty:
        return "*No DPC/ISR events in this trace.*"

    # Filter out "(all)" global summary — we want per-module
    df = df[df["Module"] != "(all)"]

    # Apply module filter
    if module_filter:
        df = df[df["Module"].astype(str).str.contains(module_filter, case=False, na=False)]

    if df.empty:
        return f"*No DPC/ISR events for module '{module_filter}'.*"

    # Aggregate per module: total count + duration health buckets
    rows = []
    for module, group in df.groupby("Module", dropna=False):
        total_count = group["Count"].sum()
        if total_count == 0:
            continue

        # Compute health buckets
        healthy = group.loc[group["Bucket_High_us"] <= 5, "Count"].sum()
        moderate = group.loc[
            (group["Bucket_Low_us"] >= 5) & (group["Bucket_High_us"] <= 20), "Count"
        ].sum()
        # Also include the 4-8 bucket's portion above 5
        risky = group.loc[group["Bucket_Low_us"] >= 16, "Count"].sum()

        rows.append({
            "Module": module,
            "DPC Count": total_count,
            "< 5us": format_pct(healthy / total_count * 100),
            "5-20us": format_pct(moderate / total_count * 100),
            "> 20us": format_pct(risky / total_count * 100),
            "Max Bucket": f"{group.loc[group['Count'] > 0, 'Bucket_High_us'].max()} us",
            "_sort": total_count,
        })

    result = pd.DataFrame(rows)
    result = result.sort_values("_sort", ascending=False).drop(columns=["_sort"])
    result = result.head(max_rows).reset_index(drop=True)

    # Global health from "(all)" row
    health_lines = _global_health(df)

    # Per-module histogram for top modules
    top_modules = result["Module"].head(5).tolist()
    histogram_lines = []
    for mod in top_modules:
        mod_df = df[df["Module"] == mod]
        if mod_df.empty:
            continue
        histogram_lines.append(f"\n**{mod}** (DPC duration histogram):")
        for _, row in mod_df.iterrows():
            count = row["Count"]
            if count == 0:
                continue
            low = row["Bucket_Low_us"]
            high = row["Bucket_High_us"]
            pct = row["Pct"]
            bar_len = min(int(pct / 2), 40)
            bar = "#" * bar_len
            histogram_lines.append(f"  {low:>6}-{high:<6} us  {bar:<40s}  {count:>10,}  ({pct:5.1f}%)")

    header = "**DPC/ISR Duration Summary**"
    output = f"{header}\n\n{format_table(result, max_rows=max_rows)}"

    if health_lines:
        output += "\n\n" + "\n".join(health_lines)

    if histogram_lines:
        output += "\n" + "\n".join(histogram_lines)

    return output


@mcp.tool()
def get_dpc_per_cpu(
    trace_id: str,
    module_filter: str | None = None,
    max_rows: int = 80,
) -> str:
    """Get per-CPU DPC information.

    Note: xperf dpcisr output includes per-CPU usage in the raw text.
    This tool extracts it from the raw dpcisr output if available,
    otherwise falls back to CPU sampling data filtered to DPC context.

    Args:
        trace_id: ID returned by load_trace.
        module_filter: Filter by module, e.g. 'xdp.sys'. Default: all.
        max_rows: Maximum rows (one per CPU). Default: 80.
    """
    trace = require_trace(trace_id)

    # Try to get per-CPU data from the raw dpcisr text
    raw_df = trace.raw_csv.get("dpc_isr_raw")
    if raw_df is not None and "raw_text" in raw_df.columns:
        raw_text = raw_df.iloc[0]["raw_text"]
        result = _parse_per_cpu_dpc(raw_text, module_filter)
        if result is not None:
            return result

    # Fall back to CPU sampling data if available
    cpu_df = trace.raw_csv.get("cpu_sampling")
    if cpu_df is not None and "Module" in cpu_df.columns:
        return _dpc_from_sampling(cpu_df, module_filter, max_rows)

    return "*No per-CPU DPC data available.*"


def _parse_per_cpu_dpc(raw_text: str, module_filter: str | None) -> str | None:
    """Parse per-CPU DPC usage from raw dpcisr text.

    Format: rows of per-CPU usec/% pairs ending with Module name.
    """
    import re

    lines_out = ["**DPC Per-CPU Usage**", ""]

    # Find lines ending with a module name that contain CPU data
    # Pattern: "  usec  %,  usec  %,  ..., Module"
    data_lines = []
    for line in raw_text.splitlines():
        stripped = line.strip()
        # Match lines ending with .sys, .exe, .dll
        m = re.match(r"^(.+?)\s+([\w.]+\.(sys|exe|dll))$", stripped, re.IGNORECASE)
        if m:
            data_part = m.group(1)
            module = m.group(2)
            if module_filter and module_filter.lower() not in module.lower():
                continue
            data_lines.append((module, data_part))

    if not data_lines:
        return None

    # Parse per-CPU data for each module
    rows = []
    for module, data_part in data_lines:
        # Split by comma-separated pairs "usec  %"
        pairs = data_part.split(",")
        total_usec = 0
        cpu_data = []
        for i, pair in enumerate(pairs):
            pair = pair.strip()
            parts = pair.split()
            if len(parts) >= 2:
                try:
                    usec = int(parts[0])
                    pct = float(parts[1])
                    total_usec += usec
                    if usec > 0:
                        cpu_data.append((i, usec, pct))
                except (ValueError, IndexError):
                    pass

        if total_usec > 0:
            rows.append({
                "Module": module,
                "Total DPC (us)": f"{total_usec:,}",
                "Active CPUs": len(cpu_data),
                "Top CPU": f"CPU {cpu_data[0][0]} ({cpu_data[0][2]:.1f}%)" if cpu_data else "-",
            })

    if not rows:
        return None

    result = pd.DataFrame(rows)
    lines_out.append(format_table(result))

    # Show top module's per-CPU detail
    if data_lines:
        module, data_part = data_lines[0]
        pairs = data_part.split(",")
        cpu_rows = []
        for i, pair in enumerate(pairs):
            pair = pair.strip()
            parts = pair.split()
            if len(parts) >= 2:
                try:
                    usec = int(parts[0])
                    pct = float(parts[1])
                    if usec > 0:
                        cpu_rows.append({"CPU": i, "DPC Time (us)": f"{usec:,}", "% of CPU": f"{pct:.2f}%"})
                except (ValueError, IndexError):
                    pass

        if cpu_rows:
            cpu_df = pd.DataFrame(cpu_rows)
            lines_out.append(f"\n**{module} per-CPU detail:**")
            lines_out.append(format_table(cpu_df, max_rows=80))

    return "\n".join(lines_out)


def _dpc_from_sampling(cpu_df: pd.DataFrame, module_filter: str | None, max_rows: int) -> str:
    """Fall back to CPU sampling data for DPC info."""
    # This is approximate — CPU sampling data doesn't have DPC-specific columns
    # but modules like xdp.sys, ndis.sys are primarily DPC context
    if module_filter:
        cpu_df = cpu_df[cpu_df["Module"].astype(str).str.contains(module_filter, case=False, na=False)]

    if cpu_df.empty:
        return "*No matching samples.*"

    # Group by module
    result = cpu_df.groupby("Module")["Weight"].sum().reset_index()
    result = result.sort_values("Weight", ascending=False).head(max_rows)
    result["% Weight"] = (result["Weight"] / result["Weight"].sum() * 100).apply(format_pct)

    return f"**DPC Approximation from CPU Sampling** (no dedicated DPC data)\n\n{format_table(result)}"


def _global_health(df: pd.DataFrame) -> list[str]:
    """Compute global DPC health from histogram data."""
    total = df["Count"].sum()
    if total == 0:
        return []

    under_5 = df.loc[df["Bucket_High_us"] <= 4, "Count"].sum()
    range_5_20 = df.loc[
        (df["Bucket_Low_us"] >= 4) & (df["Bucket_High_us"] <= 32), "Count"
    ].sum()
    over_20 = df.loc[df["Bucket_Low_us"] >= 16, "Count"].sum()

    lines = ["**Duration Health (all modules):**"]
    lines.append(f"- < 5 us: {under_5/total*100:.1f}% (healthy)")
    lines.append(f"- 5-32 us: {range_5_20/total*100:.1f}% (moderate)")
    lines.append(f"- > 16 us: {over_20/total*100:.1f}% (elevated)")

    if over_20 / total > 0.01:
        lines.append("\n**WARNING:** >1% of DPCs exceed 16us — monitor for DPC watchdog risk at higher load!")

    return lines
