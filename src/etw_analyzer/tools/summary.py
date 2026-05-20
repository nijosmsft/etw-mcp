"""Auto-summary and export tools."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

import pandas as pd

from etw_analyzer.app import mcp
from etw_analyzer.trace_state import require_trace
from etw_analyzer.tools.cpu_sampling import _get_sampling_df, _find_col
from etw_analyzer.formatting.markdown import format_table, format_pct
from etw_analyzer.parsing.aggregator import group_and_sum


@mcp.tool()
def analyze(
    trace_id: str,
    start_time: float | None = None,
    end_time: float | None = None,
) -> str:
    """Run a comprehensive analysis of the loaded trace and return a consolidated report.

    Combines system config, per-CPU utilization, hot functions, symbol status,
    and DPC health into a single output. Use this as the first tool after
    load_trace for a quick overview.

    Args:
        trace_id: ID returned by load_trace.
        start_time: Start of analysis window (seconds from trace start).
        end_time: End of analysis window (seconds from trace start).
    """
    trace = require_trace(trace_id)
    sections: list[str] = []

    # 1. Trace overview
    sections.append(f"# Trace Analysis: `{trace.etl_path.name}`\n")

    # Sysconfig summary
    sysconfig = trace.raw_csv.get("sysconfig")
    if sysconfig is not None and "raw_text" in sysconfig.columns:
        text = sysconfig.iloc[0]["raw_text"]
        cpu_count = _extract_field(text, r"ProcessorNum:\s*(\d+)")
        cpu_speed = _extract_field(text, r"ProcessorSpeed:\s*(\d+)")
        memory = _extract_field(text, r"MemorySize:\s*(\d+)")
        nic = _extract_field(text, r"Device Desc:\s*(.+?)(?:\n|$)")

        parts = []
        if cpu_count:
            parts.append(f"**{cpu_count} LPs**")
        if cpu_speed:
            parts.append(f"{cpu_speed} MHz")
        if memory:
            parts.append(f"{int(memory)//1024} GB RAM")
        if nic:
            parts.append(f"NIC: {nic}")
        if parts:
            sections.append("**System:** " + ", ".join(parts))

    # Trace stats summary
    tracestats = trace.raw_csv.get("tracestats")
    if tracestats is not None and "raw_text" in tracestats.columns:
        text = tracestats.iloc[0]["raw_text"]
        duration = _extract_field(text, r"\+\s+\d+:\d+:\d+:(\d+\.\d+)")
        os_build = _extract_field(text, r"OS Build Number\s*:\s*(\d+)")
        lost = _extract_field(text, r"Total # Lost Events\s*:\s*(\d+)")
        parts = []
        if os_build:
            parts.append(f"Build {os_build}")
        if duration:
            parts.append(f"{float(duration):.1f}s duration")
        if lost and lost != "0":
            parts.append(f"**{lost} lost events!**")
        elif lost:
            parts.append("0 lost events")
        if parts:
            sections.append("**Trace:** " + ", ".join(parts))

    sections.append("")

    # 2. Per-CPU utilization
    cpu_tl = trace.raw_csv.get("cpu_timeline")
    if cpu_tl is not None and not cpu_tl.empty:
        sections.append("## Per-CPU Utilization\n")

        cpu_avgs = {}
        for col in cpu_tl.columns:
            m = re.match(r"Cpu\s+(\d+)", col, re.IGNORECASE)
            if m:
                cpu_id = int(m.group(1))
                # Apply time filter if specified
                df_filtered = cpu_tl
                if start_time is not None and "StartTime" in cpu_tl.columns:
                    df_filtered = df_filtered[df_filtered["StartTime"] >= start_time * 1_000_000]
                if end_time is not None and "EndTime" in cpu_tl.columns:
                    df_filtered = df_filtered[df_filtered["EndTime"] <= end_time * 1_000_000]
                vals = pd.to_numeric(df_filtered[col], errors="coerce").dropna()
                cpu_avgs[cpu_id] = float(vals.mean()) if not vals.empty else 0.0

        saturated = [(c, v) for c, v in cpu_avgs.items() if v >= 80]
        active = [(c, v) for c, v in cpu_avgs.items() if 10 <= v < 80]
        low = [(c, v) for c, v in cpu_avgs.items() if 2 <= v < 10]
        idle_count = sum(1 for v in cpu_avgs.values() if v < 2)

        if saturated:
            saturated.sort(key=lambda x: x[1], reverse=True)
            cpu_list = ", ".join(f"CPU {c} ({v:.0f}%)" for c, v in saturated)
            sections.append(f"**Saturated (>=80%):** {cpu_list}")

        if active:
            active.sort(key=lambda x: x[1], reverse=True)
            # Show range summary if many
            if len(active) > 10:
                cpu_ids = sorted(c for c, _ in active)
                avg_range = f"{active[-1][1]:.0f}-{active[0][1]:.0f}%"
                sections.append(f"**Active (10-80%):** {len(active)} CPUs ({avg_range}): {', '.join(str(c) for c in cpu_ids[:20])}")
            else:
                cpu_list = ", ".join(f"CPU {c} ({v:.0f}%)" for c, v in active)
                sections.append(f"**Active (10-80%):** {cpu_list}")

        sections.append(f"**Low activity:** {len(low)} CPUs | **Idle:** {idle_count} CPUs")
        sections.append(f"**Total active (>=2%):** {len(saturated) + len(active) + len(low)}/{len(cpu_avgs)}")
        sections.append("")

    # 3. Hot functions (top 15)
    cpu_df = trace.raw_csv.get("cpu_sampling")
    if cpu_df is not None and not cpu_df.empty:
        sections.append("## Hot Functions (networking stack)\n")

        weight_col = _find_col(cpu_df, ["Weight"]) or "Weight"
        module_col = _find_col(cpu_df, ["Module"]) or "Module"
        function_col = _find_col(cpu_df, ["Function"]) or "Function"

        from etw_analyzer.tools.cpu_sampling import _DEFAULT_HOT_MODULES
        target = [m.lower() for m in _DEFAULT_HOT_MODULES]

        if module_col in cpu_df.columns:
            filtered = cpu_df[cpu_df[module_col].str.lower().apply(
                lambda m: any(t in m for t in target)
            )]
        else:
            filtered = cpu_df

        if not filtered.empty:
            group_cols = [c for c in [module_col, function_col] if c in filtered.columns]
            result = group_and_sum(filtered, group_cols, sum_col=weight_col)
            total_all = cpu_df[weight_col].sum()
            result["% of Total"] = (result[weight_col] / total_all * 100).apply(format_pct)
            result["% Weight"] = result["% Weight"].apply(format_pct)
            top = result.head(15)
            sections.append(format_table(top, max_rows=15))
        sections.append("")

    # 4. Symbol status
    if cpu_df is not None and "Module" in cpu_df.columns and "Function" in cpu_df.columns:
        missing = cpu_df[cpu_df["Function"].astype(str).str.match(r"^Unknown$|^$", na=True)]
        if not missing.empty:
            missing_mods = missing.groupby("Module")["Weight"].sum().sort_values(ascending=False)
            total_weight = cpu_df["Weight"].sum()
            missing_pct = missing["Weight"].sum() / total_weight * 100
            if missing_pct > 1:
                sections.append(f"## Symbol Gaps ({missing_pct:.1f}% unresolved)\n")
                for mod, w in missing_mods.head(5).items():
                    sections.append(f"- `{mod}` — {w:,} samples ({w/total_weight*100:.1f}%)")
                sections.append("")
            else:
                sections.append(f"**Symbols:** {100-missing_pct:.0f}% resolved\n")
        else:
            sections.append("**Symbols:** 100% resolved\n")

    # 5. DPC health (if available)
    dpc_df = trace.raw_csv.get("dpc_isr")
    if dpc_df is not None and "Count" in dpc_df.columns and not dpc_df.empty:
        total = dpc_df["Count"].sum()
        over_16 = dpc_df.loc[dpc_df["Bucket_Low_us"] >= 16, "Count"].sum()
        if total > 0:
            risky_pct = over_16 / total * 100
            if risky_pct > 1:
                sections.append(f"## DPC Health: **WARNING** — {risky_pct:.1f}% > 16us\n")
            else:
                sections.append(f"**DPC Health:** OK ({risky_pct:.1f}% > 16us)\n")
    else:
        sections.append("**DPC/ISR:** Not captured (use `wpr -start GeneralProfile` to include)\n")

    return "\n".join(sections)


@mcp.tool()
def export_analysis(
    trace_id: str,
    output_path: str,
    start_time: float | None = None,
    end_time: float | None = None,
) -> str:
    """Export the trace analysis to a markdown file for sharing.

    Runs the auto-summary analysis and writes the results to a .md file.
    The output includes system config, per-CPU utilization, hot functions,
    and symbol status.

    Args:
        trace_id: ID returned by load_trace.
        output_path: Path for the output .md file (e.g. 'C:\\traces\\analysis.md').
        start_time: Start of analysis window (seconds from trace start).
        end_time: End of analysis window (seconds from trace start).
    """
    trace = require_trace(trace_id)

    # Generate the analysis
    content = analyze(trace_id=trace_id, start_time=start_time, end_time=end_time)

    # Add metadata header
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    header = (
        f"<!-- Generated by wpr-mcp-server on {now} -->\n"
        f"<!-- Trace: {trace.etl_path} -->\n\n"
    )

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(header + content, encoding="utf-8")

    return f"Analysis exported to `{path}`"


def _extract_field(text: str, pattern: str) -> str | None:
    """Extract first regex match from text."""
    m = re.search(pattern, text)
    return m.group(1).strip() if m else None
