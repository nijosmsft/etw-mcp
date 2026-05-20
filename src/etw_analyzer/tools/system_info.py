"""System info, process, disk I/O, and trace statistics tools."""

from __future__ import annotations

import re

from etw_analyzer.app import mcp
from etw_analyzer.trace_state import require_trace


@mcp.tool()
def get_sysconfig(trace_id: str) -> str:
    """Show system configuration embedded in the trace.

    Extracts CPU model, core count, memory size, NIC details, and disk
    configuration from the trace metadata. Essential context for any
    performance analysis.

    Args:
        trace_id: ID returned by load_trace.
    """
    trace = require_trace(trace_id)
    raw = trace.raw_csv.get("sysconfig")
    if raw is None or "raw_text" not in raw.columns:
        return (
            "*No sysconfig data available. The trace may not contain system "
            "configuration events, or it was not exported.\n\n"
            "Try re-loading the trace to export sysconfig data.*"
        )

    text = raw.iloc[0]["raw_text"]
    if not text.strip():
        return "*sysconfig data is empty.*"

    # Parse into sections for clean markdown output
    lines = ["**System Configuration** (from trace metadata)", ""]
    current_section = None

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        # Detect section headers (all-caps or known patterns)
        if stripped.endswith(":") and not stripped.startswith(" "):
            current_section = stripped.rstrip(":")
            lines.append(f"\n### {current_section}")
            continue

        # Key-value pairs
        if "=" in stripped or ":" in stripped:
            lines.append(f"- {stripped}")
        else:
            lines.append(f"  {stripped}")

    return "\n".join(lines)


@mcp.tool()
def get_process_info(
    trace_id: str,
    process_filter: str | None = None,
) -> str:
    """Show processes, threads, and loaded images from the trace.

    Shows which processes were running, their command lines, thread counts,
    and loaded module versions. Use to verify test configuration.

    Args:
        trace_id: ID returned by load_trace.
        process_filter: Filter by process name (substring match).
    """
    trace = require_trace(trace_id)
    raw = trace.raw_csv.get("process_info")
    if raw is None or "raw_text" not in raw.columns:
        return (
            "*No process info available. The trace may not contain process "
            "events, or it was not exported.\n\n"
            "Try re-loading the trace to export process info.*"
        )

    text = raw.iloc[0]["raw_text"]
    if not text.strip():
        return "*Process info is empty.*"

    if process_filter:
        # Filter to lines containing the process name
        filtered_lines = []
        include_block = False
        for line in text.splitlines():
            if not line.startswith(" ") and not line.startswith("\t"):
                # New block — check if it matches
                include_block = process_filter.lower() in line.lower()
            if include_block:
                filtered_lines.append(line)

        if not filtered_lines:
            return f"*No process matching '{process_filter}' found in trace.*"

        text = "\n".join(filtered_lines)

    # Truncate if very long
    lines = text.splitlines()
    if len(lines) > 200:
        text = "\n".join(lines[:200]) + f"\n\n*... truncated ({len(lines)} total lines)*"

    return f"**Process Info**\n\n```\n{text}\n```"


@mcp.tool()
def get_diskio_summary(trace_id: str) -> str:
    """Show disk I/O summary from the trace.

    Shows per-file I/O counts, bytes, and latency. Use to rule out
    storage as a performance bottleneck.

    Args:
        trace_id: ID returned by load_trace.
    """
    trace = require_trace(trace_id)
    raw = trace.raw_csv.get("diskio")
    if raw is None or "raw_text" not in raw.columns:
        return (
            "*No disk I/O data available. The trace may not contain disk "
            "events.\n\n"
            "To capture disk I/O, use:\n"
            "  wpr -start GeneralProfile   (includes disk I/O)\n"
            "  wpr -start DiskIO           (disk I/O only)"
        )

    text = raw.iloc[0]["raw_text"]
    if not text.strip():
        return "*Disk I/O data is empty — no disk activity recorded in this trace.*"

    # Truncate if very long
    lines = text.splitlines()
    if len(lines) > 200:
        text = "\n".join(lines[:200]) + f"\n\n*... truncated ({len(lines)} total lines)*"

    return f"**Disk I/O Summary**\n\n```\n{text}\n```"


@mcp.tool()
def get_trace_stats(trace_id: str) -> str:
    """Show trace statistics — which providers and events are in the trace.

    Use this to diagnose missing data: if DPC/ISR analysis fails, check
    whether DPC events were actually recorded. Shows event counts per
    provider and storage details.

    Args:
        trace_id: ID returned by load_trace.
    """
    trace = require_trace(trace_id)
    raw = trace.raw_csv.get("tracestats")
    if raw is None or "raw_text" not in raw.columns:
        return "*No trace statistics available.*"

    text = raw.iloc[0]["raw_text"]
    if not text.strip():
        return "*Trace statistics data is empty.*"

    # Truncate if very long
    lines = text.splitlines()
    if len(lines) > 200:
        text = "\n".join(lines[:200]) + f"\n\n*... truncated ({len(lines)} total lines)*"

    return f"**Trace Statistics**\n\n```\n{text}\n```"
