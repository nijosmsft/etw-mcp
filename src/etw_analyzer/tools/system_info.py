"""System info, process, disk I/O, and trace statistics tools."""

from __future__ import annotations

from etw_analyzer.app import mcp
from etw_analyzer.formatting.markdown import format_table
from etw_analyzer.trace_state import require_trace


def _raw_text(trace, name: str) -> str | None:
    raw = trace.raw_csv.get(name)
    if raw is None or "raw_text" not in raw.columns or raw.empty:
        return None
    text = str(raw.iloc[0]["raw_text"] or "")
    return text if text.strip() else None


def _numeric_column(df, column: str):
    if df is None or df.empty or column not in df.columns:
        return None
    import pandas as pd
    values = pd.to_numeric(df[column], errors="coerce").dropna()
    if values.empty:
        return None
    return values


def _metadata_summary(trace) -> dict[str, float]:
    """Return trace header metadata from structured native fields."""
    values: dict[str, float] = {}

    if getattr(trace, "cpu_count", None):
        values["NumberOfProcessors"] = float(trace.cpu_count)
    if getattr(trace, "duration_seconds", None):
        values["DurationSeconds"] = float(trace.duration_seconds)
    if getattr(trace, "timestamp_frequency", None):
        values["PerfFreq"] = float(trace.timestamp_frequency)

    df = trace.raw_csv.get("trace_metadata")
    for key in (
        "NumberOfProcessors",
        "DurationSeconds",
        "PerfFreq",
        "TimerResolution",
        "CpuSpeedInMHz",
        "EventsLost",
        "BuffersLost",
        "BuffersWritten",
        "PointerSize",
    ):
        if key in values:
            continue
        series = _numeric_column(df, key)
        if series is not None:
            if key in {"EventsLost", "BuffersLost", "BuffersWritten"}:
                values[key] = float(series[series >= 0].sum())
            else:
                positives = series[series > 0]
                if not positives.empty:
                    values[key] = float(positives.iloc[0])

    header = trace.raw_csv.get("EventTrace/Header")
    for key in (
        "NumberOfProcessors",
        "TimerResolution",
        "CpuSpeedInMHz",
        "EventsLost",
        "BuffersWritten",
        "PointerSize",
    ):
        if key in values:
            continue
        series = _numeric_column(header, key)
        if series is not None:
            positives = series[series > 0]
            if not positives.empty:
                values[key] = float(positives.iloc[0])

    return values


def _format_metadata_sysconfig(trace) -> str | None:
    metadata = _metadata_summary(trace)
    sysconfig = trace.raw_csv.get("SystemConfig")
    if not metadata and (sysconfig is None or sysconfig.empty):
        return None

    lines = ["**System Configuration** (from trace metadata)", ""]
    label_map = (
        ("NumberOfProcessors", "ProcessorNum"),
        ("CpuSpeedInMHz", "ProcessorSpeed"),
        ("DurationSeconds", "DurationSeconds"),
        ("TimerResolution", "TimerResolution"),
        ("PointerSize", "PointerSize"),
        ("EventsLost", "EventsLost"),
        ("BuffersLost", "BuffersLost"),
        ("BuffersWritten", "BuffersWritten"),
    )
    for key, label in label_map:
        if key not in metadata:
            continue
        value = metadata[key]
        if key == "DurationSeconds":
            lines.append(f"- {label}: {value:.7f}")
        else:
            lines.append(f"- {label}: {int(value)}")

    if sysconfig is not None and not sysconfig.empty and "OpcodeName" in sysconfig.columns:
        lines.extend(["", "### SystemConfig Records"])
        counts = sysconfig["OpcodeName"].astype(str).value_counts().sort_index()
        for name, count in counts.items():
            lines.append(f"- {name}: {int(count)} record(s)")

    return "\n".join(lines)


def _format_metadata_tracestats(trace) -> str | None:
    metadata = _metadata_summary(trace)
    if not metadata and not trace.event_counts:
        return None

    lines = ["Trace Statistics", "==="]
    if "NumberOfProcessors" in metadata:
        lines.append(f"Number of Processors : {int(metadata['NumberOfProcessors'])}")
    if "DurationSeconds" in metadata:
        lines.append(f"Trace duration (s)   : {metadata['DurationSeconds']:.7f}")
    if "EventsLost" in metadata:
        lines.append(f"Total # Lost Events  : {int(metadata['EventsLost'])}")
    if "BuffersLost" in metadata:
        lines.append(f"Buffers Lost         : {int(metadata['BuffersLost'])}")
    if "BuffersWritten" in metadata:
        lines.append(f"Buffers Written      : {int(metadata['BuffersWritten'])}")

    if trace.event_counts:
        lines.append("")
        lines.append("Per-dataset row counts:")
        for name, count in sorted(trace.event_counts.items(), key=lambda kv: -kv[1]):
            lines.append(f"  {name}: {count}")
    return "\n".join(lines) + "\n"


def _process_table(trace):
    try:
        from etw_analyzer.native.aggregators.process_info import build_process_table
        return build_process_table(trace)
    except Exception:
        return None


@mcp.tool()
def get_sysconfig(trace_id: str) -> str:
    """Show system configuration embedded in the trace.

    Extracts CPU model, core count, memory size, NIC details, and disk
    configuration from the trace metadata. Native mode currently emits a
    compact metadata subset, not full xperf SystemConfig TDH decode.
    Essential context for any performance analysis.

    Args:
        trace_id: ID returned by load_trace.
    """
    trace = require_trace(trace_id)
    text = _raw_text(trace, "sysconfig")
    if text is None:
        metadata_output = _format_metadata_sysconfig(trace)
        if metadata_output:
            return metadata_output
        return (
            "*No sysconfig data available. The trace may not contain system "
            "configuration events, or it was not exported.\n\n"
            "Try re-loading the trace to export sysconfig data.*"
        )

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
    raw_text = _raw_text(trace, "process_info")
    if raw_text is None:
        table = _process_table(trace)
        if table is not None and not table.empty:
            if process_filter:
                mask = table.astype(str).apply(
                    lambda col: col.str.contains(
                        process_filter,
                        case=False,
                        na=False,
                        regex=False,
                    )
                ).any(axis=1)
                table = table[mask]
                if table.empty:
                    return f"*No process matching '{process_filter}' found in trace.*"
            return f"**Process Info**\n\n{format_table(table, max_rows=200)}"
        return (
            "*No process info available. The trace may not contain process "
            "events, or it was not exported.\n\n"
            "Try re-loading the trace to export process info.*"
        )

    text = raw_text

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
    storage as a performance bottleneck. Native mode currently exposes a
    compact DiskIo subset; use ``mode="xperf"`` for richer xperf DiskIo
    parity.

    Args:
        trace_id: ID returned by load_trace.
    """
    trace = require_trace(trace_id)
    text = _raw_text(trace, "diskio")
    if text is None:
        try:
            from etw_analyzer.native.aggregators.diskio import build_diskio_text
            text = build_diskio_text(trace)
        except Exception:
            text = None
    if text is None:
        return (
            "*No disk I/O data available. The trace may not contain disk "
            "events.\n\n"
            "To capture disk I/O, use:\n"
            "  wpr -start GeneralProfile   (includes disk I/O)\n"
            "  wpr -start DiskIO           (disk I/O only)"
        )

    if not str(text).strip():
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
    text = _raw_text(trace, "tracestats")
    if text is None:
        text = _format_metadata_tracestats(trace)
    if text is None:
        return "*No trace statistics available.*"

    if not str(text).strip():
        return "*Trace statistics data is empty.*"

    # Truncate if very long
    lines = text.splitlines()
    if len(lines) > 200:
        text = "\n".join(lines[:200]) + f"\n\n*... truncated ({len(lines)} total lines)*"

    return f"**Trace Statistics**\n\n```\n{text}\n```"
