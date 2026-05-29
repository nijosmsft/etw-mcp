"""Aggregator: ``tracestats`` raw-text — replacement for ``xperf -a tracestats``.

xperf prints per-provider event counts and dropped/lost event counters.
The native consumer captures the same data via :class:`ExtractStats`
(see ``native/extract.py``); this aggregator pulls those counters off
the trace and formats them as the text dump xperf would emit.

If extraction stats weren't recorded, the aggregator still emits ETL
header metadata from ``trace_metadata`` when available.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

import pandas as pd

if TYPE_CHECKING:
    from etw_analyzer.trace_state import TraceData


def _metadata_lines(trace: "TraceData") -> list[str]:
    stats = getattr(trace, "_native_extract_stats", None)
    metadata = getattr(stats, "logfile_metadata", None) or []
    cpu_count = None
    duration_seconds = None
    events_lost = None
    buffers_lost = None
    buffers_written = None
    if metadata:
        cpu_values = [
            int(getattr(item, "number_of_processors", 0) or 0)
            for item in metadata
            if int(getattr(item, "number_of_processors", 0) or 0) > 0
        ]
        durations = [
            float(getattr(item, "duration_seconds", 0) or 0)
            for item in metadata
            if float(getattr(item, "duration_seconds", 0) or 0) > 0
        ]
        if cpu_values:
            cpu_count = max(cpu_values)
        if durations:
            duration_seconds = max(durations)
        lost_values = [
            int(getattr(item, "events_lost", 0) or 0)
            for item in metadata
        ]
        buffer_lost_values = [
            int(getattr(item, "buffers_lost", 0) or 0)
            for item in metadata
        ]
        buffers_written_values = [
            int(getattr(item, "buffers_written", 0) or 0)
            for item in metadata
        ]
        events_lost = sum(lost_values)
        buffers_lost = sum(buffer_lost_values)
        buffers_written = sum(buffers_written_values)

    raw_csv = getattr(trace, "raw_csv", {}) or {}
    df = raw_csv.get("trace_metadata")
    if df is not None and not getattr(df, "empty", True):
        row = df.iloc[0]
        if cpu_count is None:
            value = _positive_int(row.get("NumberOfProcessors", None))
            if value is not None:
                cpu_count = value
        if duration_seconds is None:
            value = _positive_float(row.get("DurationSeconds", None))
            if value is not None:
                duration_seconds = value
        if events_lost is None:
            events_lost = _nonnegative_sum(df, "EventsLost")
        if buffers_lost is None:
            buffers_lost = _nonnegative_sum(df, "BuffersLost")
        if buffers_written is None:
            buffers_written = _nonnegative_sum(df, "BuffersWritten")

    lines: list[str] = []
    if cpu_count is not None:
        lines.append(f"Number of Processors : {cpu_count}")
    if duration_seconds is not None:
        lines.append(f"Trace duration (s)   : {duration_seconds:.7f}")
    if events_lost is not None:
        lines.append(f"Total # Lost Events  : {events_lost}")
    if buffers_lost is not None:
        lines.append(f"Buffers Lost         : {buffers_lost}")
    if buffers_written is not None:
        lines.append(f"Buffers Written      : {buffers_written}")
    return lines


def _positive_int(value) -> int | None:
    try:
        number = int(float(value))
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def _positive_float(value) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def _nonnegative_sum(df, column: str) -> int | None:
    if df is None or getattr(df, "empty", True) or column not in df.columns:
        return None
    values = pd.to_numeric(df[column], errors="coerce").dropna()
    if values.empty:
        return None
    values = values[values >= 0]
    if values.empty:
        return None
    return int(values.sum())


def build_tracestats_text(trace: "TraceData") -> Optional[str]:
    """Build a ``tracestats``-equivalent text block.

    Pulls the per-provider counts and lost-event totals off
    ``trace.event_counts`` and any cached ``ExtractStats``. The native text
    is a compact xperf-compatible subset, not a byte-for-byte
    ``xperf -a tracestats`` clone.
    """
    counts = getattr(trace, "event_counts", None) or {}
    extract_stats = getattr(trace, "_native_extract_stats", None)

    lines: list[str] = ["Trace Statistics", "==="]
    metadata_lines = _metadata_lines(trace)
    if metadata_lines:
        lines.extend(metadata_lines)
        lines.append("")
    if extract_stats is not None:
        lines.append(f"Total events:    {extract_stats.event_count}")
        lines.append(f"EventCount:      {extract_stats.event_count}")
        lines.append(f"Bytes processed: {extract_stats.bytes_processed}")
        lines.append(f"Events lost:     {extract_stats.events_lost}")
        lines.append(f"Stacks paired:   {extract_stats.stacks_paired}")
        lines.append(f"Stacks orphan:   {extract_stats.stacks_orphan}")
        lines.append(f"Elapsed:         {extract_stats.elapsed_seconds:.2f}s")
        lines.append("")
        lines.append("Provider events:")
        provider_counts = getattr(extract_stats, "provider_counts", None) or {}
        for guid, count in sorted(provider_counts.items(), key=lambda kv: -kv[1]):
            lines.append(f"  {guid}: {count}")
            lines.append(f"  {guid} EventCount={count}")
        lines.append("")
        decoded_counts = getattr(extract_stats, "decoded_counts", None) or {}
        if decoded_counts:
            lines.append("Decoded classes:")
            for name, count in sorted(decoded_counts.items(), key=lambda kv: -kv[1]):
                lines.append(f"  {name}: {count}")
            lines.append("")
    elif counts:
        lines.append("Per-dataset row counts:")
        for name, count in sorted(counts.items(), key=lambda kv: -kv[1]):
            lines.append(f"  {name}: {count}")
        lines.append("")
    elif metadata_lines:
        pass
    else:
        return None
    return "\n".join(lines) + "\n"


__all__ = ["build_tracestats_text"]
