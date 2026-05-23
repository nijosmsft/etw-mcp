"""Aggregator: ``tracestats`` raw-text — replacement for ``xperf -a tracestats``.

xperf prints per-provider event counts and dropped/lost event counters.
The native consumer captures the same data via :class:`ExtractStats`
(see ``native/extract.py``); this aggregator pulls those counters off
the trace and formats them as the text dump xperf would emit.

If extraction stats weren't recorded (older traces, or a load_trace
call that didn't pass a ``stats_sink``), this returns ``None``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from etw_analyzer.trace_state import TraceData


def build_tracestats_text(trace: "TraceData") -> Optional[str]:
    """Build a ``tracestats``-equivalent text block.

    Pulls the per-provider counts and lost-event totals off
    ``trace.event_counts`` and any cached ``ExtractStats``.
    """
    counts = getattr(trace, "event_counts", None) or {}
    extract_stats = getattr(trace, "_native_extract_stats", None)

    lines: list[str] = ["Trace Statistics", "==="]
    if extract_stats is not None:
        lines.append(f"Total events:    {extract_stats.event_count}")
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
    else:
        return None
    return "\n".join(lines) + "\n"


__all__ = ["build_tracestats_text"]
