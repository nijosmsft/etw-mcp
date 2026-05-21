"""Phase 2 tool: walk context-switch wait chains for a thread.

For a target thread (specified by TID or by process-name substring), find the
context-switch events where the thread was readied and surface the
``WaitReason`` histogram. This is the "why is this network-recv worker
blocking?" tool — it tells you the thread spends 80% of its waits on
``WrQueue`` (waiting for thread-pool work), or ``WrDispatchInt`` (waiting on
a DPC), etc.

This is a v1 wait-chain tool: it surfaces the histogram + a sample of the
underlying CSwitch events but does NOT correlate to the readying thread's
preceding switch-out (true CPA). The plan's note in
``wpr-mcp-networking-plan.md`` explicitly accepts this simplification — v2
will join ``ReadyThread`` events when the dumper extracts them.
"""

from __future__ import annotations

import pandas as pd

from etw_analyzer.app import mcp
from etw_analyzer.formatting.markdown import format_table
from etw_analyzer.parsing.wait_chain import (
    find_tids_for_process,
    summarize_wait_reasons,
    walk_wait_chain,
)
from etw_analyzer.trace_state import TraceData, require_trace


# Cap per-section sample table size so wide chains don't blow up the output.
_MAX_SAMPLE_ROWS = 20
# Cap on number of TIDs to surface when resolving a process-name substring.
# The list is sorted by activity, so the top-N are the most informative.
_MAX_TIDS_PER_PROCESS = 5


def _format_thread_section(
    cswitch_df: pd.DataFrame,
    tid: int,
    *,
    max_depth: int,
    max_window_us: float,
    process_name: str | None = None,
) -> str:
    """Render the wait-chain output for one TID as a markdown section."""
    events = walk_wait_chain(
        cswitch_df,
        target_tid=tid,
        max_depth=max_depth,
        max_window_us=max_window_us,
    )
    if not events:
        return f"### Thread {tid}\n\n*No context-switch events found for TID {tid}.*\n"

    # Try to infer the process name from the first event if not supplied.
    if process_name is None:
        process_name = str(events[0].get("NewProcessName", "")) or "(unknown)"

    histogram = summarize_wait_reasons(events)
    total = sum(histogram.values())

    lines: list[str] = []
    lines.append(f"### Thread {tid} in process `{process_name}`")
    lines.append("")
    lines.append(f"**Context-switches in window:** {total:,}")
    lines.append("")

    # WaitReason histogram
    hist_rows = [
        {"WaitReason": reason or "(unknown)", "Count": count, "%": (count / total * 100) if total else 0.0}
        for reason, count in sorted(histogram.items(), key=lambda kv: kv[1], reverse=True)
    ]
    hist_df = pd.DataFrame(hist_rows)
    lines.append("**WaitReason histogram:**")
    lines.append("")
    lines.append(format_table(
        hist_df,
        number_format={"Count": ",d", "%": ".2f"},
    ))
    lines.append("")

    # Sample event table
    sample_rows = events[:_MAX_SAMPLE_ROWS]
    sample_df = pd.DataFrame(sample_rows)
    # Project to the columns we want to display, in a stable order. Skip
    # columns that aren't present (defensive against schema drift).
    desired = ["TimeStamp", "WaitReason", "OldTID", "OldProcessName", "OldState", "CPU"]
    present = [c for c in desired if c in sample_df.columns]
    sample_df = sample_df[present] if present else sample_df

    lines.append(f"**Sample switch-in events** (up to {_MAX_SAMPLE_ROWS}):")
    lines.append("")
    lines.append(format_table(sample_df, max_rows=_MAX_SAMPLE_ROWS))
    if len(events) > _MAX_SAMPLE_ROWS:
        lines.append("")
        lines.append(f"*({len(events) - _MAX_SAMPLE_ROWS:,} additional events not shown.)*")
    lines.append("")
    return "\n".join(lines)


@mcp.tool()
def get_network_wait_chain(
    trace_id: str,
    thread_filter: int | str,
    max_depth: int = 10,
    max_window_us: float = 1_000_000,
) -> str:
    """Walk context-switch wait chains for a thread to identify why it blocks.

    Surfaces the ``WaitReason`` histogram for every CSwitch event where the
    target thread was switched IN. High ``WrQueue`` counts indicate worker
    threads waiting on a thread-pool queue; high ``WrDispatchInt`` suggests
    waiting on a DPC; ``WrAlertByThreadId`` is typical for IOCP/ALPC; lock
    waits show up as ``WrResource``/``WrEventPair``.

    v1 surfaces the histogram and a sample of switch-in events. v2 (when
    ReadyThread events land in the dumper extraction) will additionally
    correlate each wake to the readying thread's preceding switch-out for
    true causal chain attribution.

    Args:
        trace_id: ID returned by load_trace.
        thread_filter: Either a thread ID (int) or a substring of the
            process name (str). When a string is given, the busiest TIDs
            matching that process are surfaced as separate sections.
        max_depth: Reserved for the v2 ReadyThread join. Accepted today
            for API stability.
        max_window_us: Reserved for the v2 ReadyThread join. Accepted
            today for API stability.
    """
    trace = require_trace(trace_id)

    # The CSwitch DataFrame is populated by the background dumper thread.
    # Wait for it so we don't false-negative on a freshly-loaded trace.
    trace.wait_for_dumper()

    cswitch_df = trace.cswitch_events_df
    if cswitch_df is None or cswitch_df.empty:
        return (
            "**Wait-chain analysis**\n\n"
            "*No CSwitch events available for this trace.*\n\n"
            "CSwitch events come from the kernel ``CSwitch`` provider, which "
            "the `xdptrace.wprp` profile enables by default. If this trace was "
            "collected with a profile that omits the CSwitch keyword (or the "
            "background dumper extraction failed), no wait-chain analysis is "
            "possible. Re-collect the trace with a profile that includes the "
            "CSwitch kernel flag and reload."
        )

    header = ["**Wait-chain analysis**", ""]

    # Resolve thread_filter → list of (tid, process_name) sections to render.
    sections: list[str] = []

    if isinstance(thread_filter, int):
        sections.append(_format_thread_section(
            cswitch_df,
            tid=thread_filter,
            max_depth=max_depth,
            max_window_us=max_window_us,
        ))
    else:
        substring = str(thread_filter).strip()
        if not substring:
            return "\n".join(header + [
                "*`thread_filter` must be a TID (int) or a non-empty process-name substring.*",
            ])

        matches = find_tids_for_process(cswitch_df, substring)
        if not matches:
            return "\n".join(header + [
                f"*No threads matched process substring `{substring}`.*",
            ])

        # Take the top-N busiest TIDs. The list is already sorted descending.
        top = matches[:_MAX_TIDS_PER_PROCESS]
        header.append(
            f"Matched {len(matches)} TID(s) for process substring `{substring}` — "
            f"rendering top {len(top)} by switch-in count."
        )
        header.append("")

        for tid, proc_name, _count in top:
            sections.append(_format_thread_section(
                cswitch_df,
                tid=tid,
                max_depth=max_depth,
                max_window_us=max_window_us,
                process_name=proc_name,
            ))

    return "\n".join(header + sections)
