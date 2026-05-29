"""Phase 3b networking-event tools.

Extends the per-flow / per-connection tools in
:mod:`etw_analyzer.tools.network_events` with AFD- and NDIS-level views:

- ``get_connect_latency`` / ``get_accept_latency`` — p50 / p95 / p99 / p999
  of TCP connect() / accept() latency per process.
- ``get_packet_drops`` — per-(miniport, reason) NDIS drop counts.
- ``get_afd_batching`` — packets-per-IOCP-completion per socket.
- ``get_socket_lifecycle`` — per-socket create / close timeline.
- ``get_socket_affinity_check`` — heuristic check that recv completions
  cluster on the bound CPU.

All tools follow the project conventions: ``@mcp.tool()``, ``trace_id``
first, markdown-string return, defensive parsing throughout.
"""

from __future__ import annotations

import pandas as pd

from etw_analyzer.app import mcp
from etw_analyzer.formatting.markdown import format_table
from etw_analyzer.native.aggregators.network import iter_enriched_network_batches
from etw_analyzer.trace_state import TraceData, require_trace


_NO_TCPIP_DATA_MSG = (
    "*No TCP/IP event data in this trace.*\n\n"
    "This usually means the trace was collected without the "
    "`Microsoft-Windows-TCPIP` provider enabled. To capture TCP events, "
    "re-collect the trace using `udp-perf/scripts/networking.wprp`."
)

_NO_AFD_DATA_MSG = (
    "*No AFD socket event data in this trace.*\n\n"
    "This usually means the trace was collected without the "
    "`Microsoft-Windows-Winsock-AFD` provider enabled. To capture AFD "
    "events, re-collect the trace using `udp-perf/scripts/networking.wprp`."
)

_NO_NDIS_DROP_DATA_MSG = (
    "*No NDIS dropped-packet event data in this trace.*\n\n"
    "Either no packets were dropped during the trace, or the trace was "
    "collected without the `Microsoft-Windows-NDIS` provider's drop "
    "keyword enabled. Native mode also does not register NDIS drop "
    "manifest event IDs until they are verified, to avoid silently "
    "misclassifying unrelated NDIS events. For best drop coverage, "
    "re-collect using `udp-perf/scripts/networking.wprp` and load with "
    "`mode=\"xperf\"`."
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _ensure_dumper_ready(trace: TraceData) -> None:
    trace.wait_for_dumper()
    if getattr(trace, "mode", "xperf") == "native":
        try:
            from etw_analyzer.native.aggregators.network import enrich_network_events
            enrich_network_events(trace)
        except Exception:
            pass


def _apply_process_filter(df: pd.DataFrame, process_filter: str | None) -> pd.DataFrame:
    if not process_filter or df.empty or "Process Name" not in df.columns:
        return df
    mask = df["Process Name"].astype(str).str.contains(
        process_filter, case=False, na=False
    )
    return df[mask]


def _has_columns(df: pd.DataFrame | None, *required: str) -> bool:
    if df is None or df.empty:
        return False
    return all(col in df.columns for col in required)


def _network_batches(trace: TraceData, event_class: str, columns: list[str]):
    yield from iter_enriched_network_batches(
        trace,
        event_class,
        columns=columns,
    )


def _safe_int(value, default: int = 0) -> int:
    try:
        if pd.isna(value):
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def _timestamp_us(value) -> int | None:
    try:
        if pd.isna(value):
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _percentile_us(series: pd.Series, p: float) -> float:
    """Compute a percentile (0..1) on a series of microsecond values.

    Returns 0.0 for an empty series. The dumper emits timestamps already in
    microseconds, so this helper is mostly a wrapper around
    ``pd.Series.quantile`` that handles the empty case cleanly.
    """
    if series.empty:
        return 0.0
    try:
        return float(series.quantile(p, interpolation="linear"))
    except Exception:
        return 0.0


def _compute_event_latencies_us(events_df: pd.DataFrame) -> pd.DataFrame:
    """Best-effort connect/accept latency derivation.

    AFD/TCPIP connect and accept events do not (today, on the builds this
    code was written against) carry a duration field that we can rely on.
    The signal we use instead: for each (PID, ThreadID), the gap between
    consecutive events on the same thread is treated as the operation's
    wall-clock cost. This is a reasonable proxy for a server thread that
    sits in ``accept()`` waiting for a connection: the inter-event delta
    reflects how long the previous accept took to dispatch.

    A more accurate measurement requires correlating with AFD start/end
    pairs which xperf does not surface as a single dumper line — we'd need
    raw ETW. Documenting the heuristic here so users know what the
    percentiles mean.

    Returns a DataFrame with columns ``Process Name``, ``PID``,
    ``LatencyUs``. Rows with no preceding event on the same thread are
    dropped (they have no defined latency).
    """
    if not _has_columns(events_df, "TimeStamp", "PID", "ThreadID"):
        return pd.DataFrame(columns=["Process Name", "PID", "LatencyUs"])

    df = events_df.copy()
    df["TimeStamp"] = pd.to_numeric(df["TimeStamp"], errors="coerce")
    df = df.dropna(subset=["TimeStamp"]).sort_values(["PID", "ThreadID", "TimeStamp"])

    df["LatencyUs"] = (
        df.groupby(["PID", "ThreadID"])["TimeStamp"].diff()
    )
    df = df.dropna(subset=["LatencyUs"])
    df = df[df["LatencyUs"] >= 0]
    if "Process Name" not in df.columns:
        df["Process Name"] = ""
    return df[["Process Name", "PID", "LatencyUs"]]


def _compute_event_latencies_from_batches(
    trace: TraceData,
    event_class: str,
) -> tuple[bool, pd.DataFrame]:
    columns = ["TimeStamp", "Process Name", "PID", "ThreadID"]
    last_by_thread: dict[tuple[int, int], tuple[int, str]] = {}
    rows: list[dict] = []
    saw_source = False

    for batch in _network_batches(trace, event_class, columns):
        if not _has_columns(batch, "TimeStamp", "PID", "ThreadID"):
            continue
        saw_source = True
        local = batch.copy()
        local["TimeStamp"] = pd.to_numeric(local["TimeStamp"], errors="coerce")
        local = local.dropna(subset=["TimeStamp"]).sort_values(["PID", "ThreadID", "TimeStamp"])
        for _, row in local.iterrows():
            pid = _safe_int(row.get("PID", 0))
            tid = _safe_int(row.get("ThreadID", 0))
            ts = _timestamp_us(row.get("TimeStamp"))
            if ts is None:
                continue
            key = (pid, tid)
            proc = row.get("Process Name", "")
            previous = last_by_thread.get(key)
            if previous is not None and ts >= previous[0]:
                rows.append({
                    "Process Name": proc or previous[1],
                    "PID": pid,
                    "LatencyUs": ts - previous[0],
                })
            last_by_thread[key] = (ts, str(proc or ""))

    return saw_source, pd.DataFrame(rows, columns=["Process Name", "PID", "LatencyUs"])


def _format_latency_table(
    latency_df: pd.DataFrame,
    *,
    top_n: int,
    title: str,
    process_filter: str | None,
    no_data_msg: str,
) -> str:
    """Render p50/p95/p99/p999 latency per process as a markdown table."""
    if latency_df.empty:
        return no_data_msg

    if process_filter:
        latency_df = _apply_process_filter(latency_df, process_filter)
    if latency_df.empty:
        return f"*No matching events for process filter `{process_filter}`.*"

    rows = []
    for (proc, pid), group in latency_df.groupby(["Process Name", "PID"]):
        latencies = group["LatencyUs"]
        rows.append({
            "Process": proc,
            "PID": int(pid) if pd.notna(pid) else 0,
            "Samples": len(latencies),
            "p50 (us)": round(_percentile_us(latencies, 0.50), 1),
            "p95 (us)": round(_percentile_us(latencies, 0.95), 1),
            "p99 (us)": round(_percentile_us(latencies, 0.99), 1),
            "p999 (us)": round(_percentile_us(latencies, 0.999), 1),
        })

    result_df = pd.DataFrame(rows).sort_values(
        "p99 (us)", ascending=False
    ).reset_index(drop=True)

    lines = [
        f"**{title}**",
        "",
        f"Processes observed: {len(result_df):,}",
    ]
    if process_filter:
        lines.append(f"Process filter: `{process_filter}`")
    lines.append("")
    lines.append(
        "*Latency is derived from inter-event timing per thread (see docstring "
        "for caveats — connect/accept events do not carry an explicit duration "
        "field, so this is a best-effort proxy).*"
    )
    lines.append("")
    lines.append(format_table(result_df, max_rows=top_n))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool: get_connect_latency
# ---------------------------------------------------------------------------


@mcp.tool()
def get_connect_latency(
    trace_id: str,
    top_n: int = 30,
    process_filter: str | None = None,
) -> str:
    """Per-process TCP connect() latency percentiles (p50 / p95 / p99 / p999).

    Uses ``tcpip_connect_df`` when present, falling back to ``afd_connect_df``.
    Latency is a best-effort estimate derived from inter-event timing on the
    same (PID, ThreadID) — connect events do not carry a built-in duration
    field, so the gap between consecutive connects on a thread is used as a
    proxy for how long each connect took to dispatch. For tight loops over
    one connect() at a time this is a reasonable signal; for high-fan-out
    code with many threads concurrently connecting the percentiles will be
    dominated by inter-arrival time rather than per-call cost. Treat as
    "connect cadence under load", not "syscall latency".

    Args:
        trace_id: ID returned by load_trace.
        top_n: Maximum rows to return. Default: 30.
        process_filter: Case-insensitive substring filter on Process Name.
    """
    trace = require_trace(trace_id)
    _ensure_dumper_ready(trace)

    saw_source, latency_df = _compute_event_latencies_from_batches(trace, "TcpIp/Connect")
    if not saw_source:
        saw_source, latency_df = _compute_event_latencies_from_batches(trace, "AFD/Connect")

    if not saw_source:
        return _NO_TCPIP_DATA_MSG

    return _format_latency_table(
        latency_df,
        top_n=top_n,
        title="TCP Connect Latency",
        process_filter=process_filter,
        no_data_msg=(
            "*No connect events with computable latency.* "
            "(Need at least two connects on the same thread to derive an "
            "inter-event gap.)"
        ),
    )


# ---------------------------------------------------------------------------
# Tool: get_accept_latency
# ---------------------------------------------------------------------------


@mcp.tool()
def get_accept_latency(
    trace_id: str,
    top_n: int = 30,
    process_filter: str | None = None,
) -> str:
    """Per-process TCP accept() latency percentiles (p50 / p95 / p99 / p999).

    Uses ``tcpip_accept_df`` when present, falling back to ``afd_accept_df``.
    Same heuristic as ``get_connect_latency``: inter-event gap on the same
    thread is the latency proxy. For a server thread sitting in ``accept()``
    this is meaningful — the gap reflects the dispatch latency between
    consecutive successful accepts.

    Args:
        trace_id: ID returned by load_trace.
        top_n: Maximum rows to return. Default: 30.
        process_filter: Case-insensitive substring filter on Process Name.
    """
    trace = require_trace(trace_id)
    _ensure_dumper_ready(trace)

    saw_source, latency_df = _compute_event_latencies_from_batches(trace, "TcpIp/Accept")
    if not saw_source:
        saw_source, latency_df = _compute_event_latencies_from_batches(trace, "AFD/Accept")

    if not saw_source:
        return _NO_TCPIP_DATA_MSG

    return _format_latency_table(
        latency_df,
        top_n=top_n,
        title="TCP Accept Latency",
        process_filter=process_filter,
        no_data_msg=(
            "*No accept events with computable latency.* "
            "(Need at least two accepts on the same thread to derive an "
            "inter-event gap.)"
        ),
    )


# ---------------------------------------------------------------------------
# Tool: get_packet_drops
# ---------------------------------------------------------------------------


@mcp.tool()
def get_packet_drops(trace_id: str, top_n: int = 30) -> str:
    """Per-(miniport, reason) NDIS dropped-packet counts.

    Reads NDIS drop rows and groups by (MiniportName, Reason). Each row
    shows the drop count, total bytes dropped, and percentage of total
    drops. Native mode currently omits NDIS drop manifest IDs unless they
    are verified; use ``mode="xperf"`` for the broadest drop coverage.
    Common reasons include ``MissingBuffer``, ``IpsecRcvPolicyError``,
    ``WrongAdapter``.

    Args:
        trace_id: ID returned by load_trace.
        top_n: Maximum rows to return. Default: 30.
    """
    trace = require_trace(trace_id)
    _ensure_dumper_ready(trace)

    columns = ["MiniportName", "Reason", "Size"]
    aggregate: dict[tuple[str, str], dict[str, int | str]] = {}
    total_drops = 0
    saw_reason = False
    for batch in _network_batches(trace, "NdisDrop", columns):
        if batch.empty or "Reason" not in batch.columns:
            continue
        saw_reason = True
        if "MiniportName" not in batch.columns:
            batch = batch.assign(MiniportName="")
        if "Size" not in batch.columns:
            batch = batch.assign(Size=0)
        for _, row in batch.iterrows():
            miniport = str(row.get("MiniportName", "") or "")
            reason = str(row.get("Reason", "") or "")
            key = (miniport, reason)
            entry = aggregate.setdefault(
                key,
                {"Miniport": miniport, "Reason": reason, "Count": 0, "Bytes": 0},
            )
            entry["Count"] = int(entry["Count"]) + 1
            entry["Bytes"] = int(entry["Bytes"]) + _safe_int(row.get("Size", 0))
            total_drops += 1

    if not saw_reason or not aggregate:
        return _NO_NDIS_DROP_DATA_MSG

    rows = []
    for entry in aggregate.values():
        count = int(entry["Count"])
        pct = (count / total_drops * 100.0) if total_drops > 0 else 0.0
        rows.append({
            "Miniport": entry["Miniport"],
            "Reason": entry["Reason"],
            "Count": count,
            "Bytes": int(entry["Bytes"]),
            "% of Drops": round(pct, 2),
        })

    result_df = pd.DataFrame(rows).sort_values(
        "Count", ascending=False
    ).reset_index(drop=True)

    lines = [
        "**NDIS Packet Drops**",
        "",
        f"Total drops: {total_drops:,}",
        f"Distinct (miniport, reason) pairs: {len(result_df):,}",
        "",
        format_table(result_df, max_rows=top_n),
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool: get_afd_batching
# ---------------------------------------------------------------------------


# Default batching window: consecutive recv events on the same thread within
# this many microseconds count as a single IOCP completion batch. 10 us
# matches typical kernel-mode batch durations for SIO_CPU_AFFINITY pinned
# sockets and is tunable (low values undercount big batches, high values
# overcount).
_AFD_BATCH_WINDOW_US = 10


@mcp.tool()
def get_afd_batching(
    trace_id: str,
    top_n: int = 30,
    process_filter: str | None = None,
) -> str:
    """Per-socket average packets-per-IOCP-completion (batching heuristic).

    Surfaces the "I'm getting one packet per completion" anti-pattern where
    a server is paying IOCP wakeup cost for every datagram instead of
    draining batches.

    Heuristic: AFD/Recv events do not carry an explicit "completion event
    boundary" field in the dumper output, so we approximate one. For each
    socket (grouped by SocketHandle), we sort recv events by timestamp on
    the receiving thread, and treat any gap LESS than ``_AFD_BATCH_WINDOW_US``
    (10 us by default) as "same completion batch". Gaps larger than the
    window start a new batch. The reported metric is the average number of
    events per batch.

    Caveats:
    - A socket that legitimately drains 1 packet at a time will look like
      "average 1.0" — this is the intended signal.
    - High-throughput sockets that submit many recvs in flight will have
      multiple completions packed into the window; the heuristic
      *over-counts* batch size in that case. Treat the number as
      directional, not exact.

    Args:
        trace_id: ID returned by load_trace.
        top_n: Maximum rows to return. Default: 30.
        process_filter: Case-insensitive substring filter on Process Name.
    """
    trace = require_trace(trace_id)
    _ensure_dumper_ready(trace)

    columns = ["TimeStamp", "Process Name", "PID", "ThreadID", "CPU", "SocketHandle", "Size"]
    groups: dict[tuple[int, int], dict] = {}
    saw_source = False
    saw_after_filter = False
    for batch in _network_batches(trace, "AFD/Recv", columns):
        if not _has_columns(batch, "TimeStamp", "SocketHandle", "ThreadID"):
            continue
        saw_source = True
        local = _apply_process_filter(batch, process_filter)
        if local.empty:
            continue
        saw_after_filter = True
        for _, row in local.iterrows():
            handle = _safe_int(row.get("SocketHandle", 0))
            tid = _safe_int(row.get("ThreadID", 0))
            ts = _timestamp_us(row.get("TimeStamp"))
            if ts is None:
                continue
            key = (handle, tid)
            entry = groups.setdefault(
                key,
                {
                    "Process": row.get("Process Name", ""),
                    "PID": _safe_int(row.get("PID", 0)),
                    "SocketHandle": handle,
                    "ThreadID": tid,
                    "timestamps": [],
                },
            )
            entry["timestamps"].append(ts)

    if not saw_source:
        return _NO_AFD_DATA_MSG
    if not saw_after_filter:
        return f"*No matching AFD recv events for process filter `{process_filter}`.*"

    rows = []
    for entry in groups.values():
        timestamps = sorted(entry["timestamps"])
        if not timestamps:
            continue
        # Walk consecutive timestamps and count batches. Each batch starts
        # at a gap > the window.
        batches = 1
        for i in range(1, len(timestamps)):
            gap = timestamps[i] - timestamps[i - 1]
            if gap > _AFD_BATCH_WINDOW_US:
                batches += 1
        events = len(timestamps)
        handle = entry["SocketHandle"]
        rows.append({
            "Process": entry["Process"],
            "PID": entry["PID"],
            "Socket": f"0x{int(handle):x}" if int(handle) else "0",
            "ThreadID": int(entry["ThreadID"]),
            "Events": events,
            "Batches": batches,
            "Avg per Completion": round(events / batches, 2) if batches > 0 else 0.0,
        })

    if not rows:
        return "*No AFD recv events with parsable timestamps.*"

    result_df = pd.DataFrame(rows).sort_values(
        "Events", ascending=False
    ).reset_index(drop=True)

    lines = [
        "**AFD Batching (Packets per IOCP Completion)**",
        "",
        f"Sockets observed: {len(result_df):,}",
        f"Batch window: {_AFD_BATCH_WINDOW_US} us "
        "(consecutive recv events on the same thread within this gap count "
        "as one completion)",
    ]
    if process_filter:
        lines.append(f"Process filter: `{process_filter}`")
    lines.append("")
    lines.append(format_table(result_df, max_rows=top_n))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool: get_socket_lifecycle
# ---------------------------------------------------------------------------


@mcp.tool()
def get_socket_lifecycle(
    trace_id: str,
    process_filter: str | None = None,
    top_n: int = 50,
) -> str:
    """Per-socket lifecycle: create / close timestamps, duration, recv / send / bytes.

    For each socket (keyed by SocketHandle within a (PID, Process) scope):
    - **Created at**: earliest AFD/Connect or AFD/Accept timestamp
    - **Closed at**: AFD/Close timestamp (blank if the trace ends before close)
    - **Duration**: closed - created (seconds), or "open" if no close seen
    - **Recv / Send counts** and **Total bytes**: aggregated from AFD recv/send

    Sorted by duration descending.

    Args:
        trace_id: ID returned by load_trace.
        process_filter: Case-insensitive substring filter on Process Name.
        top_n: Maximum rows to return. Default: 50.
    """
    trace = require_trace(trace_id)
    _ensure_dumper_ready(trace)

    # Per-socket aggregation. Key = (PID, SocketHandle) — handles get reused
    # across processes but are unique within one.
    agg: dict[tuple, dict] = {}
    saw_source = False

    def _touch(key: tuple, proc: str, pid: int) -> dict:
        entry = agg.setdefault(key, {
            "Process": proc, "PID": pid, "SocketHandle": key[1],
            "CreatedUs": None, "ClosedUs": None,
            "RecvCount": 0, "SendCount": 0, "Bytes": 0,
        })
        return entry

    def _process_batch(df: pd.DataFrame, *, kind: str) -> None:
        nonlocal saw_source
        if not _has_columns(df, "SocketHandle"):
            return
        saw_source = True
        local = _apply_process_filter(df, process_filter)
        if local.empty:
            return
        for _, row in local.iterrows():
            handle = _safe_int(row.get("SocketHandle", 0))
            if handle == 0:
                continue
            proc = row.get("Process Name", "")
            pid = _safe_int(row.get("PID", 0))
            key = (pid, handle)
            entry = _touch(key, proc, pid)
            ts = _timestamp_us(row.get("TimeStamp"))
            if kind == "connect" or kind == "accept":
                if ts is not None and (entry["CreatedUs"] is None or ts < entry["CreatedUs"]):
                    entry["CreatedUs"] = ts
            elif kind == "close":
                if ts is not None and (entry["ClosedUs"] is None or ts > entry["ClosedUs"]):
                    entry["ClosedUs"] = ts
            elif kind == "recv":
                entry["RecvCount"] += 1
                try:
                    entry["Bytes"] += int(row.get("Size", 0) or 0)
                except (TypeError, ValueError):
                    pass
            elif kind == "send":
                entry["SendCount"] += 1
                try:
                    entry["Bytes"] += int(row.get("Size", 0) or 0)
                except (TypeError, ValueError):
                    pass

    columns = ["TimeStamp", "Process Name", "PID", "ThreadID", "CPU", "SocketHandle", "Size"]
    for event_class, kind in (
        ("AFD/Connect", "connect"),
        ("AFD/Accept", "accept"),
        ("AFD/Close", "close"),
        ("AFD/Recv", "recv"),
        ("AFD/Send", "send"),
    ):
        for batch in _network_batches(trace, event_class, columns):
            _process_batch(batch, kind=kind)

    if not saw_source:
        return _NO_AFD_DATA_MSG

    if not agg:
        msg = "*No AFD sockets matched"
        if process_filter:
            msg += f" process filter `{process_filter}`"
        msg += ".*"
        return msg

    rows = []
    for entry in agg.values():
        created = entry["CreatedUs"]
        closed = entry["ClosedUs"]
        if created is not None and closed is not None and closed >= created:
            duration_s = (closed - created) / 1_000_000.0
            duration_cell: float | str = round(duration_s, 3)
        else:
            duration_cell = "open" if closed is None else "?"
        rows.append({
            "Process": entry["Process"],
            "PID": entry["PID"],
            "Socket": f"0x{int(entry['SocketHandle']):x}",
            "Created (us)": created if created is not None else "",
            "Closed (us)": closed if closed is not None else "",
            "Duration (s)": duration_cell,
            "Recv": entry["RecvCount"],
            "Send": entry["SendCount"],
            "Bytes": entry["Bytes"],
        })

    result_df = pd.DataFrame(rows)
    # Sort by numeric duration descending; "open" / "?" go last.
    def _sort_key(val):
        try:
            return float(val)
        except (TypeError, ValueError):
            return -1.0
    result_df = result_df.iloc[
        result_df["Duration (s)"].map(_sort_key).sort_values(ascending=False).index
    ].reset_index(drop=True)

    lines = [
        "**AFD Socket Lifecycle**",
        "",
        f"Sockets observed: {len(result_df):,}",
    ]
    if process_filter:
        lines.append(f"Process filter: `{process_filter}`")
    lines.append("")
    lines.append(format_table(result_df, max_rows=top_n))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool: get_socket_affinity_check
# ---------------------------------------------------------------------------


# A socket whose recv events are this concentrated on a single CPU is
# considered to have its SIO_CPU_AFFINITY honored end-to-end. 90% is a
# pragmatic threshold — perfect 100% is rare on real hardware due to RSS
# misses, SWRSS redirects, and migration after thread reschedules.
_AFFINITY_OK_DOMINANCE_PCT = 90.0


@mcp.tool()
def get_socket_affinity_check(trace_id: str) -> str:
    """Heuristic check that AFD recv completions cluster on one CPU per socket.

    For each socket (keyed by ``SocketHandle``), this tool computes the CPU
    distribution of its ``AFD/Recv`` events and reports the dominance of the
    most-frequent CPU. The reasoning: when a socket is bound with
    ``SIO_CPU_AFFINITY`` and the network stack honors that binding (via RSS
    queue steering or SWRSS / CPUMAP redirection), nearly every recv
    completion should fire on the bound CPU. A spread across many CPUs
    suggests the binding is being defeated — either the application didn't
    set SIO_CPU_AFFINITY, the NIC's RSS hash is distributing the flow
    elsewhere, or SWRSS / CPUMAP is not configured.

    Heuristic notes (read these before drawing conclusions):
    - We do NOT see SIO_CPU_AFFINITY events in xperf's dumper output today.
      We can't tell which sockets *intended* to be CPU-affinitized — we
      simply check whether the observed recv CPUs are concentrated.
    - A socket with very few recv events (<10) is reported but flagged as
      "low confidence" — random clustering can look like affinity at small
      sample sizes.
    - "Affinity working" = top CPU handles >=90% of recv events.
      "Affinity not working" = no single CPU handles >=90%.

    Without AFD/Bind events surfaced by xperf this is the best signal we
    can produce. Documenting the limitation rather than returning
    "not supported".

    Args:
        trace_id: ID returned by load_trace.
    """
    trace = require_trace(trace_id)
    _ensure_dumper_ready(trace)

    columns = ["Process Name", "PID", "SocketHandle", "CPU"]
    socket_counts: dict[int, dict] = {}
    saw_source = False
    saw_parseable_cpu = False
    for batch in _network_batches(trace, "AFD/Recv", columns):
        if not _has_columns(batch, "SocketHandle", "CPU"):
            continue
        saw_source = True
        for _, row in batch.iterrows():
            handle_int = _safe_int(row.get("SocketHandle", 0))
            if handle_int == 0:
                continue
            cpu = _safe_int(row.get("CPU", -1), -1)
            if cpu < 0:
                continue
            saw_parseable_cpu = True
            entry = socket_counts.setdefault(
                handle_int,
                {
                    "Process": row.get("Process Name", ""),
                    "PID": _safe_int(row.get("PID", 0)),
                    "cpu_counts": {},
                },
            )
            counts = entry["cpu_counts"]
            counts[cpu] = counts.get(cpu, 0) + 1

    if not saw_source:
        return _NO_AFD_DATA_MSG
    if not saw_parseable_cpu:
        return "*No AFD recv events with parseable CPU column.*"

    rows = []
    for handle_int, entry in socket_counts.items():
        cpu_counts_dict = entry["cpu_counts"]
        if not cpu_counts_dict:
            continue
        events = int(sum(cpu_counts_dict.values()))
        top_cpu, top_count = max(cpu_counts_dict.items(), key=lambda item: item[1])
        dominance = (top_count / events) * 100.0 if events > 0 else 0.0
        distinct_cpus = len(cpu_counts_dict)

        if events < 10:
            status = "low confidence"
        elif dominance >= _AFFINITY_OK_DOMINANCE_PCT:
            status = "affinity working"
        else:
            status = "affinity not working"

        rows.append({
            "Process": entry["Process"],
            "PID": entry["PID"],
            "Socket": f"0x{handle_int:x}",
            "Events": events,
            "Top CPU": top_cpu,
            "Top CPU %": round(dominance, 1),
            "Distinct CPUs": distinct_cpus,
            "Status": status,
        })

    if not rows:
        return "*No AFD recv events with usable socket+CPU data.*"

    result_df = pd.DataFrame(rows).sort_values(
        "Events", ascending=False
    ).reset_index(drop=True)

    working = int((result_df["Status"] == "affinity working").sum())
    broken = int((result_df["Status"] == "affinity not working").sum())
    low_conf = int((result_df["Status"] == "low confidence").sum())

    lines = [
        "**Socket Affinity Check (Heuristic)**",
        "",
        f"Sockets analyzed: {len(result_df):,}",
        f"- Affinity working (top CPU >= {_AFFINITY_OK_DOMINANCE_PCT:.0f}%): {working}",
        f"- Affinity not working: {broken}",
        f"- Low confidence (<10 recv events): {low_conf}",
        "",
        "*This is a heuristic. We cannot see SIO_CPU_AFFINITY socket-bind "
        "events in xperf's dumper today, so we infer affinity from the CPU "
        "distribution of recv completions. A socket that wasn't bound to a "
        "CPU at all will still show 'affinity working' if its flow happens "
        "to RSS to one queue.*",
        "",
        format_table(result_df, max_rows=50),
    ]
    return "\n".join(lines)


__all__ = [
    "get_connect_latency",
    "get_accept_latency",
    "get_packet_drops",
    "get_afd_batching",
    "get_socket_lifecycle",
    "get_socket_affinity_check",
]
