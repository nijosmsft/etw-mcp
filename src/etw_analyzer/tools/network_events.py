"""Phase 3a networking-event tools.

These tools aggregate raw TCPIP / UDP events extracted by the background
dumper pass (see :func:`etw_analyzer.tools.trace_mgmt._start_background_dumper`
and :func:`etw_analyzer.parsing.wpa_exporter.parse_dumper_events`). Every
tool here:

- Calls ``trace.wait_for_dumper()`` before reading the event DataFrames —
  background extraction may still be running.
- Returns a "no data" markdown explanation when the relevant DataFrame is
  missing or empty (most commonly because the trace was collected without
  the TCPIP/UDP providers; point users at ``udp-perf/scripts/networking.wprp``).
- Follows the project conventions: ``@mcp.tool()``, ``trace_id`` first arg,
  markdown-string return.

The four tools shipped in Phase 3a are the foundational per-flow /
per-process aggregates the rest of the networking analysis layer builds
on. AFD-level tools and packet-capture decoding land in later phases.
"""

from __future__ import annotations

import pandas as pd

from etw_analyzer.app import mcp
from etw_analyzer.formatting.markdown import format_pct, format_table
from etw_analyzer.native.aggregators.network import iter_enriched_network_batches
from etw_analyzer.trace_state import TraceData, require_trace


_NO_TCPIP_DATA_MSG = (
    "*No TCP/IP event data in this trace.*\n\n"
    "This usually means the trace was collected without the "
    "`Microsoft-Windows-TCPIP` provider enabled. To capture TCP events, "
    "re-collect the trace using `udp-perf/scripts/networking.wprp`."
)

_NO_UDP_DATA_MSG = (
    "*No UDP event data in this trace.*\n\n"
    "This usually means the trace was collected without the UDP kernel "
    "event flag (`EVENT_TRACE_FLAG_NETWORK_TCPIP`) or the "
    "`Microsoft-Windows-Kernel-Network` provider enabled. To capture UDP "
    "events, re-collect the trace using `udp-perf/scripts/networking.wprp`."
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _five_tuple(row) -> str:
    """Render a 5-tuple as a stable string for grouping / display."""
    return (
        f"{row['LocalAddr']}:{row['LocalPort']}"
        f" <-> {row['RemoteAddr']}:{row['RemotePort']}"
    )


def _ensure_dumper_ready(trace: TraceData) -> None:
    """Block until the background dumper has finished, if it's running."""
    trace.wait_for_dumper()
    if getattr(trace, "mode", "xperf") == "native":
        try:
            from etw_analyzer.native.aggregators.network import enrich_network_events
            enrich_network_events(trace)
        except Exception:
            pass


def _apply_process_filter(df: pd.DataFrame, process_filter: str | None) -> pd.DataFrame:
    """Case-insensitive substring filter on ``Process Name`` column."""
    if not process_filter or df.empty or "Process Name" not in df.columns:
        return df
    mask = df["Process Name"].astype(str).str.contains(
        process_filter, case=False, na=False
    )
    return df[mask]


def _safe_duration(timestamps: pd.Series) -> float:
    """Compute (max - min) in seconds for a TimeStamp column.

    Dumper timestamps are in microseconds. Returns 0.0 if the series is
    empty or contains non-numeric data.
    """
    if timestamps.empty:
        return 0.0
    try:
        vals = pd.to_numeric(timestamps, errors="coerce").dropna()
    except Exception:
        return 0.0
    if vals.empty:
        return 0.0
    return float((vals.max() - vals.min()) / 1_000_000.0)


def _has_columns(df: pd.DataFrame | None, *required: str) -> bool:
    if df is None or df.empty:
        return False
    return all(col in df.columns for col in required)


def _network_batches(
    trace: TraceData,
    event_class: str,
    columns: list[str],
):
    yield from iter_enriched_network_batches(
        trace,
        event_class,
        columns=columns,
    )


def _timestamp_us(value) -> int | None:
    try:
        if pd.isna(value):
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _safe_int(value, default: int = 0) -> int:
    try:
        if pd.isna(value):
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def _update_time_range(entry: dict, timestamp) -> None:
    ts = _timestamp_us(timestamp)
    if ts is None:
        return
    if entry.get("tmin") is None or ts < entry["tmin"]:
        entry["tmin"] = ts
    if entry.get("tmax") is None or ts > entry["tmax"]:
        entry["tmax"] = ts


# ---------------------------------------------------------------------------
# Tool: get_connection_summary
# ---------------------------------------------------------------------------


@mcp.tool()
def get_connection_summary(
    trace_id: str,
    top_n: int = 50,
    process_filter: str | None = None,
) -> str:
    """Per-TCP-connection summary: bytes, packets, retransmits, duration.

    Aggregates TCP recv + send + retransmit events by 5-tuple
    (LocalAddr:LocalPort <-> RemoteAddr:RemotePort). The output is sorted by
    total bytes (recv + send) descending. One row per connection.

    Args:
        trace_id: ID returned by load_trace.
        top_n: Maximum rows to return. Default: 50.
        process_filter: Case-insensitive substring filter on Process Name.
    """
    trace = require_trace(trace_id)
    _ensure_dumper_ready(trace)

    columns = [
        "TimeStamp", "Process Name", "PID",
        "LocalAddr", "LocalPort", "RemoteAddr", "RemotePort",
        "Size", "RetransmitCount",
    ]
    aggregates: dict[str, dict] = {}
    have_any = False
    have_after_filter = False
    for event_class, kind in (
        ("TcpIp/Recv", "recv"),
        ("TcpIp/Send", "send"),
        ("TcpIp/Retransmit", "rtx"),
    ):
        for batch in _network_batches(trace, event_class, columns):
            if not _has_columns(batch, "LocalAddr", "LocalPort", "RemoteAddr", "RemotePort"):
                continue
            have_any = True
            filtered = _apply_process_filter(batch, process_filter)
            if filtered.empty:
                continue
            have_after_filter = True
            for _, row in filtered.iterrows():
                tup = _five_tuple(row)
                entry = aggregates.setdefault(
                    tup,
                    {
                        "5-Tuple": tup,
                        "Process": row.get("Process Name", ""),
                        "Recv Bytes": 0,
                        "Send Bytes": 0,
                        "recv_pkts": 0,
                        "send_pkts": 0,
                        "Retransmits": 0,
                        "tmin": None,
                        "tmax": None,
                    },
                )
                if not entry.get("Process") and row.get("Process Name"):
                    entry["Process"] = row.get("Process Name", "")
                size = _safe_int(row.get("Size", 0))
                if kind == "recv":
                    entry["Recv Bytes"] += size
                    entry["recv_pkts"] += 1
                elif kind == "send":
                    entry["Send Bytes"] += size
                    entry["send_pkts"] += 1
                else:
                    entry["Retransmits"] += _safe_int(row.get("RetransmitCount", 1), 1)
                _update_time_range(entry, row.get("TimeStamp"))

    if not have_any:
        return _NO_TCPIP_DATA_MSG
    if not have_after_filter:
        msg = "*No matching TCP events"
        if process_filter:
            msg += f" for process filter `{process_filter}`"
        msg += ".*"
        return msg

    rows = []
    for entry in aggregates.values():
        recv_pkts = entry.pop("recv_pkts")
        send_pkts = entry.pop("send_pkts")
        tmin = entry.pop("tmin")
        tmax = entry.pop("tmax")
        duration = ((tmax - tmin) / 1_000_000.0) if tmin is not None and tmax is not None else 0.0
        rows.append({
            "5-Tuple": entry["5-Tuple"],
            "Process": entry["Process"],
            "Recv Bytes": entry["Recv Bytes"],
            "Send Bytes": entry["Send Bytes"],
            "Total Bytes": entry["Recv Bytes"] + entry["Send Bytes"],
            "Packets": recv_pkts + send_pkts,
            "Retransmits": entry["Retransmits"],
            "Duration (s)": round(duration, 3),
        })

    result_df = pd.DataFrame(rows).sort_values(
        "Total Bytes", ascending=False
    ).reset_index(drop=True)

    lines = [
        "**TCP Connection Summary**",
        "",
        f"Connections observed: {len(result_df):,}",
    ]
    if process_filter:
        lines.append(f"Process filter: `{process_filter}`")
    lines.append("")
    lines.append(format_table(result_df, max_rows=top_n))

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool: get_udp_flow_summary
# ---------------------------------------------------------------------------


@mcp.tool()
def get_udp_flow_summary(
    trace_id: str,
    top_n: int = 50,
    process_filter: str | None = None,
) -> str:
    """Per-UDP-flow summary: packet count, bytes, duration, packet rate.

    Aggregates UDP recv + send events by 5-tuple. Sorted by packet count
    descending. ``PPS`` is packets/sec computed from min/max TimeStamp over
    the flow (0 for single-packet flows).

    Args:
        trace_id: ID returned by load_trace.
        top_n: Maximum rows to return. Default: 50.
        process_filter: Case-insensitive substring filter on Process Name.
            Per-process is implicit (each row has a Process column); the
            filter just narrows which flows are shown.
    """
    trace = require_trace(trace_id)
    _ensure_dumper_ready(trace)

    columns = [
        "TimeStamp", "Process Name", "PID",
        "LocalAddr", "LocalPort", "RemoteAddr", "RemotePort",
        "Size",
    ]
    aggregates: dict[str, dict] = {}
    have_any = False
    have_after_filter = False
    for event_class, kind in (("UdpIp/Recv", "recv"), ("UdpIp/Send", "send")):
        for batch in _network_batches(trace, event_class, columns):
            if not _has_columns(batch, "LocalAddr", "LocalPort", "RemoteAddr", "RemotePort"):
                continue
            have_any = True
            filtered = _apply_process_filter(batch, process_filter)
            if filtered.empty:
                continue
            have_after_filter = True
            for _, row in filtered.iterrows():
                tup = _five_tuple(row)
                entry = aggregates.setdefault(
                    tup,
                    {
                        "5-Tuple": tup,
                        "Process": row.get("Process Name", ""),
                        "Recv Pkts": 0,
                        "Send Pkts": 0,
                        "Bytes": 0,
                        "tmin": None,
                        "tmax": None,
                    },
                )
                if not entry.get("Process") and row.get("Process Name"):
                    entry["Process"] = row.get("Process Name", "")
                if kind == "recv":
                    entry["Recv Pkts"] += 1
                else:
                    entry["Send Pkts"] += 1
                entry["Bytes"] += _safe_int(row.get("Size", 0))
                _update_time_range(entry, row.get("TimeStamp"))

    if not have_any:
        return _NO_UDP_DATA_MSG
    if not have_after_filter:
        msg = "*No matching UDP events"
        if process_filter:
            msg += f" for process filter `{process_filter}`"
        msg += ".*"
        return msg

    rows = []
    for entry in aggregates.values():
        recv_pkts = entry["Recv Pkts"]
        send_pkts = entry["Send Pkts"]
        packets = recv_pkts + send_pkts
        tmin = entry["tmin"]
        tmax = entry["tmax"]
        duration = ((tmax - tmin) / 1_000_000.0) if tmin is not None and tmax is not None else 0.0
        pps = (packets / duration) if duration > 0 else 0.0

        rows.append({
            "5-Tuple": entry["5-Tuple"],
            "Process": entry["Process"],
            "Recv Pkts": recv_pkts,
            "Send Pkts": send_pkts,
            "Total Pkts": packets,
            "Bytes": entry["Bytes"],
            "Duration (s)": round(duration, 3),
            "PPS": round(pps, 1),
        })

    result_df = pd.DataFrame(rows).sort_values(
        "Total Pkts", ascending=False
    ).reset_index(drop=True)

    lines = [
        "**UDP Flow Summary**",
        "",
        f"Flows observed: {len(result_df):,}",
    ]
    if process_filter:
        lines.append(f"Process filter: `{process_filter}`")
    lines.append("")
    lines.append(format_table(result_df, max_rows=top_n))

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool: get_tcp_retransmits
# ---------------------------------------------------------------------------


# Retransmit-rate threshold (as a fraction) above which we surface a
# connection as "high retransmits". 0.1% matches the plan's stated bar.
_RTX_RATE_FLAG_THRESHOLD = 0.001


@mcp.tool()
def get_tcp_retransmits(trace_id: str, top_n: int = 30) -> str:
    """Per-connection TCP retransmit count + rate.

    Computes ``retransmits / (recv_pkts + send_pkts + retransmits)`` for
    each 5-tuple. Connections with rate above 0.1% are flagged in the
    header summary as "high retransmit rate".

    Args:
        trace_id: ID returned by load_trace.
        top_n: Maximum rows to return. Default: 30.
    """
    trace = require_trace(trace_id)
    _ensure_dumper_ready(trace)

    columns = [
        "TimeStamp", "Process Name", "PID",
        "LocalAddr", "LocalPort", "RemoteAddr", "RemotePort",
        "Size", "RetransmitCount",
    ]
    pkt_counts: dict[str, int] = {}
    have_tcp = False
    for event_class in ("TcpIp/Recv", "TcpIp/Send"):
        for batch in _network_batches(trace, event_class, columns):
            if not _has_columns(batch, "LocalAddr", "LocalPort", "RemoteAddr", "RemotePort"):
                continue
            have_tcp = True
            for _, row in batch.iterrows():
                tup = _five_tuple(row)
                pkt_counts[tup] = pkt_counts.get(tup, 0) + 1

    rtx_agg: dict[str, dict] = {}
    have_rtx = False
    for batch in _network_batches(trace, "TcpIp/Retransmit", columns):
        if not _has_columns(batch, "LocalAddr", "LocalPort", "RemoteAddr", "RemotePort"):
            continue
        have_tcp = True
        have_rtx = True
        for _, row in batch.iterrows():
            tup = _five_tuple(row)
            entry = rtx_agg.setdefault(
                tup,
                {
                    "5-Tuple": tup,
                    "Process": row.get("Process Name", ""),
                    "Retransmits": 0,
                },
            )
            if not entry.get("Process") and row.get("Process Name"):
                entry["Process"] = row.get("Process Name", "")
            entry["Retransmits"] += _safe_int(row.get("RetransmitCount", 1), 1)

    if not have_rtx:
        if not have_tcp:
            return _NO_TCPIP_DATA_MSG
        return (
            "**TCP Retransmits**\n\n"
            "*No retransmit events observed in this trace.* "
            "(TCP recv/send events are present, so the trace did capture TCP — "
            "there were simply no retransmissions.)"
        )

    rows = []
    for tup, entry in rtx_agg.items():
        rtx_count = int(entry["Retransmits"])
        base_pkts = pkt_counts.get(tup, 0)
        total_pkts = base_pkts + rtx_count
        rate = (rtx_count / total_pkts) if total_pkts > 0 else 0.0

        rows.append({
            "5-Tuple": tup,
            "Process": entry["Process"],
            "Retransmits": rtx_count,
            "Packets": total_pkts,
            "Rate": format_pct(rate * 100.0),
            "_rate_raw": rate,
        })

    result_df = pd.DataFrame(rows).sort_values(
        "Retransmits", ascending=False
    ).reset_index(drop=True)

    flagged = int((result_df["_rate_raw"] > _RTX_RATE_FLAG_THRESHOLD).sum()) if not result_df.empty else 0
    display = result_df.drop(columns=["_rate_raw"])

    lines = [
        "**TCP Retransmits**",
        "",
        f"Connections with retransmits: {len(result_df):,}",
    ]
    if flagged:
        lines.append(
            f"**HIGH RETRANSMIT RATE:** {flagged} connection(s) above "
            f"{_RTX_RATE_FLAG_THRESHOLD * 100:.1f}% threshold."
        )
    else:
        lines.append("All connections below 0.1% retransmit rate.")
    lines.append("")
    lines.append(format_table(display, max_rows=top_n))

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool: get_per_process_socket_throughput
# ---------------------------------------------------------------------------


@mcp.tool()
def get_per_process_socket_throughput(trace_id: str, top_n: int = 30) -> str:
    """Per-process PPS and MB/s, split TCP vs UDP, send vs recv.

    The headline "what is my server actually doing on the network" tool.
    One row per (Process Name, PID) with eight columns: TCP recv/send PPS
    and MB/s, UDP recv/send PPS and MB/s. Sorted by total throughput
    (bytes/sec) descending.

    Args:
        trace_id: ID returned by load_trace.
        top_n: Maximum rows to return. Default: 30.
    """
    trace = require_trace(trace_id)
    _ensure_dumper_ready(trace)

    inputs = [
        ("TcpIp/Recv", "tcp", "recv"),
        ("TcpIp/Send", "tcp", "send"),
        ("UdpIp/Recv", "udp", "recv"),
        ("UdpIp/Send", "udp", "send"),
    ]

    # Per-(process, pid, proto, dir): packet count, byte total, time range.
    agg: dict[tuple, dict] = {}
    have_any = False
    columns = ["TimeStamp", "Process Name", "PID", "Size"]
    for event_class, proto, direction in inputs:
        for batch in _network_batches(trace, event_class, columns):
            if batch.empty or "Process Name" not in batch.columns:
                continue
            have_any = True
            for _, row in batch.iterrows():
                key = (
                    row.get("Process Name", ""),
                    _safe_int(row.get("PID", 0)),
                    proto,
                    direction,
                )
                entry = agg.setdefault(key, {"pkts": 0, "bytes": 0, "tmin": None, "tmax": None})
                entry["pkts"] += 1
                entry["bytes"] += _safe_int(row.get("Size", 0))
                _update_time_range(entry, row.get("TimeStamp"))

    if not have_any:
        return (
            "*No TCP or UDP socket event data in this trace.*\n\n"
            "Re-collect using `udp-perf/scripts/networking.wprp` to capture "
            "the TCPIP/UDP kernel providers."
        )

    # Flatten per process+PID.
    proc_rows: dict[tuple, dict] = {}
    for (proc, pid, proto, direction), entry in agg.items():
        rec = proc_rows.setdefault(
            (proc, pid),
            {
                "Process": proc,
                "PID": pid,
                "TCP Recv PPS": 0.0, "TCP Recv MB/s": 0.0,
                "TCP Send PPS": 0.0, "TCP Send MB/s": 0.0,
                "UDP Recv PPS": 0.0, "UDP Recv MB/s": 0.0,
                "UDP Send PPS": 0.0, "UDP Send MB/s": 0.0,
                "_total_bps": 0.0,
            },
        )
        duration_s = 0.0
        if entry["tmin"] is not None and entry["tmax"] is not None and entry["tmax"] > entry["tmin"]:
            duration_s = (entry["tmax"] - entry["tmin"]) / 1_000_000.0
        pps = (entry["pkts"] / duration_s) if duration_s > 0 else 0.0
        mbps = ((entry["bytes"] / duration_s) / (1024 * 1024)) if duration_s > 0 else 0.0
        key_pps = f"{proto.upper()} {direction.capitalize()} PPS"
        key_mbps = f"{proto.upper()} {direction.capitalize()} MB/s"
        rec[key_pps] = round(pps, 1)
        rec[key_mbps] = round(mbps, 2)
        rec["_total_bps"] += (entry["bytes"] / duration_s) if duration_s > 0 else 0.0

    rows = sorted(proc_rows.values(), key=lambda r: r["_total_bps"], reverse=True)
    result_df = pd.DataFrame(rows)
    if "_total_bps" in result_df.columns:
        result_df = result_df.drop(columns=["_total_bps"])

    lines = [
        "**Per-Process Socket Throughput**",
        "",
        f"Processes observed with TCP/UDP traffic: {len(result_df):,}",
        "",
        format_table(result_df, max_rows=top_n),
    ]
    return "\n".join(lines)


__all__ = [
    "get_connection_summary",
    "get_udp_flow_summary",
    "get_tcp_retransmits",
    "get_per_process_socket_throughput",
]
