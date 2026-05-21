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

    recv = trace.tcpip_recv_df
    send = trace.tcpip_send_df
    rtx = trace.tcpip_retransmit_df

    have_any = any(
        _has_columns(df, "LocalAddr", "LocalPort", "RemoteAddr", "RemotePort")
        for df in (recv, send, rtx)
    )
    if not have_any:
        return _NO_TCPIP_DATA_MSG

    pieces = []
    for df, kind in ((recv, "recv"), (send, "send"), (rtx, "rtx")):
        if df is None or df.empty:
            continue
        if not _has_columns(df, "LocalAddr", "LocalPort", "RemoteAddr", "RemotePort"):
            continue
        filtered = _apply_process_filter(df, process_filter).copy()
        if filtered.empty:
            continue
        filtered["_kind"] = kind
        pieces.append(filtered)

    if not pieces:
        msg = "*No matching TCP events"
        if process_filter:
            msg += f" for process filter `{process_filter}`"
        msg += ".*"
        return msg

    combined = pd.concat(pieces, ignore_index=True, sort=False)

    # Build 5-tuple key as a single string for grouping.
    combined["FiveTuple"] = combined.apply(_five_tuple, axis=1)

    rows = []
    for tup, group in combined.groupby("FiveTuple"):
        recv_rows = group[group["_kind"] == "recv"]
        send_rows = group[group["_kind"] == "send"]
        rtx_rows = group[group["_kind"] == "rtx"]

        recv_bytes = int(recv_rows["Size"].sum()) if "Size" in recv_rows.columns and not recv_rows.empty else 0
        send_bytes = int(send_rows["Size"].sum()) if "Size" in send_rows.columns and not send_rows.empty else 0
        recv_pkts = len(recv_rows)
        send_pkts = len(send_rows)

        # Retransmit count: sum RetransmitCount if present, else row count.
        if not rtx_rows.empty and "RetransmitCount" in rtx_rows.columns:
            rtx_count = int(rtx_rows["RetransmitCount"].sum())
        else:
            rtx_count = len(rtx_rows)

        duration = _safe_duration(group["TimeStamp"]) if "TimeStamp" in group.columns else 0.0
        proc_name = group["Process Name"].iloc[0] if "Process Name" in group.columns else ""

        rows.append({
            "5-Tuple": tup,
            "Process": proc_name,
            "Recv Bytes": recv_bytes,
            "Send Bytes": send_bytes,
            "Total Bytes": recv_bytes + send_bytes,
            "Packets": recv_pkts + send_pkts,
            "Retransmits": rtx_count,
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

    recv = trace.udp_recv_df
    send = trace.udp_send_df

    have_any = any(
        _has_columns(df, "LocalAddr", "LocalPort", "RemoteAddr", "RemotePort")
        for df in (recv, send)
    )
    if not have_any:
        return _NO_UDP_DATA_MSG

    pieces = []
    for df, kind in ((recv, "recv"), (send, "send")):
        if df is None or df.empty:
            continue
        if not _has_columns(df, "LocalAddr", "LocalPort", "RemoteAddr", "RemotePort"):
            continue
        filtered = _apply_process_filter(df, process_filter).copy()
        if filtered.empty:
            continue
        filtered["_kind"] = kind
        pieces.append(filtered)

    if not pieces:
        msg = "*No matching UDP events"
        if process_filter:
            msg += f" for process filter `{process_filter}`"
        msg += ".*"
        return msg

    combined = pd.concat(pieces, ignore_index=True, sort=False)
    combined["FiveTuple"] = combined.apply(_five_tuple, axis=1)

    rows = []
    for tup, group in combined.groupby("FiveTuple"):
        recv_rows = group[group["_kind"] == "recv"]
        send_rows = group[group["_kind"] == "send"]

        recv_pkts = len(recv_rows)
        send_pkts = len(send_rows)
        packets = recv_pkts + send_pkts
        size_col = group["Size"] if "Size" in group.columns else pd.Series([], dtype=int)
        total_bytes = int(size_col.sum()) if not size_col.empty else 0

        duration = _safe_duration(group["TimeStamp"]) if "TimeStamp" in group.columns else 0.0
        pps = (packets / duration) if duration > 0 else 0.0
        proc_name = group["Process Name"].iloc[0] if "Process Name" in group.columns else ""

        rows.append({
            "5-Tuple": tup,
            "Process": proc_name,
            "Recv Pkts": recv_pkts,
            "Send Pkts": send_pkts,
            "Total Pkts": packets,
            "Bytes": total_bytes,
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

    rtx = trace.tcpip_retransmit_df
    recv = trace.tcpip_recv_df
    send = trace.tcpip_send_df

    if not _has_columns(rtx, "LocalAddr", "LocalPort", "RemoteAddr", "RemotePort"):
        # No retransmits is not the same as no TCP data, but if neither
        # recv nor send have data either, treat as "no TCP".
        if not any(
            _has_columns(df, "LocalAddr", "LocalPort", "RemoteAddr", "RemotePort")
            for df in (recv, send)
        ):
            return _NO_TCPIP_DATA_MSG
        return (
            "**TCP Retransmits**\n\n"
            "*No retransmit events observed in this trace.* "
            "(TCP recv/send events are present, so the trace did capture TCP — "
            "there were simply no retransmissions.)"
        )

    # Build per-tuple packet counts from recv + send first.
    pkt_counts: dict[str, int] = {}
    for df in (recv, send):
        if df is None or df.empty:
            continue
        if not _has_columns(df, "LocalAddr", "LocalPort", "RemoteAddr", "RemotePort"):
            continue
        for _, row in df.iterrows():
            tup = _five_tuple(row)
            pkt_counts[tup] = pkt_counts.get(tup, 0) + 1

    # Aggregate retransmits per tuple.
    rtx_local = rtx.copy()
    rtx_local["FiveTuple"] = rtx_local.apply(_five_tuple, axis=1)
    if "RetransmitCount" not in rtx_local.columns:
        rtx_local["RetransmitCount"] = 1

    rows = []
    for tup, group in rtx_local.groupby("FiveTuple"):
        rtx_count = int(group["RetransmitCount"].sum())
        base_pkts = pkt_counts.get(tup, 0)
        total_pkts = base_pkts + rtx_count
        rate = (rtx_count / total_pkts) if total_pkts > 0 else 0.0
        proc_name = group["Process Name"].iloc[0] if "Process Name" in group.columns else ""

        rows.append({
            "5-Tuple": tup,
            "Process": proc_name,
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

    tcp_recv = trace.tcpip_recv_df
    tcp_send = trace.tcpip_send_df
    udp_recv = trace.udp_recv_df
    udp_send = trace.udp_send_df

    inputs = [
        (tcp_recv, "tcp", "recv"),
        (tcp_send, "tcp", "send"),
        (udp_recv, "udp", "recv"),
        (udp_send, "udp", "send"),
    ]

    have_any = any(
        df is not None and not df.empty and "Process Name" in df.columns
        for df, _, _ in inputs
    )
    if not have_any:
        return (
            "*No TCP or UDP socket event data in this trace.*\n\n"
            "Re-collect using `udp-perf/scripts/networking.wprp` to capture "
            "the TCPIP/UDP kernel providers."
        )

    # Per-(process, pid, proto, dir): packet count, byte total, time range.
    agg: dict[tuple, dict] = {}
    for df, proto, direction in inputs:
        if df is None or df.empty or "Process Name" not in df.columns:
            continue
        for _, row in df.iterrows():
            key = (
                row.get("Process Name", ""),
                int(row.get("PID", 0) or 0),
                proto,
                direction,
            )
            entry = agg.setdefault(key, {"pkts": 0, "bytes": 0, "tmin": None, "tmax": None})
            entry["pkts"] += 1
            size = row.get("Size", 0)
            try:
                entry["bytes"] += int(size or 0)
            except (TypeError, ValueError):
                pass
            ts = row.get("TimeStamp")
            if ts is not None:
                try:
                    ts_int = int(ts)
                except (TypeError, ValueError):
                    ts_int = None
                if ts_int is not None:
                    if entry["tmin"] is None or ts_int < entry["tmin"]:
                        entry["tmin"] = ts_int
                    if entry["tmax"] is None or ts_int > entry["tmax"]:
                        entry["tmax"] = ts_int

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
