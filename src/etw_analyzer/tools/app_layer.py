"""Phase 5 application-layer tools (HTTP.sys + MsQuic).

Tools over the HTTP.sys and MsQuic event DataFrames populated by the
background dumper extraction (see
:func:`etw_analyzer.tools.trace_mgmt._start_background_dumper` and the
``_handle_http_*`` / ``_handle_quic_*`` handlers in
:mod:`etw_analyzer.parsing.wpa_exporter`).

Five tools are exposed:

- :func:`get_http_requests` — join Recv/Send/Deliver by RequestId and
  compute per-request latency.
- :func:`get_http_queue_depth` — approximate URL-group queue depth over
  time via a Recv/Deliver/Send/Close walk.
- :func:`get_quic_connections` — per-connection summary: lifetime,
  packets, bytes, packet-loss estimate from PacketNumber gaps.
- :func:`get_quic_cid_distribution` — CID-hash bucket → CPU distribution,
  validates the ``cpuredirect`` CID-hashing approach used in QUIC perf
  runs.
- :func:`get_quic_ack_delays` — per-connection AckDelay percentiles, flag
  connections above the 25 ms p99 threshold.

All tools follow the project conventions: ``@mcp.tool()``, ``trace_id``
first, markdown-string return, no emojis. Each tool waits for the
background dumper extraction before reading, and returns a friendly
"no data — re-collect with networking.wprp" markdown when the relevant
DataFrame is missing or empty.
"""

from __future__ import annotations

from typing import Any

import pandas as pd

from etw_analyzer.app import mcp
from etw_analyzer.formatting.markdown import format_table
from etw_analyzer.trace_state import TraceData, require_trace


_NO_HTTP_DATA_MSG = (
    "*No HTTP.sys event data in this trace.*\n\n"
    "Re-collect with `udp-perf/scripts/networking.wprp` — the "
    "`Microsoft-Windows-HttpService` provider must be enabled to record "
    "the HTTP.sys request lifecycle. Standard `xdptrace.wprp` traces do "
    "not include HttpService events."
)

_NO_QUIC_DATA_MSG = (
    "*No MsQuic event data in this trace.*\n\n"
    "Re-collect with `udp-perf/scripts/networking.wprp` — the "
    "`Microsoft-Quic` provider must be enabled to record QUIC connection "
    "state. Standard `xdptrace.wprp` traces do not include MsQuic events."
)


# Connections with p99 AckDelay above this value (microseconds) are
# flagged as poor delayed-ACK behavior. 25 ms aligns with the upper bound
# the TCP RFC suggests for the comparable mechanism — QUIC operators use
# the same number as a smoke-test signal.
_ACK_DELAY_FLAG_THRESHOLD_US = 25_000


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _ensure_dumper_ready(trace: TraceData) -> None:
    trace.wait_for_dumper()


def _has_rows(df: pd.DataFrame | None) -> bool:
    return df is not None and not df.empty


def _apply_process_filter(df: pd.DataFrame, process_filter: str | None) -> pd.DataFrame:
    if not process_filter or df.empty or "Process Name" not in df.columns:
        return df
    mask = df["Process Name"].astype(str).str.contains(
        process_filter, case=False, na=False
    )
    return df[mask]


def _fnv1a_hash(data: bytes) -> int:
    """Compute 32-bit FNV-1a hash of a byte string.

    Used as the placeholder CID hash for :func:`get_quic_cid_distribution`.

    Production fidelity note: real MsQuic / ``secnetperf cpuredirect`` uses
    a manifest-defined hash (likely a Toeplitz or SHA-based reduction over
    the CID bytes plus optional salt). The hash is opaque to a trace
    parser — there is no event field that records the final
    "hash & cpumap_mask" bucket. Until we can read the on-wire steering
    decision from the trace itself, FNV-1a is a small, fast,
    well-distributed proxy that lets the histogram show *whether*
    different CIDs land on different CPU buckets.
    """
    h = 0x811c9dc5
    for byte in data:
        h ^= byte
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def _cid_to_bytes(cid: str) -> bytes:
    """Normalize a CID string (hex) to bytes.

    Returns empty bytes if the string isn't parseable as hex. We tolerate
    ``0x`` prefix, mixed case, and embedded ``-`` / ``:`` separators (a
    common rendering in some MsQuic builds).
    """
    if not cid:
        return b""
    cleaned = cid.strip().strip('"').strip("'")
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    cleaned = cleaned.replace("-", "").replace(":", "").replace(" ", "")
    if not cleaned or len(cleaned) % 2 != 0:
        # If it's not pure hex, hash the raw bytes so distinct CIDs at
        # least bucket distinctly.
        return cid.encode("utf-8", errors="ignore")
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        return cid.encode("utf-8", errors="ignore")


# ---------------------------------------------------------------------------
# Tool: get_http_requests
# ---------------------------------------------------------------------------


@mcp.tool()
def get_http_requests(
    trace_id: str,
    top_n: int = 100,
    url_filter: str | None = None,
) -> str:
    """Per-HTTP-request lifecycle summary: URL, verb, status, latency.

    Joins HTTP.sys ``Recv`` (request received) and ``Send`` (response sent)
    events by ``RequestId``, optionally enriches with ``Deliver`` to
    compute app-pool handoff time. Output sorted by total latency
    (recv -> send) descending. Requests still in flight at trace end show
    a blank status and latency.

    Args:
        trace_id: ID returned by load_trace.
        top_n: Maximum rows to return. Default: 100.
        url_filter: Case-insensitive substring filter on Url.
    """
    trace = require_trace(trace_id)
    _ensure_dumper_ready(trace)

    recv = trace.http_recv_df
    send = trace.http_send_df
    deliver = trace.http_deliver_df

    if not _has_rows(recv):
        return _NO_HTTP_DATA_MSG

    # Build a per-RequestId record. Recv is the anchor (URL + verb live
    # only there); Send and Deliver are joined in by RequestId.
    recv_local = recv.copy()
    if url_filter and "Url" in recv_local.columns:
        recv_local = recv_local[
            recv_local["Url"].astype(str).str.contains(url_filter, case=False, na=False)
        ]
        if recv_local.empty:
            return f"*No HTTP requests match URL filter `{url_filter}`.*"

    # Pre-index Send / Deliver by RequestId for fast lookup. If multiple
    # rows share a RequestId (e.g. chunked send), use the first one we
    # see — Recv -> earliest Send is the meaningful response time.
    send_by_rid: dict[int, dict[str, Any]] = {}
    if _has_rows(send):
        for _, row in send.iterrows():
            rid = int(row.get("RequestId", 0) or 0)
            if rid and rid not in send_by_rid:
                send_by_rid[rid] = {
                    "TimeStamp": int(row.get("TimeStamp", 0) or 0),
                    "StatusCode": int(row.get("StatusCode", 0) or 0),
                    "ContentLength": int(row.get("ContentLength", 0) or 0),
                }

    deliver_by_rid: dict[int, int] = {}
    if _has_rows(deliver):
        for _, row in deliver.iterrows():
            rid = int(row.get("RequestId", 0) or 0)
            if rid and rid not in deliver_by_rid:
                deliver_by_rid[rid] = int(row.get("TimeStamp", 0) or 0)

    rows: list[dict[str, Any]] = []
    for _, row in recv_local.iterrows():
        rid = int(row.get("RequestId", 0) or 0)
        if rid == 0:
            continue
        recv_ts = int(row.get("TimeStamp", 0) or 0)
        verb = row.get("Verb", "")
        url = row.get("Url", "")

        send_info = send_by_rid.get(rid)
        send_ts = send_info["TimeStamp"] if send_info else 0
        status = send_info["StatusCode"] if send_info else 0
        recv_to_send_us = (send_ts - recv_ts) if send_info and send_ts >= recv_ts else 0

        deliver_ts = deliver_by_rid.get(rid, 0)
        deliver_to_send_us = (
            (send_ts - deliver_ts) if deliver_ts and send_info and send_ts >= deliver_ts else 0
        )

        rows.append({
            "RequestId": rid,
            "Verb": verb,
            "Url": url,
            "Status": status if status else "",
            "Recv->Send (us)": recv_to_send_us if send_info else "",
            "Deliver->Send (us)": deliver_to_send_us if deliver_ts and send_info else "",
            "_sort": recv_to_send_us,
        })

    if not rows:
        return "*No HTTP request records reconstructed (RequestId join produced no rows).*"

    result_df = pd.DataFrame(rows).sort_values(
        "_sort", ascending=False
    ).reset_index(drop=True)
    result_df = result_df.drop(columns=["_sort"])

    in_flight = int(sum(1 for r in rows if not r["Status"]))

    lines = [
        "**HTTP Requests**",
        "",
        f"Requests observed: {len(result_df):,}",
    ]
    if in_flight:
        lines.append(f"Requests in flight at trace end (no Send seen): {in_flight:,}")
    if url_filter:
        lines.append(f"URL filter: `{url_filter}`")
    lines.append("")
    lines.append(format_table(result_df, max_rows=top_n))

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool: get_http_queue_depth
# ---------------------------------------------------------------------------


@mcp.tool()
def get_http_queue_depth(trace_id: str, top_n: int = 20) -> str:
    """Per-URL-group queue depth (peak, average) and total requests.

    Approximates concurrent in-flight requests per UrlGroupId by walking
    the Recv -> Deliver -> Send -> Close events ordered by timestamp.
    For each event we adjust a running counter (+1 on Deliver, -1 on
    Send or Close) and track the maximum and mean. Connections without a
    Deliver event (Recv-only) are excluded from the per-group totals
    because we cannot attribute them to a URL group.

    Args:
        trace_id: ID returned by load_trace.
        top_n: Maximum rows to return. Default: 20.
    """
    trace = require_trace(trace_id)
    _ensure_dumper_ready(trace)

    deliver = trace.http_deliver_df
    send = trace.http_send_df
    close = trace.http_close_df

    if not _has_rows(deliver):
        if not _has_rows(trace.http_recv_df):
            return _NO_HTTP_DATA_MSG
        return (
            "**HTTP Queue Depth**\n\n"
            "*No HttpService/Deliver events in this trace — cannot attribute "
            "requests to URL groups.*"
        )

    # Map RequestId -> UrlGroupId via the Deliver event.
    rid_to_urlgroup: dict[int, int] = {}
    deliver_events: list[tuple[int, int, str]] = []  # (ts, url_group, "deliver")
    for _, row in deliver.iterrows():
        rid = int(row.get("RequestId", 0) or 0)
        ug = int(row.get("UrlGroupId", 0) or 0)
        ts = int(row.get("TimeStamp", 0) or 0)
        if rid:
            rid_to_urlgroup[rid] = ug
            deliver_events.append((ts, ug, "deliver"))

    # Stream Send / Close events with their resolved UrlGroupId.
    completion_events: list[tuple[int, int, str]] = []
    for df, kind in ((send, "send"), (close, "close")):
        if not _has_rows(df):
            continue
        for _, row in df.iterrows():
            rid = int(row.get("RequestId", 0) or 0)
            ug = rid_to_urlgroup.get(rid, 0)
            if ug == 0:
                continue
            ts = int(row.get("TimeStamp", 0) or 0)
            completion_events.append((ts, ug, kind))

    # For depth analysis we only want a single "completion" per request to
    # avoid double-counting Send + Close for the same lifecycle. Track which
    # RequestIds have already been completed.
    events: list[tuple[int, int, int]] = []  # (ts, url_group, delta)
    completed_rids: set[int] = set()

    for _, row in deliver.iterrows():
        rid = int(row.get("RequestId", 0) or 0)
        ug = int(row.get("UrlGroupId", 0) or 0)
        ts = int(row.get("TimeStamp", 0) or 0)
        if rid and ug:
            events.append((ts, ug, +1))

    # Use Send when available; fall back to Close if no Send (rare).
    for df, kind in ((send, "send"), (close, "close")):
        if not _has_rows(df):
            continue
        for _, row in df.iterrows():
            rid = int(row.get("RequestId", 0) or 0)
            if rid in completed_rids:
                continue
            ug = rid_to_urlgroup.get(rid, 0)
            if ug == 0:
                continue
            ts = int(row.get("TimeStamp", 0) or 0)
            events.append((ts, ug, -1))
            completed_rids.add(rid)

    # Sort by timestamp and walk per URL group.
    events.sort(key=lambda e: e[0])
    per_group: dict[int, dict[str, Any]] = {}
    current_depth: dict[int, int] = {}

    # Track depth-time integral for time-weighted average. We approximate
    # by area under the depth-step function between adjacent events.
    last_ts_for_group: dict[int, int] = {}
    integral_for_group: dict[int, int] = {}

    for ts, ug, delta in events:
        depth = current_depth.get(ug, 0)
        # Integrate previous depth over the elapsed interval.
        if ug in last_ts_for_group and ts >= last_ts_for_group[ug]:
            integral_for_group[ug] = integral_for_group.get(ug, 0) + depth * (
                ts - last_ts_for_group[ug]
            )
        depth += delta
        if depth < 0:
            depth = 0  # Guard against double-completion edge cases.
        current_depth[ug] = depth
        last_ts_for_group[ug] = ts

        rec = per_group.setdefault(ug, {"peak": 0, "deliveries": 0, "completions": 0})
        if delta > 0:
            rec["deliveries"] += 1
        else:
            rec["completions"] += 1
        if depth > rec["peak"]:
            rec["peak"] = depth

    if not per_group:
        return (
            "**HTTP Queue Depth**\n\n"
            "*No deliverable HTTP requests in this trace.*"
        )

    rows: list[dict[str, Any]] = []
    for ug, rec in per_group.items():
        # Time-weighted average depth = integral / time span.
        span = 0
        for ts, target_ug, _ in events:
            if target_ug == ug:
                if span == 0:
                    span = ts
                else:
                    span = ts
        # Recompute span as max-min for the group.
        group_timestamps = [ts for ts, target_ug, _ in events if target_ug == ug]
        if group_timestamps:
            span = max(group_timestamps) - min(group_timestamps)
        else:
            span = 0
        integral = integral_for_group.get(ug, 0)
        avg_depth = (integral / span) if span > 0 else 0.0

        rows.append({
            "UrlGroupId": ug,
            "Peak Depth": rec["peak"],
            "Avg Depth": round(avg_depth, 2),
            "Deliveries": rec["deliveries"],
            "Completions": rec["completions"],
        })

    result_df = pd.DataFrame(rows).sort_values(
        "Peak Depth", ascending=False
    ).reset_index(drop=True)

    lines = [
        "**HTTP Queue Depth**",
        "",
        f"URL groups observed: {len(result_df):,}",
        "",
        format_table(result_df, max_rows=top_n),
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool: get_quic_connections
# ---------------------------------------------------------------------------


@mcp.tool()
def get_quic_connections(
    trace_id: str,
    top_n: int = 50,
    process_filter: str | None = None,
) -> str:
    """Per-MsQuic-connection summary: lifetime, packets, bytes, losses.

    For each ConnectionId, aggregates Created / Closed timestamps,
    PacketRecv / PacketSend counts and byte totals, and approximates
    packet loss by counting gaps in the received-PacketNumber sequence
    (max_pn - len(distinct_pns)). Sorted by total packets descending.

    Args:
        trace_id: ID returned by load_trace.
        top_n: Maximum rows to return. Default: 50.
        process_filter: Case-insensitive substring filter on Process Name
            (applied to the created/closed events).
    """
    trace = require_trace(trace_id)
    _ensure_dumper_ready(trace)

    created = trace.quic_conn_created_df
    closed = trace.quic_conn_closed_df
    recv = trace.quic_packet_recv_df
    send = trace.quic_packet_send_df

    have_any = any(
        _has_rows(df) for df in (created, closed, recv, send)
    )
    if not have_any:
        return _NO_QUIC_DATA_MSG

    # Build per-ConnectionId aggregator. Start from Created so we capture
    # peer / process context; fall back to a default row for connections
    # that only appear in PacketRecv/Send (e.g. trace started mid-flight).
    conns: dict[int, dict[str, Any]] = {}

    if _has_rows(created):
        for _, row in _apply_process_filter(created, process_filter).iterrows():
            cid = int(row.get("ConnectionId", 0) or 0)
            if not cid:
                continue
            rec = conns.setdefault(cid, {
                "ConnectionId": cid,
                "Process": row.get("Process Name", ""),
                "RemoteAddr": row.get("RemoteAddr", ""),
                "LocalAddr": row.get("LocalAddr", ""),
                "CID": row.get("CID", ""),
                "CreatedTs": int(row.get("TimeStamp", 0) or 0),
                "ClosedTs": 0,
                "RecvPackets": 0,
                "SendPackets": 0,
                "RecvBytes": 0,
                "SendBytes": 0,
                "RecvPns": set(),
            })

    if _has_rows(closed):
        for _, row in closed.iterrows():
            cid = int(row.get("ConnectionId", 0) or 0)
            if not cid or cid not in conns:
                continue
            conns[cid]["ClosedTs"] = int(row.get("TimeStamp", 0) or 0)

    # Only include connections matching the process filter, plus those
    # for which only packet events exist. Build the eligible set up front
    # from the (possibly filtered) Created list. When no filter is given
    # we don't restrict at all — packet-only connections still surface.
    eligible: set[int] | None = None
    if process_filter and _has_rows(created):
        eligible = set(conns.keys())

    if _has_rows(recv):
        for _, row in recv.iterrows():
            cid = int(row.get("ConnectionId", 0) or 0)
            if not cid:
                continue
            if eligible is not None and cid not in eligible:
                continue
            rec = conns.setdefault(cid, _make_default_conn_record(cid))
            rec["RecvPackets"] += 1
            rec["RecvBytes"] += int(row.get("Size", 0) or 0)
            pn = int(row.get("PacketNumber", 0) or 0)
            rec["RecvPns"].add(pn)

    if _has_rows(send):
        for _, row in send.iterrows():
            cid = int(row.get("ConnectionId", 0) or 0)
            if not cid:
                continue
            if eligible is not None and cid not in eligible:
                continue
            rec = conns.setdefault(cid, _make_default_conn_record(cid))
            rec["SendPackets"] += 1
            rec["SendBytes"] += int(row.get("Size", 0) or 0)

    if not conns:
        msg = "*No matching MsQuic connections"
        if process_filter:
            msg += f" for process filter `{process_filter}`"
        msg += ".*"
        return msg

    rows: list[dict[str, Any]] = []
    for cid, rec in conns.items():
        # Packet loss estimate: gap between max(packet_number) + 1 (the
        # expected count of distinct PNs if no loss) and the actual count.
        recv_pns = rec["RecvPns"]
        if recv_pns:
            max_pn = max(recv_pns)
            min_pn = min(recv_pns)
            expected = max_pn - min_pn + 1
            loss = max(0, expected - len(recv_pns))
        else:
            loss = 0

        lifetime_us = 0
        if rec["CreatedTs"] and rec["ClosedTs"] and rec["ClosedTs"] >= rec["CreatedTs"]:
            lifetime_us = rec["ClosedTs"] - rec["CreatedTs"]

        rows.append({
            "ConnectionId": cid,
            "Process": rec["Process"],
            "Peer": rec["RemoteAddr"],
            "Lifetime (us)": lifetime_us,
            "Recv Pkts": rec["RecvPackets"],
            "Send Pkts": rec["SendPackets"],
            "Recv Bytes": rec["RecvBytes"],
            "Send Bytes": rec["SendBytes"],
            "Lost Pkts": loss,
        })

    result_df = pd.DataFrame(rows).sort_values(
        ["Recv Pkts", "Send Pkts"], ascending=False
    ).reset_index(drop=True)

    lines = [
        "**MsQuic Connections**",
        "",
        f"Connections observed: {len(result_df):,}",
    ]
    if process_filter:
        lines.append(f"Process filter: `{process_filter}`")
    lines.append("")
    lines.append(format_table(result_df, max_rows=top_n))

    return "\n".join(lines)


def _make_default_conn_record(cid: int) -> dict[str, Any]:
    return {
        "ConnectionId": cid,
        "Process": "",
        "RemoteAddr": "",
        "LocalAddr": "",
        "CID": "",
        "CreatedTs": 0,
        "ClosedTs": 0,
        "RecvPackets": 0,
        "SendPackets": 0,
        "RecvBytes": 0,
        "SendBytes": 0,
        "RecvPns": set(),
    }


# ---------------------------------------------------------------------------
# Tool: get_quic_cid_distribution
# ---------------------------------------------------------------------------


@mcp.tool()
def get_quic_cid_distribution(trace_id: str, top_n: int = 30) -> str:
    """CID-hash bucket distribution across CPUs (cpuredirect validation).

    For each QUIC connection's CID, computes a hash (currently FNV-1a 32-bit
    over the CID bytes — see ``_fnv1a_hash`` docstring for production
    fidelity caveats) and observes the set of CPUs that processed
    PacketRecv events for that connection. Output per CID-hash bucket
    (hash modulo CPU count): number of distinct connections, number of
    distinct CPUs they actually landed on, and a quick "spread" ratio
    (actual_cpus / 1 since a well-steered bucket should land on a single
    CPU). Connections without a CID (e.g. trace started mid-flow) are
    grouped under bucket -1.

    The CPU count is taken from the maximum CPU observed in
    ``quic_packet_recv_df``. With CPUMAP / cpuredirect on, every
    connection in a single hash bucket should pin to one CPU; a bucket
    showing many CPUs means the steering is not working or many distinct
    connections happen to share that bucket.

    Args:
        trace_id: ID returned by load_trace.
        top_n: Maximum rows to return. Default: 30.
    """
    trace = require_trace(trace_id)
    _ensure_dumper_ready(trace)

    created = trace.quic_conn_created_df
    recv = trace.quic_packet_recv_df

    if not _has_rows(created) and not _has_rows(recv):
        return _NO_QUIC_DATA_MSG

    # Build ConnectionId -> CID map. Only Created events carry the CID.
    cid_by_conn: dict[int, str] = {}
    if _has_rows(created):
        for _, row in created.iterrows():
            conn = int(row.get("ConnectionId", 0) or 0)
            cid = str(row.get("CID", ""))
            if conn and cid and conn not in cid_by_conn:
                cid_by_conn[conn] = cid

    # Build ConnectionId -> set(CPU) from PacketRecv events.
    cpus_by_conn: dict[int, set[int]] = {}
    cpu_max = 0
    if _has_rows(recv):
        for _, row in recv.iterrows():
            conn = int(row.get("ConnectionId", 0) or 0)
            cpu = int(row.get("CPU", -1))
            if conn and cpu >= 0:
                cpus_by_conn.setdefault(conn, set()).add(cpu)
                if cpu > cpu_max:
                    cpu_max = cpu

    cpu_count = cpu_max + 1 if cpu_max > 0 else 1

    # Bucket connections by hash(CID) mod cpu_count.
    bucket_to_conns: dict[int, list[int]] = {}
    for conn in set(list(cid_by_conn.keys()) + list(cpus_by_conn.keys())):
        cid = cid_by_conn.get(conn, "")
        if not cid:
            bucket = -1
        else:
            bucket = _fnv1a_hash(_cid_to_bytes(cid)) % cpu_count
        bucket_to_conns.setdefault(bucket, []).append(conn)

    if not bucket_to_conns:
        return _NO_QUIC_DATA_MSG

    rows: list[dict[str, Any]] = []
    for bucket, conn_list in bucket_to_conns.items():
        cpus_observed: set[int] = set()
        for conn in conn_list:
            cpus_observed.update(cpus_by_conn.get(conn, set()))
        rows.append({
            "Bucket": bucket,
            "Expected CPU": bucket if bucket >= 0 else "n/a",
            "Connections": len(conn_list),
            "Actual CPUs": len(cpus_observed),
            "CPU List": ",".join(str(c) for c in sorted(cpus_observed)) if cpus_observed else "",
        })

    result_df = pd.DataFrame(rows).sort_values(
        "Connections", ascending=False
    ).reset_index(drop=True)

    lines = [
        "**MsQuic CID Distribution**",
        "",
        f"CPU count (derived from PacketRecv): {cpu_count}",
        f"Hash function: FNV-1a 32-bit over CID hex bytes (placeholder — see source).",
        "",
        format_table(result_df, max_rows=top_n),
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool: get_quic_ack_delays
# ---------------------------------------------------------------------------


@mcp.tool()
def get_quic_ack_delays(
    trace_id: str,
    top_n: int = 30,
    process_filter: str | None = None,
) -> str:
    """Per-connection AckDelay percentiles (p50/p99/p999).

    Computes AckDelay (in microseconds) percentiles from
    ``quic_ack_recv_df.AckDelay`` per ConnectionId. Connections with
    p99 >= 25 ms are flagged in the summary as exhibiting poor delayed-ACK
    behavior (the TCP-spec-derived smoke-test threshold).

    Args:
        trace_id: ID returned by load_trace.
        top_n: Maximum rows to return. Default: 30.
        process_filter: Case-insensitive substring filter on Process Name
            via the ConnectionCreated record. When provided, only
            connections originating from a matching process are reported.
    """
    trace = require_trace(trace_id)
    _ensure_dumper_ready(trace)

    ack = trace.quic_ack_recv_df
    if not _has_rows(ack):
        return _NO_QUIC_DATA_MSG

    # Resolve Process Name per connection via Created records (optional).
    process_by_conn: dict[int, str] = {}
    if process_filter and _has_rows(trace.quic_conn_created_df):
        for _, row in trace.quic_conn_created_df.iterrows():
            conn = int(row.get("ConnectionId", 0) or 0)
            if conn:
                process_by_conn[conn] = str(row.get("Process Name", ""))

    # Group AckDelay by ConnectionId.
    groups: dict[int, list[int]] = {}
    for _, row in ack.iterrows():
        conn = int(row.get("ConnectionId", 0) or 0)
        if not conn:
            continue
        if process_filter:
            proc = process_by_conn.get(conn, "")
            if process_filter.lower() not in proc.lower():
                continue
        try:
            delay = int(row.get("AckDelay", 0) or 0)
        except (TypeError, ValueError):
            continue
        groups.setdefault(conn, []).append(delay)

    if not groups:
        msg = "*No MsQuic AckReceived events"
        if process_filter:
            msg += f" for process filter `{process_filter}`"
        msg += ".*"
        return msg

    rows: list[dict[str, Any]] = []
    flagged_count = 0
    for conn, delays in groups.items():
        s = pd.Series(delays, dtype="float64")
        p99 = float(s.quantile(0.99))
        flagged = p99 >= _ACK_DELAY_FLAG_THRESHOLD_US
        if flagged:
            flagged_count += 1
        rows.append({
            "ConnectionId": conn,
            "Process": process_by_conn.get(conn, ""),
            "Acks": len(delays),
            "p50 (us)": round(float(s.quantile(0.50)), 1),
            "p99 (us)": round(p99, 1),
            "p999 (us)": round(float(s.quantile(0.999)), 1),
            "Flag": "HIGH" if flagged else "",
        })

    result_df = pd.DataFrame(rows).sort_values(
        "p99 (us)", ascending=False
    ).reset_index(drop=True)

    lines = [
        "**MsQuic Ack Delays**",
        "",
        f"Connections with Ack data: {len(result_df):,}",
    ]
    if flagged_count:
        lines.append(
            f"**HIGH ACK DELAY:** {flagged_count} connection(s) with "
            f"p99 >= {_ACK_DELAY_FLAG_THRESHOLD_US // 1000} ms."
        )
    else:
        lines.append(
            f"All connections under p99 = {_ACK_DELAY_FLAG_THRESHOLD_US // 1000} ms."
        )
    if process_filter:
        lines.append(f"Process filter: `{process_filter}`")
    lines.append("")
    lines.append(format_table(result_df, max_rows=top_n))

    return "\n".join(lines)


__all__ = [
    "get_http_requests",
    "get_http_queue_depth",
    "get_quic_connections",
    "get_quic_cid_distribution",
    "get_quic_ack_delays",
]
