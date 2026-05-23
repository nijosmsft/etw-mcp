"""Phase 5 application-layer tools (HTTP.sys + MsQuic).

Tools over the HTTP.sys and MsQuic event DataFrames populated by xperf or
native extraction, with lazy native event-store scans when full-detail
streaming captured app-layer chunks.

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
first, markdown-string return, no emojis. Each tool waits for any
background dumper extraction before reading, prefers existing materialized
DataFrames, then falls back to bounded event-store scans. If an exact
lifecycle join or percentile would exceed the bounded in-memory limit, the
tool declines with guidance instead of approximating silently.
"""

from __future__ import annotations

import math
from typing import Any

import pandas as pd

from etw_analyzer.app import mcp
from etw_analyzer.formatting.markdown import format_table
from etw_analyzer.native.accessors import iter_event_batches
from etw_analyzer.trace_state import TraceData, require_trace


_NO_HTTP_DATA_MSG = (
    "*No HTTP.sys event data in this trace.*\n\n"
    "Re-collect with `udp-perf/scripts/networking.wprp` — the "
    "`Microsoft-Windows-HttpService` provider must be enabled to record "
    "the HTTP.sys request lifecycle. Standard `xdptrace.wprp` traces do "
    "not include HttpService events. Native event-store caches include "
    "these app-layer classes only with "
    "`WPR_MCP_NATIVE_STREAMING_PROFILE=all`; the default `summary` profile "
    "intentionally skips them."
)

_NO_QUIC_DATA_MSG = (
    "*No MsQuic event data in this trace.*\n\n"
    "Re-collect with `udp-perf/scripts/networking.wprp` — the "
    "`Microsoft-Quic` provider must be enabled to record QUIC connection "
    "state. Standard `xdptrace.wprp` traces do not include MsQuic events. "
    "Native event-store caches include these app-layer classes only with "
    "`WPR_MCP_NATIVE_STREAMING_PROFILE=all`; the default `summary` profile "
    "intentionally skips them."
)


# Connections with p99 AckDelay above this value (microseconds) are
# flagged as poor delayed-ACK behavior. 25 ms aligns with the upper bound
# the TCP RFC suggests for the comparable mechanism — QUIC operators use
# the same number as a smoke-test signal.
_ACK_DELAY_FLAG_THRESHOLD_US = 25_000

_APP_EVENT_ROW_LIMIT = 500_000
_APP_EXACT_VALUE_LIMIT = 500_000
_APP_BATCH_SIZE = 65_536


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _ensure_dumper_ready(trace: TraceData) -> None:
    trace.wait_for_dumper()


class _ExactLimitExceeded(ValueError):
    def __init__(self, label: str, limit: int, unit: str) -> None:
        super().__init__(
            f"{label} exceeded the exact {unit} limit of {limit:,}"
        )
        self.label = label
        self.limit = limit
        self.unit = unit


def _analysis_too_large(title: str, exc: _ExactLimitExceeded) -> str:
    return (
        f"**{title}**\n\n"
        f"*Exact app-layer analysis declined: {exc}. Narrow the trace, "
        "use a shorter capture, or add a more selective filter before "
        "rerunning. No approximate summary was produced.*"
    )


def _iter_limited_records(
    trace: TraceData,
    event_class: str,
    *,
    columns: list[str] | None = None,
    limit: int = _APP_EVENT_ROW_LIMIT,
):
    seen = 0
    for batch in iter_event_batches(
        trace,
        event_class,
        columns=columns,
        batch_size=_APP_BATCH_SIZE,
    ):
        if batch.empty:
            continue
        seen += len(batch)
        if seen > limit:
            raise _ExactLimitExceeded(event_class, limit, "row")
        for row in batch.to_dict("records"):
            yield row


def _event_has_rows(
    trace: TraceData,
    event_class: str,
    *,
    columns: list[str] | None = None,
) -> bool:
    for batch in iter_event_batches(
        trace,
        event_class,
        columns=columns,
        batch_size=1,
    ):
        if not batch.empty:
            return True
    return False


def _to_int(value: Any, default: Any = 0) -> Any:
    if value is None:
        return default
    try:
        if pd.isna(value):
            return default
    except (TypeError, ValueError):
        pass
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


def _to_str(value: Any) -> str:
    if value is None:
        return ""
    try:
        if pd.isna(value):
            return ""
    except (TypeError, ValueError):
        pass
    return str(value)


def _event_time_us(row: dict[str, Any]) -> int:
    timestamp = _to_int(row.get("TimeStamp"), None)
    if timestamp is not None:
        return timestamp
    return _to_int(row.get("TimeStampQpc"))


def _matches_filter(value: Any, text_filter: str | None) -> bool:
    if not text_filter:
        return True
    return text_filter.lower() in _to_str(value).lower()


def _record_process_matches(row: dict[str, Any], process_filter: str | None) -> bool:
    return _matches_filter(row.get("Process Name", ""), process_filter)


def _check_exact_value_limit(count: int, label: str) -> None:
    if count > _APP_EXACT_VALUE_LIMIT:
        raise _ExactLimitExceeded(label, _APP_EXACT_VALUE_LIMIT, "value")


def _exact_percentile(values: list[int], q: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    rank = max(1, math.ceil(float(q) * len(ordered)))
    return int(ordered[min(rank - 1, len(ordered) - 1)])


def _format_exact_percentile_line(label: str, values: list[int]) -> str:
    return (
        f"{label} exact p50/p95/p99/max (us): "
        f"{_exact_percentile(values, 0.50):,} / "
        f"{_exact_percentile(values, 0.95):,} / "
        f"{_exact_percentile(values, 0.99):,} / "
        f"{max(values):,}"
    )


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
    events by ``RequestId``, optionally enriches with ``Deliver`` and
    ``Close``. Output is sorted by total latency (recv -> send)
    descending. Summary percentiles are exact nearest-rank over bounded
    materialized or event-store rows; huge traces are declined instead of
    approximated silently.

    Args:
        trace_id: ID returned by load_trace.
        top_n: Maximum rows to return. Default: 100.
        url_filter: Case-insensitive substring filter on Url.
    """
    trace = require_trace(trace_id)
    _ensure_dumper_ready(trace)

    try:
        # Pre-index Send / Deliver / Close by RequestId for fast exact joins.
        # If multiple Send rows share a RequestId (for example chunked
        # responses), use the earliest Send as the response-completion point.
        send_by_rid: dict[int, dict[str, Any]] = {}
        for row in _iter_limited_records(
            trace,
            "http_send",
            columns=[
                "RequestId", "TimeStamp", "TimeStampQpc",
                "StatusCode", "ContentLength",
            ],
        ):
            rid = _to_int(row.get("RequestId"))
            if not rid:
                continue
            ts = _event_time_us(row)
            current = send_by_rid.get(rid)
            if current is None or ts < current["TimeStamp"]:
                send_by_rid[rid] = {
                    "TimeStamp": ts,
                    "StatusCode": _to_int(row.get("StatusCode")),
                    "ContentLength": _to_int(row.get("ContentLength")),
                }

        deliver_by_rid: dict[int, int] = {}
        for row in _iter_limited_records(
            trace,
            "http_deliver",
            columns=["RequestId", "TimeStamp", "TimeStampQpc"],
        ):
            rid = _to_int(row.get("RequestId"))
            if not rid:
                continue
            ts = _event_time_us(row)
            if rid not in deliver_by_rid or ts < deliver_by_rid[rid]:
                deliver_by_rid[rid] = ts

        close_by_rid: dict[int, int] = {}
        for row in _iter_limited_records(
            trace,
            "http_close",
            columns=["RequestId", "TimeStamp", "TimeStampQpc"],
        ):
            rid = _to_int(row.get("RequestId"))
            if not rid:
                continue
            ts = _event_time_us(row)
            if rid not in close_by_rid or ts < close_by_rid[rid]:
                close_by_rid[rid] = ts

        rows: list[dict[str, Any]] = []
        recv_seen = 0
        recv_matched_filter = 0
        recv_to_send_latencies: list[int] = []
        deliver_to_send_latencies: list[int] = []

        for row in _iter_limited_records(
            trace,
            "http_recv",
            columns=[
                "RequestId", "ConnectionId", "TimeStamp", "TimeStampQpc",
                "Verb", "Url", "Process Name", "PID", "ThreadID", "CPU",
            ],
        ):
            recv_seen += 1
            if not _matches_filter(row.get("Url", ""), url_filter):
                continue
            recv_matched_filter += 1
            rid = _to_int(row.get("RequestId"))
            if not rid:
                continue
            recv_ts = _event_time_us(row)
            verb = _to_str(row.get("Verb"))
            url = _to_str(row.get("Url"))

            send_info = send_by_rid.get(rid)
            send_ts = send_info["TimeStamp"] if send_info else 0
            status = send_info["StatusCode"] if send_info else 0
            recv_to_send_us = (
                send_ts - recv_ts
                if send_info and send_ts >= recv_ts
                else 0
            )
            if send_info:
                recv_to_send_latencies.append(recv_to_send_us)
                _check_exact_value_limit(
                    len(recv_to_send_latencies),
                    "HTTP Recv->Send latencies",
                )

            deliver_ts = deliver_by_rid.get(rid, 0)
            deliver_to_send_us = (
                send_ts - deliver_ts
                if deliver_ts and send_info and send_ts >= deliver_ts
                else 0
            )
            if deliver_ts and send_info:
                deliver_to_send_latencies.append(deliver_to_send_us)
                _check_exact_value_limit(
                    len(deliver_to_send_latencies),
                    "HTTP Deliver->Send latencies",
                )

            close_ts = close_by_rid.get(rid, 0)
            recv_to_close_us = (
                close_ts - recv_ts
                if close_ts and close_ts >= recv_ts
                else 0
            )

            rows.append({
                "RequestId": rid,
                "Verb": verb,
                "Url": url,
                "Status": status if status else "",
                "Recv->Send (us)": recv_to_send_us if send_info else "",
                "Deliver->Send (us)": deliver_to_send_us if deliver_ts and send_info else "",
                "Recv->Close (us)": recv_to_close_us if close_ts else "",
                "ContentLength": send_info["ContentLength"] if send_info else "",
                "_sort": recv_to_send_us or recv_to_close_us,
            })
    except _ExactLimitExceeded as exc:
        return _analysis_too_large("HTTP Requests", exc)

    if not rows:
        if recv_seen == 0:
            return _NO_HTTP_DATA_MSG
        if url_filter and recv_matched_filter == 0:
            return f"*No HTTP requests match URL filter `{url_filter}`.*"
        return "*No HTTP request records reconstructed (RequestId join produced no rows).*"

    result_df = pd.DataFrame(rows).sort_values(
        "_sort", ascending=False
    ).reset_index(drop=True)
    result_df = result_df.drop(columns=["_sort"])

    in_flight = int(
        sum(1 for r in rows if not r["Status"] and not r["Recv->Close (us)"])
    )

    lines = [
        "**HTTP Requests**",
        "",
        f"Requests observed: {len(result_df):,}",
    ]
    if recv_to_send_latencies:
        lines.append(f"Responses completed: {len(recv_to_send_latencies):,}")
        lines.append(
            _format_exact_percentile_line("Recv->Send", recv_to_send_latencies)
        )
    if deliver_to_send_latencies:
        lines.append(
            _format_exact_percentile_line(
                "Deliver->Send", deliver_to_send_latencies
            )
        )
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

    Computes concurrent in-flight requests per UrlGroupId by walking
    the Recv -> Deliver -> Send -> Close events ordered by timestamp.
    For each event we adjust a running counter (+1 on Deliver, -1 on
    Send or Close) and track the maximum, time-weighted mean, and exact
    nearest-rank completion latency percentiles. Requests without a Deliver
    event are excluded because they cannot be attributed to a URL group.

    Args:
        trace_id: ID returned by load_trace.
        top_n: Maximum rows to return. Default: 20.
    """
    trace = require_trace(trace_id)
    _ensure_dumper_ready(trace)

    try:
        # Map RequestId -> UrlGroupId via the Deliver event. Deliver is the
        # queue entry point for per-URL-group depth accounting.
        rid_to_urlgroup: dict[int, int] = {}
        deliver_ts_by_rid: dict[int, int] = {}
        events: list[tuple[int, int, int]] = []  # (ts, url_group, delta)
        deliver_seen = 0

        for row in _iter_limited_records(
            trace,
            "http_deliver",
            columns=["RequestId", "UrlGroupId", "TimeStamp", "TimeStampQpc"],
        ):
            rid = _to_int(row.get("RequestId"))
            ug = _to_int(row.get("UrlGroupId"))
            ts = _event_time_us(row)
            if not rid:
                continue
            deliver_seen += 1
            rid_to_urlgroup[rid] = ug
            deliver_ts_by_rid[rid] = ts
            if ug:
                events.append((ts, ug, +1))

        if deliver_seen == 0:
            if not _event_has_rows(trace, "http_recv", columns=["RequestId"]):
                return _NO_HTTP_DATA_MSG
            return (
                "**HTTP Queue Depth**\n\n"
                "*No HttpService/Deliver events in this trace — cannot attribute "
                "requests to URL groups.*"
            )

        completion_by_rid: dict[int, tuple[int, str]] = {}
        for row in _iter_limited_records(
            trace,
            "http_send",
            columns=["RequestId", "TimeStamp", "TimeStampQpc"],
        ):
            rid = _to_int(row.get("RequestId"))
            if not rid:
                continue
            ts = _event_time_us(row)
            current = completion_by_rid.get(rid)
            if current is None or ts < current[0]:
                completion_by_rid[rid] = (ts, "send")

        # Use Send when available; fall back to Close if no Send (rare).
        for row in _iter_limited_records(
            trace,
            "http_close",
            columns=["RequestId", "TimeStamp", "TimeStampQpc"],
        ):
            rid = _to_int(row.get("RequestId"))
            if not rid or rid in completion_by_rid:
                continue
            completion_by_rid[rid] = (_event_time_us(row), "close")

        latencies_by_group: dict[int, list[int]] = {}
        latency_count = 0
        for rid, (ts, _kind) in completion_by_rid.items():
            ug = rid_to_urlgroup.get(rid, 0)
            if ug == 0:
                continue
            events.append((ts, ug, -1))
            deliver_ts = deliver_ts_by_rid.get(rid)
            if deliver_ts is not None and ts >= deliver_ts:
                latencies_by_group.setdefault(ug, []).append(ts - deliver_ts)
                latency_count += 1
                _check_exact_value_limit(
                    latency_count,
                    "HTTP queue completion latencies",
                )
    except _ExactLimitExceeded as exc:
        return _analysis_too_large("HTTP Queue Depth", exc)

    # Sort by timestamp and walk per URL group.
    events.sort(key=lambda e: (e[0], -e[2]))
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
        latencies = latencies_by_group.get(ug, [])

        rows.append({
            "UrlGroupId": ug,
            "Peak Depth": rec["peak"],
            "Avg Depth": round(avg_depth, 2),
            "Deliveries": rec["deliveries"],
            "Completions": rec["completions"],
            "Latency p50 (us)": _exact_percentile(latencies, 0.50) if latencies else "",
            "Latency p99 (us)": _exact_percentile(latencies, 0.99) if latencies else "",
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
    PacketRecv / PacketSend counts and byte totals, and estimates packet
    loss exactly from gaps in the distinct received-PacketNumber sequence.
    Sorted by total packets descending; huge packet-number sets are
    declined instead of approximated silently.

    Args:
        trace_id: ID returned by load_trace.
        top_n: Maximum rows to return. Default: 50.
        process_filter: Case-insensitive substring filter on Process Name
            (applied to the created/closed events).
    """
    trace = require_trace(trace_id)
    _ensure_dumper_ready(trace)

    try:
        # Build per-ConnectionId aggregators. Start from Created so we
        # capture peer / process context; fall back to a default row for
        # connections that only appear in PacketRecv/Send when no process
        # filter is active.
        conns: dict[int, dict[str, Any]] = {}
        have_any = False

        for row in _iter_limited_records(
            trace,
            "quic_conn_created",
            columns=[
                "ConnectionId", "TimeStamp", "TimeStampQpc",
                "Process Name", "CID", "LocalAddr", "RemoteAddr",
            ],
        ):
            have_any = True
            if not _record_process_matches(row, process_filter):
                continue
            cid = _to_int(row.get("ConnectionId"))
            if not cid:
                continue
            rec = conns.setdefault(cid, _make_default_conn_record(cid))
            rec.update({
                "Process": _to_str(row.get("Process Name")),
                "RemoteAddr": _to_str(row.get("RemoteAddr")),
                "LocalAddr": _to_str(row.get("LocalAddr")),
                "CID": _to_str(row.get("CID")),
                "CreatedTs": _event_time_us(row),
            })

        eligible: set[int] | None = set(conns.keys()) if process_filter else None

        for row in _iter_limited_records(
            trace,
            "quic_conn_closed",
            columns=["ConnectionId", "TimeStamp", "TimeStampQpc", "Process Name"],
        ):
            have_any = True
            cid = _to_int(row.get("ConnectionId"))
            if not cid:
                continue
            if eligible is not None and cid not in eligible:
                continue
            rec = conns.setdefault(cid, _make_default_conn_record(cid))
            rec["ClosedTs"] = _event_time_us(row)
            if not rec["Process"]:
                rec["Process"] = _to_str(row.get("Process Name"))

        pn_value_count = 0
        for row in _iter_limited_records(
            trace,
            "quic_packet_recv",
            columns=["ConnectionId", "PacketNumber", "Size", "CPU"],
        ):
            have_any = True
            cid = _to_int(row.get("ConnectionId"))
            if not cid:
                continue
            if eligible is not None and cid not in eligible:
                continue
            rec = conns.setdefault(cid, _make_default_conn_record(cid))
            rec["RecvPackets"] += 1
            rec["RecvBytes"] += _to_int(row.get("Size"))
            pn = _to_int(row.get("PacketNumber"), None)
            if pn is not None and pn not in rec["RecvPns"]:
                rec["RecvPns"].add(pn)
                pn_value_count += 1
                _check_exact_value_limit(
                    pn_value_count,
                    "QUIC received packet-number set",
                )

        for row in _iter_limited_records(
            trace,
            "quic_packet_send",
            columns=["ConnectionId", "PacketNumber", "Size"],
        ):
            have_any = True
            cid = _to_int(row.get("ConnectionId"))
            if not cid:
                continue
            if eligible is not None and cid not in eligible:
                continue
            rec = conns.setdefault(cid, _make_default_conn_record(cid))
            rec["SendPackets"] += 1
            rec["SendBytes"] += _to_int(row.get("Size"))
    except _ExactLimitExceeded as exc:
        return _analysis_too_large("MsQuic Connections", exc)

    if not have_any:
        return _NO_QUIC_DATA_MSG

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
            "CID": rec["CID"],
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

    The CPU count is taken from the maximum CPU observed in PacketRecv
    events. With CPUMAP / cpuredirect on, every
    connection in a single hash bucket should pin to one CPU; a bucket
    showing many CPUs means the steering is not working or many distinct
    connections happen to share that bucket.

    Args:
        trace_id: ID returned by load_trace.
        top_n: Maximum rows to return. Default: 30.
    """
    trace = require_trace(trace_id)
    _ensure_dumper_ready(trace)

    try:
        have_any = False

        # Build ConnectionId -> CID map. Only Created events carry the CID.
        cid_by_conn: dict[int, str] = {}
        for row in _iter_limited_records(
            trace,
            "quic_conn_created",
            columns=["ConnectionId", "CID"],
        ):
            have_any = True
            conn = _to_int(row.get("ConnectionId"))
            cid = _to_str(row.get("CID"))
            if conn and cid and conn not in cid_by_conn:
                cid_by_conn[conn] = cid

        # Build ConnectionId -> set(CPU) from PacketRecv events.
        cpus_by_conn: dict[int, set[int]] = {}
        cpu_max = 0
        for row in _iter_limited_records(
            trace,
            "quic_packet_recv",
            columns=["ConnectionId", "CPU"],
        ):
            have_any = True
            conn = _to_int(row.get("ConnectionId"))
            cpu = _to_int(row.get("CPU"), -1)
            if conn and cpu >= 0:
                cpus_by_conn.setdefault(conn, set()).add(cpu)
                if cpu > cpu_max:
                    cpu_max = cpu
    except _ExactLimitExceeded as exc:
        return _analysis_too_large("MsQuic CID Distribution", exc)

    if not have_any:
        return _NO_QUIC_DATA_MSG

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

    Computes exact nearest-rank AckDelay (in microseconds) percentiles
    from materialized or event-store AckReceived rows per ConnectionId.
    Connections with p99 >= 25 ms are flagged in the summary as exhibiting
    poor delayed-ACK behavior (the TCP-spec-derived smoke-test threshold).
    Huge AckDelay groups are declined instead of approximated silently.

    Args:
        trace_id: ID returned by load_trace.
        top_n: Maximum rows to return. Default: 30.
        process_filter: Case-insensitive substring filter on Process Name
            via the ConnectionCreated record. When provided, only
            connections originating from a matching process are reported.
    """
    trace = require_trace(trace_id)
    _ensure_dumper_ready(trace)

    try:
        # Resolve Process Name per connection via Created records. This is
        # optional for display, but required when process_filter is provided.
        process_by_conn: dict[int, str] = {}
        have_quic_lifecycle = False
        for row in _iter_limited_records(
            trace,
            "quic_conn_created",
            columns=["ConnectionId", "Process Name"],
        ):
            have_quic_lifecycle = True
            conn = _to_int(row.get("ConnectionId"))
            if conn:
                process_by_conn[conn] = _to_str(row.get("Process Name"))

        # Group AckDelay by ConnectionId. Values are kept exactly and
        # percentiles below use nearest-rank over the sorted observations.
        groups: dict[int, list[int]] = {}
        ack_seen = False
        ack_value_count = 0
        for row in _iter_limited_records(
            trace,
            "quic_ack_recv",
            columns=["ConnectionId", "AckDelay", "LargestAcknowledged"],
        ):
            ack_seen = True
            conn = _to_int(row.get("ConnectionId"))
            if not conn:
                continue
            if process_filter:
                proc = process_by_conn.get(conn, "")
                if process_filter.lower() not in proc.lower():
                    continue
            delay = _to_int(row.get("AckDelay"), None)
            if delay is None:
                continue
            groups.setdefault(conn, []).append(delay)
            ack_value_count += 1
            _check_exact_value_limit(
                ack_value_count,
                "QUIC AckDelay observations",
            )
    except _ExactLimitExceeded as exc:
        return _analysis_too_large("MsQuic Ack Delays", exc)

    if not ack_seen:
        if have_quic_lifecycle:
            return "*No MsQuic AckReceived events in this trace.*"
        return _NO_QUIC_DATA_MSG

    if not groups:
        msg = "*No MsQuic AckReceived events"
        if process_filter:
            msg += f" for process filter `{process_filter}`"
        msg += ".*"
        return msg

    rows: list[dict[str, Any]] = []
    flagged_count = 0
    for conn, delays in groups.items():
        p50 = _exact_percentile(delays, 0.50)
        p99 = _exact_percentile(delays, 0.99)
        p999 = _exact_percentile(delays, 0.999)
        flagged = p99 >= _ACK_DELAY_FLAG_THRESHOLD_US
        if flagged:
            flagged_count += 1
        rows.append({
            "ConnectionId": conn,
            "Process": process_by_conn.get(conn, ""),
            "Acks": len(delays),
            "p50 (us)": p50,
            "p99 (us)": p99,
            "p999 (us)": p999,
            "Flag": "HIGH" if flagged else "",
        })

    result_df = pd.DataFrame(rows).sort_values(
        "p99 (us)", ascending=False
    ).reset_index(drop=True)

    lines = [
        "**MsQuic Ack Delays**",
        "",
        f"Connections with Ack data: {len(result_df):,}",
        "Percentiles: exact nearest-rank over observed AckDelay values.",
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
