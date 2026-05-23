"""Phase 4 packet-capture tools.

Tools over the ``packet_capture_df`` populated by the background dumper
extraction (see :func:`etw_analyzer.tools.trace_mgmt._start_background_dumper`
and :func:`etw_analyzer.parsing.wpa_exporter._handle_ndis_packet_capture`).

Each row in ``packet_capture_df`` carries a hex string of the captured
frame bytes; layer-by-layer decode is done lazily here via
:func:`etw_analyzer.parsing.packet_decode.decode_packet_headers` so we
never pay the decode cost for traces that just want the trace_id stored.

All four tools follow the project conventions: ``@mcp.tool()``,
``trace_id`` first, markdown-string return. When the trace was collected
without ``Microsoft-Windows-NDIS-PacketCapture`` enabled (the common case
for ``xdptrace.wprp`` traces), the tools return a friendly explanation
pointing at ``udp-perf/scripts/networking.wprp``.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterator
import heapq
from typing import Any

import pandas as pd

from etw_analyzer.app import mcp
from etw_analyzer.formatting.markdown import format_table
from etw_analyzer.native.accessors import has_trace_event_dataset, iter_event_batches
from etw_analyzer.parsing.packet_decode import decode_packet_headers
from etw_analyzer.trace_state import TraceData, require_trace


_NO_PACKET_CAPTURE_MSG = (
    "*No packet-capture data in this trace.*\n\n"
    "Re-collect with `udp-perf/scripts/networking.wprp` — the "
    "`Microsoft-Windows-NDIS-PacketCapture` provider must be enabled to "
    "record frame bytes. Standard `xdptrace.wprp` traces do not include "
    "packet captures."
)

_PACKET_BATCH_SIZE = 65_536
_PACKET_COLUMNS = [
    "TimeStamp",
    "Direction",
    "MiniportName",
    "PacketBytes",
    "Size",
    "Process Name",
    "PID",
    "ThreadID",
    "CPU",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ensure_dumper_ready(trace: TraceData) -> None:
    trace.wait_for_dumper()


def _decode_row(packet_hex: str) -> dict[str, Any]:
    """Decode the PacketBytes hex string for one row, swallowing errors.

    Returns ``{}`` for unparseable rows so the caller can filter them out
    cleanly. A malformed hex blob in a real-world trace shouldn't take
    down a whole report.
    """
    if not isinstance(packet_hex, str) or not packet_hex:
        return {}
    try:
        return decode_packet_headers(bytes.fromhex(packet_hex))
    except (ValueError, TypeError):
        return {}


def _packet_capture_ready(df: pd.DataFrame | None) -> bool:
    """True if ``df`` looks usable (non-empty, has PacketBytes column)."""
    if df is None or df.empty:
        return False
    return "PacketBytes" in df.columns


def _project_packet_columns(
    df: pd.DataFrame,
    columns: list[str] | None,
) -> pd.DataFrame:
    if columns is None:
        return df.reset_index(drop=True)
    keep = [column for column in columns if column in df.columns]
    if "TimeStamp" in df.columns and "TimeStamp" not in keep:
        keep.append("TimeStamp")
    return df[keep].reset_index(drop=True)


def _packet_capture_batches(
    trace: TraceData,
    *,
    columns: list[str] | None = None,
    batch_size: int = _PACKET_BATCH_SIZE,
    sort_by_time: bool = False,
) -> Iterator[pd.DataFrame]:
    """Yield packet-capture rows without forcing event-store materialization."""

    materialized = trace.packet_capture_df
    if isinstance(materialized, pd.DataFrame):
        df = _project_packet_columns(materialized, columns)
        if sort_by_time and "TimeStamp" in df.columns and not df.empty:
            ts = pd.to_numeric(df["TimeStamp"], errors="coerce")
            df = df.assign(_sort_ts=ts).sort_values("_sort_ts").drop(columns=["_sort_ts"])
        safe_batch_size = max(1, int(batch_size or _PACKET_BATCH_SIZE))
        for start in range(0, len(df), safe_batch_size):
            yield df.iloc[start:start + safe_batch_size].reset_index(drop=True)
        return

    for batch in iter_event_batches(
        trace,
        "packet_capture",
        columns=columns,
        batch_size=batch_size,
    ):
        if sort_by_time and "TimeStamp" in batch.columns and not batch.empty:
            ts = pd.to_numeric(batch["TimeStamp"], errors="coerce")
            batch = batch.assign(_sort_ts=ts).sort_values("_sort_ts").drop(columns=["_sort_ts"])
        yield batch.reset_index(drop=True)


def _packet_capture_available(trace: TraceData) -> bool:
    materialized = trace.packet_capture_df
    if isinstance(materialized, pd.DataFrame):
        return _packet_capture_ready(materialized)
    return has_trace_event_dataset(trace, "packet_capture")


def _apply_process_filter(df: pd.DataFrame, process_filter: str | None) -> pd.DataFrame:
    """Case-insensitive substring filter on Process Name."""
    if not process_filter or df.empty or "Process Name" not in df.columns:
        return df
    mask = df["Process Name"].astype(str).str.contains(
        process_filter, case=False, na=False
    )
    return df[mask]


def _decoded_with_five_tuple(df: pd.DataFrame) -> pd.DataFrame:
    """Return a copy of ``df`` augmented with decoded header columns.

    Adds: ``_src``, ``_dst``, ``_src_port``, ``_dst_port``, ``_proto`` (as a
    short string: tcp / udp / icmp / icmpv6 / proto-N / other) and
    ``_five_tuple`` (canonical "src:port -> dst:port/proto"). Rows whose
    packet bytes don't decode to at least an IP layer get blank tuple
    fields and the literal string ``"undecoded"`` for ``_five_tuple`` so
    summaries still surface them.
    """
    out = df.copy()
    srcs: list[str] = []
    dsts: list[str] = []
    sports: list[int] = []
    dports: list[int] = []
    protos: list[str] = []
    tuples: list[str] = []

    for _, row in out.iterrows():
        decoded = _decode_row(row.get("PacketBytes", ""))
        src, dst, sport, dport, proto, five = _decoded_tuple_fields(decoded)

        srcs.append(src)
        dsts.append(dst)
        sports.append(sport)
        dports.append(dport)
        protos.append(proto)
        tuples.append(five)

    out["_src"] = srcs
    out["_dst"] = dsts
    out["_src_port"] = sports
    out["_dst_port"] = dports
    out["_proto"] = protos
    out["_five_tuple"] = tuples
    return out


def _decoded_tuple_fields(decoded: dict[str, Any]) -> tuple[str, str, int, int, str, str]:
    src = decoded.get("ip.src", "")
    dst = decoded.get("ip.dst", "")
    proto_num = decoded.get("ip.proto")
    if proto_num == 6:
        proto = "tcp"
        sport = int(decoded.get("tcp.src_port", 0))
        dport = int(decoded.get("tcp.dst_port", 0))
    elif proto_num == 17:
        proto = "udp"
        sport = int(decoded.get("udp.src_port", 0))
        dport = int(decoded.get("udp.dst_port", 0))
    elif proto_num == 1:
        proto = "icmp"
        sport = 0
        dport = 0
    elif proto_num == 58:
        proto = "icmpv6"
        sport = 0
        dport = 0
    elif proto_num is not None:
        proto = f"proto-{int(proto_num)}"
        sport = 0
        dport = 0
    else:
        proto = "other"
        sport = 0
        dport = 0

    if src and dst:
        five = f"{src}:{sport} -> {dst}:{dport}/{proto}"
    else:
        five = "undecoded"
    return str(src), str(dst), int(sport), int(dport), proto, five


def _parse_five_tuple_query(query: str) -> dict[str, Any] | None:
    """Parse a flexible 5-tuple query string.

    Accepted forms:
      * ``src:sport -> dst:dport/proto`` (canonical, from get_packet_capture_summary)
      * ``src:sport -> dst:dport`` (proto inferred from data)
      * ``src:sport-dst:dport``
      * ``src:sport dst:dport`` (whitespace separated)

    Returns a dict with keys ``src``, ``dst``, ``src_port``, ``dst_port``,
    ``proto`` (any of which may be ``None`` / 0 when not provided). Returns
    ``None`` if the query can't be split into two endpoints.
    """
    if not query:
        return None
    q = query.strip()
    proto = None
    if "/" in q:
        q, proto_tail = q.rsplit("/", 1)
        proto = proto_tail.strip().lower() or None
        q = q.strip()

    # Normalize separators between the two endpoints.
    for sep in ("->", "<->", "<-"):
        if sep in q:
            left, right = q.split(sep, 1)
            break
    else:
        if " " in q.strip():
            left, right = q.split(None, 1)
        else:
            # "src:sport-dst:dport" — assume the last single '-' is the
            # separator. Be careful: IPv6 addresses contain ':' but no '-'.
            # We only split on '-' that's preceded by a digit and followed
            # by a digit/letter (heuristic to avoid splitting MAC addresses
            # that might have been passed in).
            if "-" in q:
                parts = q.rsplit("-", 1)
                if len(parts) == 2:
                    left, right = parts
                else:
                    return None
            else:
                return None

    def _split_endpoint(endpoint: str) -> tuple[str, int]:
        endpoint = endpoint.strip()
        # IPv6 in brackets: [::1]:5000
        if endpoint.startswith("["):
            close = endpoint.find("]")
            if close < 0:
                return endpoint.strip("[]"), 0
            ip = endpoint[1:close]
            tail = endpoint[close + 1:].lstrip(":")
            try:
                return ip, int(tail) if tail else 0
            except ValueError:
                return ip, 0
        # IPv4 or hostname: last ':' is port (IPv6 without brackets is ambiguous)
        if ":" in endpoint:
            # If the address contains more than one colon, treat as IPv6 without port.
            if endpoint.count(":") > 1:
                return endpoint, 0
            ip, _, port = endpoint.rpartition(":")
            try:
                return ip, int(port)
            except ValueError:
                return endpoint, 0
        return endpoint, 0

    src, src_port = _split_endpoint(left)
    dst, dst_port = _split_endpoint(right)

    return {
        "src": src,
        "dst": dst,
        "src_port": src_port,
        "dst_port": dst_port,
        "proto": proto,
    }


def _five_tuples_match(row, query: dict[str, Any]) -> bool:
    """Return True if a row from ``_decoded_with_five_tuple`` matches.

    Direction-agnostic: a query of ``A -> B`` matches packets with either
    A→B or B→A so a single timeline shows both halves of a conversation.
    """
    src, dst = row["_src"], row["_dst"]
    sport, dport = row["_src_port"], row["_dst_port"]
    proto = row["_proto"]

    if query.get("proto") and proto != query["proto"]:
        return False

    q_src = query["src"]
    q_dst = query["dst"]
    q_sport = query["src_port"]
    q_dport = query["dst_port"]

    def _ip_matches(a: str, b: str) -> bool:
        return (not a) or (not b) or a == b

    def _port_matches(a: int, b: int) -> bool:
        return (not a) or (not b) or int(a) == int(b)

    forward = (
        _ip_matches(q_src, src) and _ip_matches(q_dst, dst)
        and _port_matches(q_sport, sport) and _port_matches(q_dport, dport)
    )
    backward = (
        _ip_matches(q_src, dst) and _ip_matches(q_dst, src)
        and _port_matches(q_sport, dport) and _port_matches(q_dport, sport)
    )
    return forward or backward


# ---------------------------------------------------------------------------
# Tool: get_packet_capture_summary
# ---------------------------------------------------------------------------


@mcp.tool()
def get_packet_capture_summary(
    trace_id: str,
    top_n: int = 50,
    process_filter: str | None = None,
) -> str:
    """Per-5-tuple packet/byte counts derived from decoded packet headers.

    Decodes the captured frame bytes for every row in ``packet_capture_df``
    on the fly (Ethernet → IP → L4) and groups by 5-tuple. One row per
    5-tuple with packet count split by Direction (Recv / Send) and total
    bytes. Sorted by total bytes descending.

    Args:
        trace_id: ID returned by load_trace.
        top_n: Maximum rows to return. Default: 50.
        process_filter: Case-insensitive substring filter on Process Name.
    """
    trace = require_trace(trace_id)
    _ensure_dumper_ready(trace)

    if not _packet_capture_available(trace):
        return _NO_PACKET_CAPTURE_MSG

    aggregates: dict[str, dict[str, Any]] = {}
    saw_packets = False
    saw_after_filter = False
    columns = [
        "Direction", "PacketBytes", "Size", "Process Name",
    ]
    for batch in _packet_capture_batches(trace, columns=columns):
        if not _packet_capture_ready(batch):
            continue
        saw_packets = saw_packets or not batch.empty
        batch = _apply_process_filter(batch, process_filter)
        if batch.empty:
            continue
        saw_after_filter = True
        for _, row in batch.iterrows():
            decoded = _decode_row(row.get("PacketBytes", ""))
            *_unused, five_tuple = _decoded_tuple_fields(decoded)
            entry = aggregates.setdefault(
                five_tuple,
                {
                    "5-Tuple": five_tuple,
                    "Recv Pkts": 0,
                    "Send Pkts": 0,
                    "Total Pkts": 0,
                    "Total Bytes": 0,
                },
            )
            direction = str(row.get("Direction", ""))
            if direction == "Recv":
                entry["Recv Pkts"] += 1
            elif direction == "Send":
                entry["Send Pkts"] += 1
            entry["Total Pkts"] += 1
            try:
                entry["Total Bytes"] += int(row.get("Size", 0) or 0)
            except (TypeError, ValueError):
                pass

    if not saw_packets:
        return _NO_PACKET_CAPTURE_MSG
    if not saw_after_filter:
        return f"*No packets match process filter `{process_filter}`.*"

    if not aggregates:
        return _NO_PACKET_CAPTURE_MSG

    result_df = pd.DataFrame(list(aggregates.values())).sort_values(
        "Total Bytes", ascending=False
    ).reset_index(drop=True)

    lines = [
        "**Packet Capture Summary**",
        "",
        f"5-tuples observed: {len(result_df):,}",
        f"Total packets: {int(result_df['Total Pkts'].sum()):,}",
    ]
    if process_filter:
        lines.append(f"Process filter: `{process_filter}`")
    lines.append("")
    lines.append(format_table(result_df, max_rows=top_n))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool: get_packet_timeline
# ---------------------------------------------------------------------------


@mcp.tool()
def get_packet_timeline(
    trace_id: str,
    five_tuple: str,
    max_packets: int = 100,
) -> str:
    """All packets for a given 5-tuple, in chronological order.

    Filters ``packet_capture_df`` to packets whose decoded 5-tuple matches
    ``five_tuple`` (direction-agnostic — both halves of the conversation
    are shown). Each row shows the decoded headers relevant to the L4
    protocol: ``Seq``, ``Ack``, ``Flags`` for TCP, ``Length`` for UDP,
    plus the raw captured size.

    Args:
        trace_id: ID returned by load_trace.
        five_tuple: 5-tuple selector. Accepted forms:
          ``"src:sport -> dst:dport/proto"`` (canonical, copy-pasteable
          from ``get_packet_capture_summary``); ``"src:sport - dst:dport"``;
          ``"src:sport dst:dport"``. Proto suffix is optional.
        max_packets: Cap on rows returned. Default: 100.
    """
    trace = require_trace(trace_id)
    _ensure_dumper_ready(trace)

    if not _packet_capture_available(trace):
        return _NO_PACKET_CAPTURE_MSG

    query = _parse_five_tuple_query(five_tuple)
    if query is None:
        return (
            "*Could not parse 5-tuple. Expected a form like "
            "`10.0.0.1:5000 -> 10.0.0.2:6000/udp` or "
            "`10.0.0.1:5000-10.0.0.2:6000`.*"
        )

    rows: list[dict[str, Any]] = []
    columns = ["TimeStamp", "Direction", "PacketBytes", "Size"]
    for batch in _packet_capture_batches(trace, columns=columns):
        if not _packet_capture_ready(batch):
            continue
        for _, row in batch.iterrows():
            decoded_row = _decode_row(row.get("PacketBytes", ""))
            src, dst, sport, dport, proto, _five = _decoded_tuple_fields(decoded_row)
            match_row = {
                "_src": src,
                "_dst": dst,
                "_src_port": sport,
                "_dst_port": dport,
                "_proto": proto,
            }
            if not _five_tuples_match(match_row, query):
                continue
            if proto == "tcp":
                flags = decoded_row.get("tcp.flags", [])
                l4_fields = (
                    f"seq={decoded_row.get('tcp.seq', 0)} "
                    f"ack={decoded_row.get('tcp.ack', 0)} "
                    f"flags={'+'.join(flags) if flags else '-'}"
                )
            elif proto == "udp":
                l4_fields = f"length={decoded_row.get('udp.length', 0)}"
            elif proto in ("icmp", "icmpv6"):
                prefix = proto
                l4_fields = (
                    f"type={decoded_row.get(f'{prefix}.type', 0)} "
                    f"code={decoded_row.get(f'{prefix}.code', 0)}"
                )
            else:
                l4_fields = ""

            rows.append({
                "TimeStamp": row.get("TimeStamp", 0),
                "Direction": row.get("Direction", ""),
                "Proto": proto,
                "Src": f"{src}:{sport}",
                "Dst": f"{dst}:{dport}",
                "L4 Fields": l4_fields,
                "Size": int(row.get("Size", 0) or 0),
            })

    if not rows:
        return f"*No packets match 5-tuple `{five_tuple}`.*"

    timeline_df = pd.DataFrame(rows).sort_values("TimeStamp").reset_index(drop=True)
    lines = [
        f"**Packet Timeline:** `{five_tuple}`",
        "",
        f"Matched packets: {len(timeline_df):,}",
        "",
        format_table(timeline_df, max_rows=max_packets),
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool: get_send_recv_latency
# ---------------------------------------------------------------------------


# Maximum allowed gap between a matched Send→Recv pair, in microseconds.
# Larger gaps are almost certainly unrelated packets that happened to share
# the same IPID or seqno. 10 ms is generous for loopback, conservative for
# WAN, and a non-issue for the typical project usage (loopback echo tests).
_MATCH_WINDOW_US = 10_000


def _matching_key(row, decoded: dict[str, Any]) -> tuple | None:
    """Build a matching key for Send/Recv latency.

    Strategy:
      * TCP — match by (src_ip, dst_ip, src_port, dst_port, seq).
      * UDP / other IP protocols — match by (src_ip, dst_ip, src_port,
        dst_port, ip.id). IPID is not guaranteed unique across a long
        trace but is a good signal over a short ~10 ms window.

    Returns ``None`` when we lack enough fields to form a key, in which
    case the row is excluded from the latency analysis.
    """
    src = decoded.get("ip.src")
    dst = decoded.get("ip.dst")
    if not src or not dst:
        return None

    proto = decoded.get("ip.proto")
    if proto == 6:  # TCP
        seq = decoded.get("tcp.seq")
        sport = decoded.get("tcp.src_port")
        dport = decoded.get("tcp.dst_port")
        if seq is None or sport is None or dport is None:
            return None
        return ("tcp", src, dst, sport, dport, seq)
    if proto == 17:  # UDP
        ip_id = decoded.get("ip.id")
        sport = decoded.get("udp.src_port")
        dport = decoded.get("udp.dst_port")
        if ip_id is None or sport is None or dport is None:
            return None
        return ("udp", src, dst, sport, dport, ip_id)
    # IPv6 has no IPID; bail unless TCP path covered it above.
    return None


def _flow_label(src: str, dst: str, sport: int, dport: int, proto: str) -> str:
    return f"{src}:{sport} -> {dst}:{dport}/{proto}"


def _packet_timestamp(row) -> int | None:
    try:
        value = row.get("TimeStamp", 0)
    except AttributeError:
        return None
    try:
        if pd.isna(value):
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


@mcp.tool()
def get_send_recv_latency(trace_id: str, top_n: int = 20) -> str:
    """Match Send → Recv packet pairs and report per-flow latency percentiles.

    For each Send packet we look up the next Recv packet with the same
    matching key (5-tuple + TCP sequence number, or 5-tuple + IPID for
    UDP) and compute the elapsed microseconds. Pairs separated by more
    than ~10 ms are dropped.

    **Heuristic, with caveats:**

    * On **loopback**, the latency floor is meaningful — the kernel is
      both sender and receiver and the timestamps come from the same
      clock, so anything sub-microsecond is real.
    * On a **two-NIC test setup with synchronized clocks** (e.g. PTP),
      the floor is meaningful but offset by clock skew.
    * On a **multi-NIC system with unsynchronized clocks** the floor is
      essentially clock skew, not network latency — treat distributions
      as a relative signal across flows, not as absolute one-way latency.

    The matching by IPID is also approximate: NICs and stacks may reuse
    IPIDs over long timescales, but within the ~10 ms match window
    collisions are rare for the project's loopback / 100 GbE setups.

    Args:
        trace_id: ID returned by load_trace.
        top_n: Maximum rows to return. Default: 20.
    """
    trace = require_trace(trace_id)
    _ensure_dumper_ready(trace)

    if not _packet_capture_available(trace):
        return _NO_PACKET_CAPTURE_MSG

    # Stream in timestamp order. Keep only unmatched sends whose expiry is
    # inside the bounded matching window, and match them when the corresponding
    # recv arrives. Materialized xperf traces are globally sorted first; native
    # event-store chunks are sorted per batch and can undercount if chunks are
    # globally out of order.
    pending_sends: dict[tuple, deque[tuple[int, dict[str, Any]]]] = {}
    expiry_heap: list[tuple[int, tuple, int]] = []
    per_flow_latencies: dict[str, list[int]] = {}
    saw_send = False
    saw_recv = False

    def _evict_expired(now_ts: int) -> None:
        while expiry_heap and expiry_heap[0][0] < now_ts:
            _expires_at, key, send_ts = heapq.heappop(expiry_heap)
            queue = pending_sends.get(key)
            if not queue:
                continue
            while queue and queue[0][0] < now_ts - _MATCH_WINDOW_US:
                queue.popleft()
            if not queue:
                pending_sends.pop(key, None)

    columns = ["TimeStamp", "Direction", "PacketBytes"]
    for batch in _packet_capture_batches(trace, columns=columns, sort_by_time=True):
        if not _packet_capture_ready(batch):
            continue
        if "Direction" not in batch.columns or "TimeStamp" not in batch.columns:
            continue
        for _, row in batch.iterrows():
            ts = _packet_timestamp(row)
            if ts is None:
                continue
            _evict_expired(ts)
            decoded = _decode_row(row.get("PacketBytes", ""))
            if not decoded:
                continue
            key = _matching_key(row, decoded)
            if key is None:
                continue
            direction = str(row.get("Direction", "")).lower()
            if direction == "send":
                saw_send = True
                pending_sends.setdefault(key, deque()).append((ts, decoded))
                heapq.heappush(expiry_heap, (ts + _MATCH_WINDOW_US, key, ts))
                continue
            if direction != "recv":
                continue
            saw_recv = True
            candidates = pending_sends.get(key)
            if not candidates:
                continue
            while candidates and ts - candidates[0][0] > _MATCH_WINDOW_US:
                candidates.popleft()
            if not candidates:
                pending_sends.pop(key, None)
                continue
            send_ts, send_decoded = candidates.popleft()
            if not candidates:
                pending_sends.pop(key, None)
            if send_ts > ts:
                continue
            latency_us = ts - send_ts
            proto_str = "tcp" if key[0] == "tcp" else "udp"
            if proto_str == "tcp":
                sport = send_decoded.get("tcp.src_port", 0)
                dport = send_decoded.get("tcp.dst_port", 0)
            else:
                sport = send_decoded.get("udp.src_port", 0)
                dport = send_decoded.get("udp.dst_port", 0)
            flow_label = _flow_label(
                send_decoded.get("ip.src", ""), send_decoded.get("ip.dst", ""),
                int(sport or 0), int(dport or 0), proto_str,
            )
            per_flow_latencies.setdefault(flow_label, []).append(latency_us)

    if not saw_send or not saw_recv:
        return (
            "*No matched Send/Recv pairs in packet capture data.*\n\n"
            "Either the trace contains only one direction, or the matching "
            "fields (TCP seqno / IPID + 5-tuple) are not consistent between "
            "send and recv (common on a multi-NIC setup where the IPID is "
            "rewritten in transit)."
        )

    if not per_flow_latencies:
        return (
            "*No Send → Recv pairs found within the matching window.*\n\n"
            "On multi-NIC systems with unsynchronized clocks the timestamps "
            "may differ by more than the 10 ms window we use to match a "
            "send to its echo; this can produce zero pairs even when the "
            "raw capture contains both directions."
        )

    rows: list[dict[str, Any]] = []
    for flow, latencies in per_flow_latencies.items():
        s = pd.Series(latencies, dtype="float64")
        rows.append({
            "Flow": flow,
            "Pairs": len(s),
            "p50 (us)": round(float(s.quantile(0.50)), 2),
            "p99 (us)": round(float(s.quantile(0.99)), 2),
            "p999 (us)": round(float(s.quantile(0.999)), 2),
            "min (us)": int(s.min()),
            "max (us)": int(s.max()),
        })

    result_df = pd.DataFrame(rows).sort_values(
        "Pairs", ascending=False
    ).reset_index(drop=True)

    lines = [
        "**Send → Recv Latency (Heuristic)**",
        "",
        f"Flows with matched pairs: {len(result_df):,}",
        f"Match window: {_MATCH_WINDOW_US / 1000:.0f} ms",
        "",
        "*Latency is one-way Send→Recv elapsed microseconds. Meaningful on "
        "loopback and PTP-synced two-NIC setups; on unsynchronized multi-NIC "
        "systems the floor is dominated by clock skew.*",
        "",
        "*Native event-store scans use bounded timestamp-order matching and "
        "evict candidates after the match window. If packet-capture chunks are "
        "globally out of order, pair counts can be under-reported; xperf/"
        "materialized traces are sorted before matching.*",
        "",
        format_table(result_df, max_rows=top_n),
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool: decode_packet
# ---------------------------------------------------------------------------


def _format_decoded_packet(decoded: dict[str, Any]) -> str:
    """Render a decoded-headers dict as a hierarchical markdown block."""
    if not decoded:
        return "*Packet bytes failed to decode (truncated or non-Ethernet).*"

    lines = ["**Ethernet:**"]
    lines.append(f"- src: `{decoded.get('eth.src', '?')}`")
    lines.append(f"- dst: `{decoded.get('eth.dst', '?')}`")
    et = decoded.get("eth.ethertype")
    if et is not None:
        lines.append(f"- ethertype: `0x{int(et):04x}`")
    if "eth.vlan_ethertype" in decoded:
        lines.append(
            f"- inner ethertype (VLAN): `0x{int(decoded['eth.vlan_ethertype']):04x}`"
        )

    if "ip.version" in decoded:
        version = decoded["ip.version"]
        lines.append("")
        lines.append(f"**IPv{int(version)}:**")
        if version == 4:
            lines.append(f"- src: `{decoded.get('ip.src', '?')}`")
            lines.append(f"- dst: `{decoded.get('ip.dst', '?')}`")
            lines.append(f"- proto: `{decoded.get('ip.proto', '?')}`")
            lines.append(f"- ttl: `{decoded.get('ip.ttl', '?')}`")
            lines.append(f"- id: `{decoded.get('ip.id', '?')}`")
            lines.append(f"- total_length: `{decoded.get('ip.total_length', '?')}`")
        else:
            lines.append(f"- src: `{decoded.get('ip.src', '?')}`")
            lines.append(f"- dst: `{decoded.get('ip.dst', '?')}`")
            lines.append(f"- next_header: `{decoded.get('ip.next_header', '?')}`")
            lines.append(f"- hop_limit: `{decoded.get('ip.hop_limit', '?')}`")
            lines.append(f"- payload_length: `{decoded.get('ip.payload_length', '?')}`")

    if "tcp.src_port" in decoded:
        lines.append("")
        lines.append("**TCP:**")
        lines.append(f"- src_port: `{decoded.get('tcp.src_port', '?')}`")
        lines.append(f"- dst_port: `{decoded.get('tcp.dst_port', '?')}`")
        lines.append(f"- seq: `{decoded.get('tcp.seq', '?')}`")
        lines.append(f"- ack: `{decoded.get('tcp.ack', '?')}`")
        flags = decoded.get("tcp.flags")
        if flags is not None:
            lines.append(f"- flags: `{'+'.join(flags) if flags else '-'}`")
        lines.append(f"- window: `{decoded.get('tcp.window', '?')}`")
    elif "udp.src_port" in decoded:
        lines.append("")
        lines.append("**UDP:**")
        lines.append(f"- src_port: `{decoded.get('udp.src_port', '?')}`")
        lines.append(f"- dst_port: `{decoded.get('udp.dst_port', '?')}`")
        lines.append(f"- length: `{decoded.get('udp.length', '?')}`")
    elif "icmp.type" in decoded:
        lines.append("")
        lines.append("**ICMP:**")
        lines.append(f"- type: `{decoded.get('icmp.type', '?')}`")
        lines.append(f"- code: `{decoded.get('icmp.code', '?')}`")
    elif "icmpv6.type" in decoded:
        lines.append("")
        lines.append("**ICMPv6:**")
        lines.append(f"- type: `{decoded.get('icmpv6.type', '?')}`")
        lines.append(f"- code: `{decoded.get('icmpv6.code', '?')}`")

    if "_truncated_at" in decoded:
        lines.append("")
        lines.append(f"*Packet truncated at layer: `{decoded['_truncated_at']}`.*")
    return "\n".join(lines)


@mcp.tool()
def decode_packet(trace_id: str, timestamp_us: float) -> str:
    """Decode the single packet whose timestamp is closest to ``timestamp_us``.

    Useful for "show me what packet fired at time X". The result lays out
    the Ethernet, IP, and L4 layers field-by-field.

    Args:
        trace_id: ID returned by load_trace.
        timestamp_us: Target timestamp in microseconds (matches the
            dumper's TimeStamp column).
    """
    trace = require_trace(trace_id)
    _ensure_dumper_ready(trace)

    if not _packet_capture_available(trace):
        return _NO_PACKET_CAPTURE_MSG

    best_row: dict[str, Any] | None = None
    best_delta: float | None = None
    target = float(timestamp_us)
    columns = ["TimeStamp", "Direction", "MiniportName", "PacketBytes", "Size"]
    for batch in _packet_capture_batches(trace, columns=columns):
        if not _packet_capture_ready(batch) or "TimeStamp" not in batch.columns:
            continue
        for _, row in batch.iterrows():
            ts = _packet_timestamp(row)
            if ts is None:
                continue
            delta = abs(float(ts) - target)
            if best_delta is None or delta < best_delta:
                best_delta = delta
                best_row = row.to_dict()

    if best_row is None:
        return "*No packets with parseable timestamps in this trace.*"

    packet_hex = best_row.get("PacketBytes", "")
    decoded = _decode_row(packet_hex)
    actual_ts = int(best_row.get("TimeStamp", 0) or 0)
    direction = best_row.get("Direction", "")
    miniport = best_row.get("MiniportName", "")
    size = int(best_row.get("Size", 0) or 0)

    lines = [
        "**Decoded Packet**",
        "",
        f"- Trace timestamp: `{actual_ts} us` (queried `{target:.1f} us`, "
        f"delta `{actual_ts - target:.1f} us`)",
        f"- Direction: `{direction}`",
        f"- Miniport: `{miniport}`",
        f"- Captured size: `{size}` bytes",
        "",
        _format_decoded_packet(decoded),
    ]
    return "\n".join(lines)


__all__ = [
    "decode_packet",
    "get_packet_capture_summary",
    "get_packet_timeline",
    "get_send_recv_latency",
]
