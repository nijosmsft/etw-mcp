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

from typing import Any

import pandas as pd

from etw_analyzer.app import mcp
from etw_analyzer.formatting.markdown import format_table
from etw_analyzer.parsing.packet_decode import decode_packet_headers
from etw_analyzer.trace_state import TraceData, require_trace


_NO_PACKET_CAPTURE_MSG = (
    "*No packet-capture data in this trace.*\n\n"
    "Re-collect with `udp-perf/scripts/networking.wprp` — the "
    "`Microsoft-Windows-NDIS-PacketCapture` provider must be enabled to "
    "record frame bytes. Standard `xdptrace.wprp` traces do not include "
    "packet captures."
)


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

    df = trace.packet_capture_df
    if not _packet_capture_ready(df):
        return _NO_PACKET_CAPTURE_MSG

    df = _apply_process_filter(df, process_filter)
    if df.empty:
        return f"*No packets match process filter `{process_filter}`.*"

    decoded = _decoded_with_five_tuple(df)

    rows: list[dict[str, Any]] = []
    for tup, group in decoded.groupby("_five_tuple"):
        recv = int((group.get("Direction", pd.Series(dtype=str)) == "Recv").sum())
        send = int((group.get("Direction", pd.Series(dtype=str)) == "Send").sum())
        total = len(group)
        size_col = pd.to_numeric(group["Size"], errors="coerce").fillna(0) if "Size" in group.columns else pd.Series([])
        total_bytes = int(size_col.sum()) if not size_col.empty else 0
        rows.append({
            "5-Tuple": tup,
            "Recv Pkts": recv,
            "Send Pkts": send,
            "Total Pkts": total,
            "Total Bytes": total_bytes,
        })

    if not rows:
        return _NO_PACKET_CAPTURE_MSG

    result_df = pd.DataFrame(rows).sort_values(
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

    df = trace.packet_capture_df
    if not _packet_capture_ready(df):
        return _NO_PACKET_CAPTURE_MSG

    query = _parse_five_tuple_query(five_tuple)
    if query is None:
        return (
            "*Could not parse 5-tuple. Expected a form like "
            "`10.0.0.1:5000 -> 10.0.0.2:6000/udp` or "
            "`10.0.0.1:5000-10.0.0.2:6000`.*"
        )

    decoded = _decoded_with_five_tuple(df)
    mask = decoded.apply(lambda row: _five_tuples_match(row, query), axis=1)
    matched = decoded[mask]
    if matched.empty:
        return f"*No packets match 5-tuple `{five_tuple}`.*"

    # Build per-row display: TimeStamp, Direction, decoded L4 fields, Size.
    rows: list[dict[str, Any]] = []
    for _, row in matched.iterrows():
        decoded_row = _decode_row(row.get("PacketBytes", ""))
        proto = row["_proto"]
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
            "Src": f"{row['_src']}:{row['_src_port']}",
            "Dst": f"{row['_dst']}:{row['_dst_port']}",
            "L4 Fields": l4_fields,
            "Size": int(row.get("Size", 0) or 0),
        })

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

    df = trace.packet_capture_df
    if not _packet_capture_ready(df):
        return _NO_PACKET_CAPTURE_MSG

    if "Direction" not in df.columns or "TimeStamp" not in df.columns:
        return _NO_PACKET_CAPTURE_MSG

    # Index by matching key for Recv packets; for each Send, search for the
    # earliest Recv with the same key and a positive small delta.
    recv_index: dict[tuple, list[tuple[int, str, dict[str, Any]]]] = {}
    send_rows: list[tuple[int, tuple, dict[str, Any]]] = []

    for _, row in df.iterrows():
        packet_hex = row.get("PacketBytes", "")
        decoded = _decode_row(packet_hex)
        if not decoded:
            continue
        key = _matching_key(row, decoded)
        if key is None:
            continue
        try:
            ts = int(row.get("TimeStamp", 0))
        except (TypeError, ValueError):
            continue
        direction = row.get("Direction", "")
        if direction == "Recv":
            recv_index.setdefault(key, []).append((ts, str(row.get("MiniportName", "")), decoded))
        elif direction == "Send":
            send_rows.append((ts, key, decoded))

    if not send_rows or not recv_index:
        return (
            "*No matched Send/Recv pairs in packet capture data.*\n\n"
            "Either the trace contains only one direction, or the matching "
            "fields (TCP seqno / IPID + 5-tuple) are not consistent between "
            "send and recv (common on a multi-NIC setup where the IPID is "
            "rewritten in transit)."
        )

    # Sort recv lists by timestamp so we can binary-search.
    for key in recv_index:
        recv_index[key].sort(key=lambda x: x[0])

    # Per-flow latency aggregation. Flow label = canonical send tuple.
    per_flow_latencies: dict[str, list[int]] = {}

    for send_ts, key, send_decoded in send_rows:
        candidates = recv_index.get(key)
        if not candidates:
            continue
        # Find the first recv ts >= send_ts within window. Linear scan is
        # fine for our scales (sub-million-packet traces).
        match_ts: int | None = None
        for recv_ts, _miniport, _recv_decoded in candidates:
            if recv_ts < send_ts:
                continue
            if recv_ts - send_ts > _MATCH_WINDOW_US:
                break
            match_ts = recv_ts
            break

        if match_ts is None:
            continue

        latency_us = match_ts - send_ts
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

    df = trace.packet_capture_df
    if not _packet_capture_ready(df):
        return _NO_PACKET_CAPTURE_MSG

    if "TimeStamp" not in df.columns:
        return _NO_PACKET_CAPTURE_MSG

    timestamps = pd.to_numeric(df["TimeStamp"], errors="coerce")
    valid = timestamps.dropna()
    if valid.empty:
        return "*No packets with parseable timestamps in this trace.*"

    target = float(timestamp_us)
    diffs = (valid - target).abs()
    closest_idx = diffs.idxmin()
    row = df.loc[closest_idx]

    packet_hex = row.get("PacketBytes", "")
    decoded = _decode_row(packet_hex)
    actual_ts = int(row.get("TimeStamp", 0) or 0)
    direction = row.get("Direction", "")
    miniport = row.get("MiniportName", "")
    size = int(row.get("Size", 0) or 0)

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
