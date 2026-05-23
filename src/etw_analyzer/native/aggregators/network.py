"""Native networking event enrichment helpers.

The manifest TCP send/recv events often carry only a TCB pointer.  The
connect/rundown events carry the corresponding 5-tuple.  This module joins
those pieces in-memory so the existing network tools see the same shape they
get from xperf dumper output.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import TYPE_CHECKING

import pandas as pd

from etw_analyzer.native.accessors import iter_event_batches

from .profile_detail import _build_pid_to_name_map

if TYPE_CHECKING:
    from etw_analyzer.trace_state import TraceData


_TCP_CLASSES: tuple[tuple[str, str], ...] = (
    ("TcpIp/Recv", "tcpip_recv_df"),
    ("TcpIp/Send", "tcpip_send_df"),
    ("TcpIp/Retransmit", "tcpip_retransmit_df"),
    ("TcpIp/Connect", "tcpip_connect_df"),
    ("TcpIp/Accept", "tcpip_accept_df"),
)

_AFD_CLASSES: tuple[tuple[str, str], ...] = (
    ("AFD/Recv", "afd_recv_df"),
    ("AFD/Send", "afd_send_df"),
    ("AFD/Connect", "afd_connect_df"),
    ("AFD/Accept", "afd_accept_df"),
    ("AFD/Close", "afd_close_df"),
)

_ENDPOINT_COLS = ("LocalAddr", "LocalPort", "RemoteAddr", "RemotePort")
_UNKNOWN_NAME = "unknown"
_UNKNOWN_ADDR = "<unknown>"
_PID_SENTINELS = {0, -1, 0xFFFFFFFF}
_DEFAULT_BATCH_SIZE = 65_536

_CANONICAL_TO_ATTR = {
    canonical: attr for canonical, attr in (*_TCP_CLASSES, *_AFD_CLASSES)
}
_STORE_TO_CANONICAL = {
    "tcpip_recv": "TcpIp/Recv",
    "tcpip_send": "TcpIp/Send",
    "tcpip_retransmit": "TcpIp/Retransmit",
    "tcpip_connect": "TcpIp/Connect",
    "tcpip_accept": "TcpIp/Accept",
    "udp_recv": "UdpIp/Recv",
    "udp_send": "UdpIp/Send",
    "afd_recv": "AFD/Recv",
    "afd_send": "AFD/Send",
    "afd_connect": "AFD/Connect",
    "afd_accept": "AFD/Accept",
    "afd_close": "AFD/Close",
    "ndis_drops": "NdisDrop",
    "packet_capture": "NdisPacketCapture",
}
_CANONICAL_TO_STORE = {canonical: store for store, canonical in _STORE_TO_CANONICAL.items()}


def _to_int(value, default: int = 0) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, float) and pd.notna(value):
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return default
        try:
            if text.lower().startswith("0x"):
                return int(text, 16)
            return int(float(text))
        except ValueError:
            return default
    return default


def _has_endpoint(row: pd.Series) -> bool:
    local = str(row.get("LocalAddr", "") or "").strip()
    remote = str(row.get("RemoteAddr", "") or "").strip()
    local_port = _to_int(row.get("LocalPort", 0))
    remote_port = _to_int(row.get("RemotePort", 0))
    return bool(local and remote and local_port > 0 and remote_port > 0)


def _is_unknown_name(value: object) -> bool:
    text = str(value or "").strip()
    return text == "" or text.lower() in {"<unknown>", "unknown", "nan"}


def _set_if_missing(df: pd.DataFrame, idx, column: str, value) -> bool:
    if value is None:
        return False
    if column not in df.columns:
        df[column] = "" if column.endswith("Addr") or column == "Process Name" else 0
    current = df.at[idx, column]
    if column.endswith("Port") or column == "PID":
        if _to_int(current) not in _PID_SENTINELS and _to_int(current) != 0:
            return False
        new_value = _to_int(value)
        if new_value == 0:
            return False
        df.at[idx, column] = new_value
        return True
    if str(current or "").strip():
        return False
    if str(value or "").strip():
        df.at[idx, column] = value
        return True
    return False


def _set_name_if_unknown(
    df: pd.DataFrame,
    idx,
    *,
    pid_map: dict[int, str],
    fallback_pid: int | None = None,
    fallback_name: str | None = None,
) -> bool:
    if "Process Name" not in df.columns:
        df["Process Name"] = ""
    if not _is_unknown_name(df.at[idx, "Process Name"]):
        return False

    pid = _to_int(df.at[idx, "PID"]) if "PID" in df.columns else 0
    if pid in _PID_SENTINELS and fallback_pid is not None:
        pid = fallback_pid

    name = pid_map.get(pid, "") if pid not in _PID_SENTINELS else ""
    if not name and fallback_name and not _is_unknown_name(fallback_name):
        name = str(fallback_name)
    if not name:
        name = _UNKNOWN_NAME
    df.at[idx, "Process Name"] = name
    return True


def _normalise_unknowns(df: pd.DataFrame) -> bool:
    mutated = False
    for column in ("LocalAddr", "RemoteAddr"):
        if column in df.columns:
            blank = df[column].astype(str).str.strip().isin({"", "nan", "None"})
            if blank.any():
                df.loc[blank, column] = _UNKNOWN_ADDR
                mutated = True
    if "Process Name" in df.columns:
        unknown = df["Process Name"].map(_is_unknown_name)
        if unknown.any():
            df.loc[unknown, "Process Name"] = _UNKNOWN_NAME
            mutated = True
    return mutated


def _project_columns(
    df: pd.DataFrame,
    columns: list[str] | None,
    *,
    include_time: bool = True,
) -> pd.DataFrame:
    if columns is None:
        if include_time or "TimeStamp" not in df.columns:
            return df.reset_index(drop=True)
        return df.drop(columns=["TimeStamp"]).reset_index(drop=True)
    keep = [column for column in columns if column in df.columns]
    if include_time and "TimeStamp" in df.columns and "TimeStamp" not in keep:
        keep.append("TimeStamp")
    return df[keep].reset_index(drop=True)


def _canonical_event_class(event_class: str) -> str:
    try:
        from etw_analyzer.native.schemas import canonical_event_class

        store_name = canonical_event_class(event_class)
        return _STORE_TO_CANONICAL.get(store_name, store_name)
    except Exception:
        return _STORE_TO_CANONICAL.get(event_class, event_class)


def _expanded_columns_for_enrichment(
    canonical: str,
    columns: list[str] | None,
) -> list[str] | None:
    if columns is None:
        return None
    expanded = list(dict.fromkeys(columns))
    for column in ("PID", "Process Name"):
        if column not in expanded:
            expanded.append(column)
    if canonical in {name for name, _attr in _TCP_CLASSES} and "ConnId" not in expanded:
        expanded.append("ConnId")
    if canonical in {name for name, _attr in _AFD_CLASSES} and "SocketHandle" not in expanded:
        expanded.append("SocketHandle")
    if canonical in {
        "TcpIp/Recv", "TcpIp/Send", "TcpIp/Retransmit",
        "TcpIp/Connect", "TcpIp/Accept",
        "UdpIp/Recv", "UdpIp/Send",
        "AFD/Connect", "AFD/Accept",
    }:
        for column in _ENDPOINT_COLS:
            if column not in expanded:
                expanded.append(column)
    return expanded


def _event_batches(
    trace: "TraceData",
    event_class: str,
    *,
    columns: list[str] | None = None,
    include_time: bool = True,
    batch_size: int = _DEFAULT_BATCH_SIZE,
) -> Iterator[pd.DataFrame]:
    yield from iter_event_batches(
        trace,
        event_class,
        columns=columns,
        include_time=include_time,
        batch_size=batch_size,
    )


def _build_pid_to_name_map_with_store(trace: "TraceData") -> dict[int, str]:
    pid_map = dict(_build_pid_to_name_map(trace))
    for batch in _event_batches(
        trace,
        "process",
        columns=["ProcessId", "ImageFileName"],
        include_time=False,
    ):
        if batch.empty:
            continue
        if "ProcessId" not in batch.columns or "ImageFileName" not in batch.columns:
            continue
        for _, row in batch.iterrows():
            pid = _to_int(row.get("ProcessId", 0))
            name = str(row.get("ImageFileName", "") or "").strip("\x00").strip()
            if pid not in _PID_SENTINELS and name:
                pid_map[pid] = name
    return pid_map


def _build_map_from_batches(
    trace: "TraceData",
    event_classes: tuple[str, ...],
    *,
    id_column: str,
) -> dict[int, dict[str, object]]:
    mapping: dict[int, dict[str, object]] = {}
    columns = [
        id_column,
        *_ENDPOINT_COLS,
        "PID",
        "Process Name",
    ]
    for event_class in event_classes:
        for batch in _event_batches(
            trace,
            event_class,
            columns=columns,
            include_time=False,
        ):
            if batch.empty or id_column not in batch.columns:
                continue
            for _, row in batch.iterrows():
                item_id = _to_int(row.get(id_column, 0))
                if item_id == 0:
                    continue
                entry = mapping.setdefault(item_id, {})
                for column in _ENDPOINT_COLS:
                    value = row.get(column)
                    if value not in (None, "", 0):
                        entry[column] = value
                pid = _to_int(row.get("PID", 0))
                if pid not in _PID_SENTINELS:
                    entry["PID"] = pid
                name = row.get("Process Name")
                if name is not None and not _is_unknown_name(name):
                    entry["Process Name"] = str(name)
    return mapping


def _network_enrichment_cache(
    trace: "TraceData",
) -> tuple[dict[int, str], dict[int, dict[str, object]], dict[int, dict[str, object]]]:
    with trace.lock:
        cached = getattr(trace, "_network_enrichment_cache", None)
        if cached is not None:
            return cached
        pid_map = _build_pid_to_name_map_with_store(trace)
        tcb_map = _build_map_from_batches(
            trace,
            tuple(canonical for canonical, _attr in _TCP_CLASSES if canonical != "TcpIp/Recv" and canonical != "TcpIp/Send"),
            id_column="ConnId",
        )
        socket_map = _build_map_from_batches(
            trace,
            ("AFD/Accept", "AFD/Connect", "AFD/Recv", "AFD/Send"),
            id_column="SocketHandle",
        )
        cached = (pid_map, tcb_map, socket_map)
        setattr(trace, "_network_enrichment_cache", cached)
        return cached


def iter_enriched_network_batches(
    trace: "TraceData",
    event_class: str,
    *,
    columns: list[str] | None = None,
    include_time: bool = True,
    batch_size: int = _DEFAULT_BATCH_SIZE,
) -> Iterator[pd.DataFrame]:
    """Yield network event batches, preferring xperf/materialized frames.

    The native event store keeps network detail in chunked parquet datasets.
    This accessor streams those chunks and applies the same ConnId/socket
    enrichment used by the materialized native path so existing tools can
    operate without forcing the whole dataset into memory.
    """

    canonical = _canonical_event_class(event_class)
    store_class = _CANONICAL_TO_STORE.get(canonical, event_class)
    expanded_columns = _expanded_columns_for_enrichment(canonical, columns)
    pid_map, tcb_map, socket_map = _network_enrichment_cache(trace)

    for batch in _event_batches(
        trace,
        store_class,
        columns=expanded_columns,
        include_time=include_time,
        batch_size=batch_size,
    ):
        if batch.empty:
            continue
        out = batch.copy()
        if canonical in {name for name, _attr in _TCP_CLASSES}:
            _enrich_by_id(
                out,
                id_column="ConnId",
                mapping=tcb_map,
                pid_map=pid_map,
            )
        elif canonical in {name for name, _attr in _AFD_CLASSES}:
            _enrich_by_id(
                out,
                id_column="SocketHandle",
                mapping=socket_map,
                pid_map=pid_map,
            )
        elif canonical in {"UdpIp/Recv", "UdpIp/Send", "NdisDrop", "NdisPacketCapture"}:
            if "Process Name" in out.columns:
                for idx, _row in out.iterrows():
                    _set_name_if_unknown(out, idx, pid_map=pid_map)
            _normalise_unknowns(out)
        yield _project_columns(out, columns, include_time=include_time)


def _build_tcb_map(trace: "TraceData") -> dict[int, dict[str, object]]:
    mapping: dict[int, dict[str, object]] = {}
    for attr in ("tcpip_connect_df", "tcpip_accept_df", "tcpip_retransmit_df"):
        df = getattr(trace, attr, None)
        if df is None or df.empty or "ConnId" not in df.columns:
            continue
        for _, row in df.iterrows():
            conn_id = _to_int(row.get("ConnId", 0))
            if conn_id == 0 or not _has_endpoint(row):
                continue
            entry = mapping.setdefault(conn_id, {})
            for column in _ENDPOINT_COLS:
                value = row.get(column)
                if value not in (None, "", 0):
                    entry[column] = value
            pid = _to_int(row.get("PID", 0))
            if pid not in _PID_SENTINELS:
                entry["PID"] = pid
            name = row.get("Process Name")
            if name is not None and not _is_unknown_name(name):
                entry["Process Name"] = str(name)
    return mapping


def _build_socket_map(trace: "TraceData") -> dict[int, dict[str, object]]:
    mapping: dict[int, dict[str, object]] = {}
    for attr in ("afd_accept_df", "afd_connect_df", "afd_recv_df", "afd_send_df"):
        df = getattr(trace, attr, None)
        if df is None or df.empty or "SocketHandle" not in df.columns:
            continue
        for _, row in df.iterrows():
            handle = _to_int(row.get("SocketHandle", 0))
            if handle == 0:
                continue
            entry = mapping.setdefault(handle, {})
            for column in _ENDPOINT_COLS:
                value = row.get(column)
                if value not in (None, "", 0):
                    entry[column] = value
            pid = _to_int(row.get("PID", 0))
            if pid not in _PID_SENTINELS:
                entry["PID"] = pid
            name = row.get("Process Name")
            if name is not None and not _is_unknown_name(name):
                entry["Process Name"] = str(name)
    return mapping


def _enrich_by_id(
    df: pd.DataFrame,
    *,
    id_column: str,
    mapping: dict[int, dict[str, object]],
    pid_map: dict[int, str],
) -> bool:
    if df.empty:
        return False
    mutated = False
    if id_column not in df.columns:
        mutated |= _normalise_unknowns(df)
        return mutated
    for idx, row in df.iterrows():
        item_id = _to_int(row.get(id_column, 0))
        entry = mapping.get(item_id, {})
        if entry:
            for column in _ENDPOINT_COLS:
                mutated |= _set_if_missing(df, idx, column, entry.get(column))
            fallback_pid = _to_int(entry.get("PID", 0))
            if fallback_pid not in _PID_SENTINELS:
                mutated |= _set_if_missing(df, idx, "PID", fallback_pid)
            mutated |= _set_name_if_unknown(
                df,
                idx,
                pid_map=pid_map,
                fallback_pid=fallback_pid,
                fallback_name=entry.get("Process Name"),
            )
        else:
            mutated |= _set_name_if_unknown(df, idx, pid_map=pid_map)
    mutated |= _normalise_unknowns(df)
    return mutated


def enrich_network_events(trace: "TraceData") -> set[str]:
    """Enrich native-mode networking DataFrames in-place.

    Returns the canonical event-class names that were mutated.  It is safe to
    call repeatedly; once rows are enriched the helper becomes a no-op except
    for normalising explicit unknown markers.
    """
    pid_map = _build_pid_to_name_map(trace)
    mutated: set[str] = set()

    tcb_map = _build_tcb_map(trace)
    for canonical, attr in _TCP_CLASSES:
        df = getattr(trace, attr, None)
        if df is None or df.empty:
            continue
        if _enrich_by_id(df, id_column="ConnId", mapping=tcb_map, pid_map=pid_map):
            mutated.add(canonical)

    socket_map = _build_socket_map(trace)
    for canonical, attr in _AFD_CLASSES:
        df = getattr(trace, attr, None)
        if df is None or df.empty:
            continue
        if _enrich_by_id(
            df,
            id_column="SocketHandle",
            mapping=socket_map,
            pid_map=pid_map,
        ):
            mutated.add(canonical)

    return mutated


__all__ = ["enrich_network_events", "iter_enriched_network_batches"]
