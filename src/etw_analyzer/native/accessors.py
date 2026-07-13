"""Shared helpers for reading native event-store datasets without refactors."""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any

import pandas as pd

from etw_analyzer.parsing.aggregator import parse_cpu_filter

from .event_store import EventFilters
from .schemas import canonical_event_class, empty_table

if TYPE_CHECKING:
    from etw_analyzer.trace_state import TraceData


DEFAULT_MATERIALIZE_ROW_LIMIT = 100_000
DEFAULT_SCHEDULER_BATCH_SIZE = 65_536
DEFAULT_READY_JOIN_ROW_LIMIT = 100_000


_TRACE_ATTRS_BY_DATASET: dict[str, tuple[str, ...]] = {
    "sampled_profile": ("dumper_df",),
    "cswitch": ("cswitch_events_df",),
    "readythread": ("readythread_df",),
    "tcpip_recv": ("tcpip_recv_df",),
    "tcpip_send": ("tcpip_send_df",),
    "tcpip_retransmit": ("tcpip_retransmit_df",),
    "tcpip_connect": ("tcpip_connect_df",),
    "tcpip_accept": ("tcpip_accept_df",),
    "udp_recv": ("udp_recv_df",),
    "udp_send": ("udp_send_df",),
    "afd_recv": ("afd_recv_df",),
    "afd_send": ("afd_send_df",),
    "afd_connect": ("afd_connect_df",),
    "afd_accept": ("afd_accept_df",),
    "afd_close": ("afd_close_df",),
    "ndis_drops": ("ndis_drops_df",),
    "packet_capture": ("packet_capture_df",),
    "http_recv": ("http_recv_df",),
    "http_deliver": ("http_deliver_df",),
    "http_send": ("http_send_df",),
    "http_close": ("http_close_df",),
    "quic_conn_created": ("quic_conn_created_df",),
    "quic_conn_closed": ("quic_conn_closed_df",),
    "quic_packet_recv": ("quic_packet_recv_df",),
    "quic_packet_send": ("quic_packet_send_df",),
    "quic_ack_recv": ("quic_ack_recv_df",),
}


_RAW_KEYS_BY_DATASET: dict[str, tuple[str, ...]] = {
    "sampled_profile": ("sampled_profile", "SampledProfile"),
    "cswitch": ("cswitch", "CSwitch", "context_switch"),
    "readythread": ("readythread", "ReadyThread", "ready_thread"),
    "dpc": ("dpc", "PerfInfo/DPC"),
    "isr": ("isr", "PerfInfo/ISR"),
}


def has_event_store_dataset(trace: "TraceData", event_class: str) -> bool:
    """Return True when ``trace.event_store`` contains ``event_class``."""

    cname = _safe_canonical_event_class(event_class)
    if cname is None:
        return False
    store = getattr(trace, "event_store", None)
    datasets = getattr(getattr(store, "manifest", None), "datasets", None)
    return isinstance(datasets, dict) and cname in datasets


def has_trace_event_dataset(trace: "TraceData", event_class: str) -> bool:
    """Return True when a materialized or event-store dataset is available."""

    cname = _safe_canonical_event_class(event_class)
    if cname is None:
        return False
    return (
        _materialized_frame(trace, cname, event_class) is not None
        or has_event_store_dataset(trace, cname)
    )


def iter_event_batches(
    trace: "TraceData",
    event_class: str,
    *,
    filters: EventFilters | None = None,
    columns: list[str] | None = None,
    include_time: bool = True,
    batch_size: int = 65_536,
) -> Iterator[pd.DataFrame]:
    """Yield event rows, preferring materialized frames over event-store data."""

    cname = _safe_canonical_event_class(event_class)
    if cname is None:
        return

    frame = _materialized_frame(trace, cname, event_class)
    if frame is not None:
        df = _filter_materialized_frame(
            frame,
            filters=filters,
            columns=columns,
            include_time=include_time,
        )
        safe_batch_size = max(1, int(batch_size or 65_536))
        for start in range(0, len(df), safe_batch_size):
            yield df.iloc[start:start + safe_batch_size].reset_index(drop=True)
        return

    store = getattr(trace, "event_store", None)
    if store is None or not has_event_store_dataset(trace, cname):
        return
    store_columns = _columns_with_filter_dependencies(columns, filters)
    for batch in store.iter_batches(
        cname,
        filters=filters,
        columns=store_columns,
        include_time=include_time,
        batch_size=batch_size,
    ):
        yield _project_requested_columns(
            batch,
            columns=columns,
            include_time=include_time,
        )


def materialize_event_dataset(
    trace: "TraceData",
    event_class: str,
    *,
    filters: EventFilters | None = None,
    columns: list[str] | None = None,
    include_time: bool = True,
    max_rows: int | None = DEFAULT_MATERIALIZE_ROW_LIMIT,
) -> pd.DataFrame | None:
    """Return a bounded DataFrame for tests and small traces, or ``None``."""

    cname = _safe_canonical_event_class(event_class)
    if cname is None:
        return None

    frame = _materialized_frame(trace, cname, event_class)
    if frame is not None:
        df = _filter_materialized_frame(
            frame,
            filters=filters,
            columns=columns,
            include_time=include_time,
        )
        _raise_if_over_limit(cname, len(df), max_rows)
        return df

    store = getattr(trace, "event_store", None)
    if store is None or not has_event_store_dataset(trace, cname):
        return None

    chunks: list[pd.DataFrame] = []
    total = 0
    store_columns = _columns_with_filter_dependencies(columns, filters)
    for batch in store.iter_batches(
        cname,
        filters=filters,
        columns=store_columns,
        include_time=include_time,
    ):
        if batch.empty:
            continue
        batch = _project_requested_columns(
            batch,
            columns=columns,
            include_time=include_time,
        )
        total += len(batch)
        _raise_if_over_limit(cname, total, max_rows)
        chunks.append(batch)

    if chunks:
        return pd.concat(chunks, ignore_index=True, sort=False)
    return store.scan(
        cname,
        filters=filters,
        columns=store_columns,
        include_time=include_time,
    ).pipe(
        _project_requested_columns,
        columns=columns,
        include_time=include_time,
    )


def empty_event_dataset(event_class: str) -> pd.DataFrame | None:
    """Return an empty materialized DataFrame for a known dataset class."""

    cname = _safe_canonical_event_class(event_class)
    if cname is None:
        return None
    return empty_table(cname).to_pandas()


def build_cswitch_wait_summary(
    trace: "TraceData",
    *,
    filters: EventFilters | None = None,
    batch_size: int = DEFAULT_SCHEDULER_BATCH_SIZE,
) -> pd.DataFrame | None:
    """Build a memory-bounded CSwitch WaitReason histogram.

    The returned DataFrame has ``WaitReason``, ``Count``, and ``%`` columns.
    It streams event-store batches when available and preserves the legacy
    materialized DataFrame path through :func:`iter_event_batches`.
    """

    counts: dict[str, int] = defaultdict(int)
    total = 0
    for batch in iter_event_batches(
        trace,
        "cswitch",
        filters=filters,
        columns=["WaitReason"],
        include_time=False,
        batch_size=batch_size,
    ):
        if batch.empty or "WaitReason" not in batch.columns:
            continue
        reasons = batch["WaitReason"].fillna("").astype(str)
        grouped = reasons.value_counts(dropna=False)
        for reason, count in grouped.items():
            counts[str(reason) or "(unknown)"] += int(count)
            total += int(count)

    if total == 0:
        return None
    rows = [
        {
            "WaitReason": reason or "(unknown)",
            "Count": count,
            "%": (count / total * 100.0),
        }
        for reason, count in sorted(
            counts.items(),
            key=lambda item: item[1],
            reverse=True,
        )
    ]
    return pd.DataFrame(rows)


def build_cswitch_events_for_tid(
    trace: "TraceData",
    target_tid: int,
    *,
    filters: EventFilters | None = None,
    max_rows: int | None = DEFAULT_MATERIALIZE_ROW_LIMIT,
    batch_size: int = DEFAULT_SCHEDULER_BATCH_SIZE,
) -> pd.DataFrame | None:
    """Return CSwitch rows for one switched-in TID without loading all rows."""

    rows: list[pd.DataFrame] = []
    total = 0
    columns = [
        "TimeStampQpc", "TimeStamp", "CPU", "NewTID", "OldTID",
        "NewPID", "OldPID", "WaitReason",
    ]
    for batch in iter_event_batches(
        trace,
        "cswitch",
        filters=filters,
        columns=columns,
        include_time=True,
        batch_size=batch_size,
    ):
        if batch.empty or "NewTID" not in batch.columns:
            continue
        tids = pd.to_numeric(batch["NewTID"], errors="coerce")
        subset = batch[tids == int(target_tid)].copy()
        if subset.empty:
            continue
        total += len(subset)
        _raise_if_over_limit("cswitch", total, max_rows)
        rows.append(_normalize_cswitch_columns(subset))

    if rows:
        return pd.concat(rows, ignore_index=True, sort=False)
    if has_trace_event_dataset(trace, "cswitch"):
        return pd.DataFrame(columns=[
            "TimeStamp", "WaitReason", "OldTID", "OldPID",
            "NewTID", "NewPID", "CPU",
        ])
    return None


def find_cswitch_tids_for_process(
    trace: "TraceData",
    process_substring: str,
    *,
    filters: EventFilters | None = None,
    batch_size: int = DEFAULT_SCHEDULER_BATCH_SIZE,
) -> list[tuple[int, str, int]]:
    """Find busy switched-in TIDs for a process-name substring via event-store maps."""

    needle = str(process_substring or "").lower()
    if not needle:
        return []

    pid_to_name: dict[int, str] = {}
    for batch in iter_event_batches(
        trace,
        "process",
        columns=["ProcessId", "ImageFileName"],
        include_time=False,
        batch_size=batch_size,
    ):
        if batch.empty or "ProcessId" not in batch.columns:
            continue
        names = batch.get("ImageFileName", pd.Series([""] * len(batch)))
        for pid_value, name_value in zip(batch["ProcessId"], names):
            pid = _safe_int(pid_value)
            name = str(name_value or "")
            if pid is not None and name:
                pid_to_name[pid] = name

    matching_pids = {
        pid for pid, name in pid_to_name.items()
        if needle in name.lower()
    }
    if not matching_pids:
        return []

    tid_to_process: dict[int, str] = {}
    for batch in iter_event_batches(
        trace,
        "thread",
        columns=["ThreadId", "ProcessId"],
        include_time=False,
        batch_size=batch_size,
    ):
        if (
            batch.empty
            or "ThreadId" not in batch.columns
            or "ProcessId" not in batch.columns
        ):
            continue
        for tid_value, pid_value in zip(batch["ThreadId"], batch["ProcessId"]):
            tid = _safe_int(tid_value)
            pid = _safe_int(pid_value)
            if tid is None or pid not in matching_pids:
                continue
            tid_to_process[tid] = pid_to_name.get(pid, "")

    if not tid_to_process:
        return []

    counts: dict[int, int] = defaultdict(int)
    candidate_tids = set(tid_to_process)
    for batch in iter_event_batches(
        trace,
        "cswitch",
        filters=filters,
        columns=["NewTID"],
        include_time=False,
        batch_size=batch_size,
    ):
        if batch.empty or "NewTID" not in batch.columns:
            continue
        tids = pd.to_numeric(batch["NewTID"], errors="coerce")
        matched = tids[tids.isin(candidate_tids)]
        for tid, count in matched.value_counts().items():
            counts[int(tid)] += int(count)

    return sorted(
        (
            (tid, tid_to_process.get(tid, ""), count)
            for tid, count in counts.items()
        ),
        key=lambda item: item[2],
        reverse=True,
    )


def iter_readythread_cswitch_waits(
    trace: "TraceData",
    *,
    filters: EventFilters | None = None,
    target_tid: int | None = None,
    max_window_us: float = 1_000_000.0,
    batch_size: int = DEFAULT_SCHEDULER_BATCH_SIZE,
    output_batch_size: int = 4096,
) -> Iterator[pd.DataFrame]:
    """Yield ReadyThread rows joined to the next CSwitch for the same TID.

    The join is bounded by ``max_window_us`` and streams both event classes in
    timestamp order. It is intended for scheduler tools that need wait-time
    attribution without materializing the full CSwitch/ReadyThread datasets.
    """

    if (
        not has_trace_event_dataset(trace, "readythread")
        or not has_trace_event_dataset(trace, "cswitch")
    ):
        return

    ready_filters = filters or EventFilters()
    cswitch_filters = _expand_end_time_filter(ready_filters, max_window_us)
    ready_rows = _iter_scheduler_rows(
        trace,
        "readythread",
        filters=ready_filters,
        columns=[
            "EventSequence", "TimeStampQpc", "TimeStamp", "CPU",
            "ProcessId", "ThreadId", "AdjustReason", "AdjustIncrement",
            "Flag", "Stack",
        ],
        batch_size=batch_size,
    )
    cswitch_rows = _iter_scheduler_rows(
        trace,
        "cswitch",
        filters=cswitch_filters,
        columns=[
            "EventSequence", "TimeStampQpc", "TimeStamp", "CPU",
            "NewTID", "OldTID", "NewPID", "OldPID", "WaitReason",
        ],
        batch_size=batch_size,
    )

    formatter = _StackFormatter(trace)
    pending: dict[int, deque[dict[str, Any]]] = defaultdict(deque)
    out: list[dict[str, Any]] = []
    max_delta = _max_window_units(trace, max_window_us)

    ready = _next_or_none(ready_rows)
    cswitch = _next_or_none(cswitch_rows)
    while ready is not None or cswitch is not None:
        if cswitch is None or (
            ready is not None and _event_order_value(ready) <= _event_order_value(cswitch)
        ):
            ready_tid = _ready_thread_id(ready)
            if ready_tid is not None and (target_tid is None or ready_tid == int(target_tid)):
                pending[ready_tid].append(ready)
            ready = _next_or_none(ready_rows)
            continue

        switch_tid = _safe_int(cswitch.get("NewTID"))
        switch_time = _event_order_value(cswitch)
        if switch_tid is not None and (target_tid is None or switch_tid == int(target_tid)):
            queue = pending.get(switch_tid)
            if queue:
                while queue and switch_time - _event_order_value(queue[0]) > max_delta:
                    queue.popleft()
                while queue and _event_order_value(queue[0]) <= switch_time:
                    ready_row = queue.popleft()
                    wait_us = _wait_delta_us(trace, ready_row, cswitch)
                    if wait_us is None or wait_us < 0 or wait_us > max_window_us:
                        continue
                    out.append(_ready_cswitch_join_row(
                        trace,
                        ready_row,
                        cswitch,
                        wait_us,
                        formatter,
                    ))
                    if len(out) >= output_batch_size:
                        yield pd.DataFrame(out)
                        out = []
                if not queue:
                    pending.pop(switch_tid, None)
        cswitch = _next_or_none(cswitch_rows)

    if out:
        yield pd.DataFrame(out)


def build_readythread_cswitch_waits(
    trace: "TraceData",
    *,
    filters: EventFilters | None = None,
    target_tid: int | None = None,
    max_window_us: float = 1_000_000.0,
    max_rows: int | None = DEFAULT_READY_JOIN_ROW_LIMIT,
    batch_size: int = DEFAULT_SCHEDULER_BATCH_SIZE,
) -> pd.DataFrame | None:
    """Materialize a bounded ReadyThread→CSwitch wait dataset."""

    chunks: list[pd.DataFrame] = []
    total = 0
    for batch in iter_readythread_cswitch_waits(
        trace,
        filters=filters,
        target_tid=target_tid,
        max_window_us=max_window_us,
        batch_size=batch_size,
    ):
        if batch.empty:
            continue
        total += len(batch)
        _raise_if_over_limit("readythread/cswitch", total, max_rows)
        chunks.append(batch)

    if chunks:
        return pd.concat(chunks, ignore_index=True, sort=False)
    if (
        has_trace_event_dataset(trace, "readythread")
        and has_trace_event_dataset(trace, "cswitch")
    ):
        return pd.DataFrame(columns=[
            "TimeStamp", "ReadyTimeStamp", "SwitchTimeStamp", "ThreadID",
            "NewTID", "OldTID", "WaitReason", "Wait (us)", "CPU",
            "SwitchCPU", "Ready Thread Stack", "ReadyThread Stack",
        ])
    return None


def _safe_canonical_event_class(event_class: str) -> str | None:
    try:
        return canonical_event_class(event_class)
    except KeyError:
        return None


def _iter_scheduler_rows(
    trace: "TraceData",
    event_class: str,
    *,
    filters: EventFilters | None,
    columns: list[str],
    batch_size: int,
) -> Iterator[dict[str, Any]]:
    for batch in iter_event_batches(
        trace,
        event_class,
        filters=filters,
        columns=columns,
        include_time=True,
        batch_size=batch_size,
    ):
        if batch.empty:
            continue
        for row in _sort_by_event_time(batch).to_dict(orient="records"):
            yield row


def _sort_by_event_time(df: pd.DataFrame) -> pd.DataFrame:
    sort_columns = [
        column for column in ("TimeStampQpc", "TimeStamp", "EventSequence")
        if column in df.columns
    ]
    if not sort_columns:
        return df
    return df.sort_values(sort_columns, kind="stable")


def _normalize_cswitch_columns(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    if "OldThreadState" not in out.columns:
        out["OldThreadState"] = ""
    if "OldProcessName" not in out.columns:
        out["OldProcessName"] = ""
    if "NewProcessName" not in out.columns:
        out["NewProcessName"] = ""
    return out.reset_index(drop=True)


def _expand_end_time_filter(
    filters: EventFilters,
    max_window_us: float,
) -> EventFilters:
    end_time = filters.end_time
    if end_time is not None:
        end_time = float(end_time) + float(max_window_us) / 1_000_000.0
    return EventFilters(
        cpu_filter=filters.cpu_filter,
        start_time=filters.start_time,
        end_time=end_time,
        start_qpc=filters.start_qpc,
        end_qpc=filters.end_qpc,
    )


def _max_window_units(trace: "TraceData", max_window_us: float) -> float:
    store = getattr(trace, "event_store", None)
    timebase = getattr(store, "timebase", None)
    perf_freq = getattr(timebase, "perf_freq", None)
    if perf_freq:
        return float(max_window_us) * float(perf_freq) / 1_000_000.0
    return float(max_window_us)


def _next_or_none(iterator: Iterator[dict[str, Any]]) -> dict[str, Any] | None:
    try:
        return next(iterator)
    except StopIteration:
        return None


def _event_order_value(row: dict[str, Any]) -> float:
    for key in ("TimeStampQpc", "TimeStamp"):
        value = row.get(key)
        if value is None:
            continue
        try:
            if pd.isna(value):
                continue
        except TypeError:
            pass
        try:
            return float(value)
        except (TypeError, ValueError):
            continue
    return 0.0


def _ready_thread_id(row: dict[str, Any]) -> int | None:
    for key in ("ThreadId", "ThreadID", "ReadyThreadId"):
        value = _safe_int(row.get(key))
        if value is not None:
            return value
    return None


def _safe_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        if pd.isna(value):
            return None
    except TypeError:
        pass
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _wait_delta_us(
    trace: "TraceData",
    ready_row: dict[str, Any],
    cswitch_row: dict[str, Any],
) -> float | None:
    ready_ts = _numeric_value(ready_row.get("TimeStamp"))
    switch_ts = _numeric_value(cswitch_row.get("TimeStamp"))
    if ready_ts is not None and switch_ts is not None:
        return switch_ts - ready_ts

    ready_qpc = _numeric_value(ready_row.get("TimeStampQpc"))
    switch_qpc = _numeric_value(cswitch_row.get("TimeStampQpc"))
    if ready_qpc is None or switch_qpc is None:
        return None
    store = getattr(trace, "event_store", None)
    timebase = getattr(store, "timebase", None)
    perf_freq = getattr(timebase, "perf_freq", None)
    if perf_freq:
        return (switch_qpc - ready_qpc) * 1_000_000.0 / float(perf_freq)
    return switch_qpc - ready_qpc


def _numeric_value(value: Any) -> float | None:
    if value is None:
        return None
    try:
        if pd.isna(value):
            return None
    except TypeError:
        pass
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _ready_cswitch_join_row(
    trace: "TraceData",
    ready_row: dict[str, Any],
    cswitch_row: dict[str, Any],
    wait_us: float,
    formatter: "_StackFormatter",
) -> dict[str, Any]:
    stack_text = formatter.stack_text(ready_row.get("Stack"))
    ready_time = ready_row.get("TimeStamp")
    switch_time = cswitch_row.get("TimeStamp")
    return {
        "TimeStamp": switch_time if switch_time is not None else ready_time,
        "ReadyTimeStamp": ready_time,
        "SwitchTimeStamp": switch_time,
        "TimeStampQpc": cswitch_row.get("TimeStampQpc"),
        "ReadyTimeStampQpc": ready_row.get("TimeStampQpc"),
        "SwitchTimeStampQpc": cswitch_row.get("TimeStampQpc"),
        "CPU": ready_row.get("CPU"),
        "SwitchCPU": cswitch_row.get("CPU"),
        "PID": ready_row.get("ProcessId"),
        "ThreadID": _ready_thread_id(ready_row),
        "NewTID": cswitch_row.get("NewTID"),
        "OldTID": cswitch_row.get("OldTID"),
        "NewPID": cswitch_row.get("NewPID"),
        "OldPID": cswitch_row.get("OldPID"),
        "WaitReason": cswitch_row.get("WaitReason", ""),
        "Wait (us)": float(wait_us),
        "AdjustReason": ready_row.get("AdjustReason"),
        "AdjustIncrement": ready_row.get("AdjustIncrement"),
        "Flag": ready_row.get("Flag"),
        "Ready Thread Stack": stack_text,
        "ReadyThread Stack": stack_text,
    }


class _StackFormatter:
    def __init__(self, trace: "TraceData") -> None:
        self.trace = trace
        self._cache: dict[tuple[int, ...], str] = {}
        self._symbolizer_checked = False

    def stack_text(self, value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, str):
            return value
        if hasattr(value, "tolist"):
            value = value.tolist()
        if not isinstance(value, (list, tuple)):
            return str(value)
        addrs: list[int] = []
        for item in value:
            try:
                addrs.append(int(item))
            except (TypeError, ValueError):
                continue
        if not addrs:
            return ""
        key = tuple(addrs)
        cached = self._cache.get(key)
        if cached is not None:
            return cached

        symbolizer = self._symbolizer()
        labels: dict[int, str] = {}
        if symbolizer is not None:
            try:
                labels = symbolizer.bulk_resolve(addrs)
            except Exception:
                labels = {}
        text = " / ".join(labels.get(addr, f"0x{addr:x}") for addr in addrs)
        self._cache[key] = text
        return text

    def _symbolizer(self):
        symbolizer = getattr(self.trace, "symbolizer", None)
        if symbolizer is not None or self._symbolizer_checked:
            return symbolizer
        self._symbolizer_checked = True
        store = getattr(self.trace, "event_store", None)
        if store is None or not has_event_store_dataset(self.trace, "image"):
            return None
        try:
            from etw_analyzer.native import Symbolizer

            symbolizer = Symbolizer(symbol_path=getattr(self.trace, "symbol_path", None))
            for batch in iter_event_batches(
                self.trace,
                "image",
                columns=["ImageBase", "ImageSize", "FileName"],
                include_time=False,
                batch_size=DEFAULT_SCHEDULER_BATCH_SIZE,
            ):
                if batch.empty:
                    continue
                for base, size, file_name in zip(
                    batch.get("ImageBase", pd.Series(dtype="object")),
                    batch.get("ImageSize", pd.Series(dtype="object")),
                    batch.get("FileName", pd.Series(dtype="object")),
                ):
                    base_i = _safe_int(base)
                    size_i = _safe_int(size)
                    if base_i is None or size_i is None:
                        continue
                    pdb_id = getattr(self.trace, "pdb_identity", {}).get(base_i)
                    if pdb_id and pdb_id.get("pdb_guid"):
                        symbolizer.add_module(
                            base_i, size_i, str(file_name or ""),
                            pdb_guid=pdb_id["pdb_guid"],
                            pdb_age=pdb_id.get("pdb_age"),
                            pdb_name=pdb_id.get("pdb_name"),
                            time_date_stamp=pdb_id.get("time_date_stamp"),
                        )
                    else:
                        symbolizer.add_module(base_i, size_i, str(file_name or ""))
            self.trace.symbolizer = symbolizer
            return symbolizer
        except Exception:
            return None


def _raw_csv_keys(cname: str, requested: str) -> tuple[str, ...]:
    keys = [requested, cname, *_RAW_KEYS_BY_DATASET.get(cname, ())]
    seen: set[str] = set()
    ordered: list[str] = []
    for key in keys:
        if not key or key in seen:
            continue
        seen.add(key)
        ordered.append(key)
    return tuple(ordered)


def _materialized_frame(
    trace: "TraceData",
    cname: str,
    requested: str,
) -> pd.DataFrame | None:
    raw_csv = getattr(trace, "raw_csv", {}) or {}
    for key in _raw_csv_keys(cname, requested):
        df = raw_csv.get(key)
        if isinstance(df, pd.DataFrame):
            return df

    for attr in _TRACE_ATTRS_BY_DATASET.get(cname, ()):
        df = getattr(trace, attr, None)
        if isinstance(df, pd.DataFrame):
            return df
    return None


def _filter_materialized_frame(
    df: pd.DataFrame,
    *,
    filters: EventFilters | None,
    columns: list[str] | None,
    include_time: bool,
) -> pd.DataFrame:
    out = df.copy()
    if filters is not None and not out.empty:
        out = _apply_event_filters(out, filters)
    if columns is not None:
        out = _project_requested_columns(
            out,
            columns=columns,
            include_time=include_time,
        )
    elif not include_time and "TimeStamp" in out.columns:
        out = out.drop(columns=["TimeStamp"])
    return out.reset_index(drop=True)


def _columns_with_filter_dependencies(
    columns: list[str] | None,
    filters: EventFilters | None,
) -> list[str] | None:
    if columns is None:
        return None
    expanded = list(columns)
    if filters is None:
        return expanded
    if filters.cpu_filter is not None and "CPU" not in expanded:
        expanded.append("CPU")
    has_time_filter = any(
        value is not None
        for value in (
            filters.start_time,
            filters.end_time,
            filters.start_qpc,
            filters.end_qpc,
        )
    )
    if has_time_filter and "TimeStampQpc" not in expanded:
        expanded.append("TimeStampQpc")
    return expanded


def _project_requested_columns(
    df: pd.DataFrame,
    *,
    columns: list[str] | None,
    include_time: bool,
) -> pd.DataFrame:
    if columns is None:
        if include_time or "TimeStamp" not in df.columns:
            return df.reset_index(drop=True)
        return df.drop(columns=["TimeStamp"]).reset_index(drop=True)
    keep = [column for column in columns if column in df.columns]
    if include_time and "TimeStamp" in df.columns and "TimeStamp" not in keep:
        keep.append("TimeStamp")
    return df[keep].reset_index(drop=True)


def _apply_event_filters(df: pd.DataFrame, filters: EventFilters) -> pd.DataFrame:
    mask = pd.Series(True, index=df.index)
    cpu_set = _cpu_set(filters.cpu_filter)
    if cpu_set and "CPU" in df.columns:
        mask &= df["CPU"].isin(cpu_set)

    start_qpc = filters.start_qpc
    end_qpc = filters.end_qpc
    if "TimeStampQpc" in df.columns:
        qpc = pd.to_numeric(df["TimeStampQpc"], errors="coerce")
        if start_qpc is not None:
            mask &= qpc >= start_qpc
        if end_qpc is not None:
            mask &= qpc <= end_qpc

    if "TimeStamp" in df.columns:
        timestamp = pd.to_numeric(df["TimeStamp"], errors="coerce")
        if filters.start_time is not None:
            mask &= timestamp >= float(filters.start_time) * 1_000_000.0
        if filters.end_time is not None:
            mask &= timestamp <= float(filters.end_time) * 1_000_000.0

    return df[mask].copy()


def _cpu_set(cpu_filter: str | object) -> set[int] | None:
    if cpu_filter is None:
        return None
    if isinstance(cpu_filter, str):
        return set(parse_cpu_filter(cpu_filter) or [])
    try:
        return {int(value) for value in cpu_filter}  # type: ignore[union-attr]
    except TypeError:
        return None


def _raise_if_over_limit(
    cname: str,
    row_count: int,
    max_rows: int | None,
) -> None:
    if max_rows is not None and row_count > int(max_rows):
        raise ValueError(
            f"event-store dataset {cname!r} has {row_count:,} rows, "
            f"exceeding max_rows={int(max_rows):,}; iterate batches instead"
        )


__all__ = [
    "DEFAULT_MATERIALIZE_ROW_LIMIT",
    "DEFAULT_READY_JOIN_ROW_LIMIT",
    "DEFAULT_SCHEDULER_BATCH_SIZE",
    "build_cswitch_events_for_tid",
    "build_cswitch_wait_summary",
    "build_readythread_cswitch_waits",
    "find_cswitch_tids_for_process",
    "has_event_store_dataset",
    "has_trace_event_dataset",
    "iter_event_batches",
    "iter_readythread_cswitch_waits",
    "materialize_event_dataset",
    "empty_event_dataset",
]
