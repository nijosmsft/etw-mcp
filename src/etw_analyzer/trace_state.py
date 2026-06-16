"""Loaded trace registry."""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pandas as pd


@dataclass
class TraceData:
    """Cached data from a loaded ETL trace."""

    trace_id: str
    etl_path: Path
    export_dir: Path
    symbol_path: str | None = None

    # Source mode for the cached DataFrames. Either ``"xperf"`` (the
    # default text-based ``xperf -a dumper`` pipeline) or ``"native"``
    # (the in-process ``OpenTraceW``/``ProcessTrace`` consumer added in
    # Phase N1 of the native-ETW work). Tools may surface this in their
    # output but should not rely on it for correctness — both modes are
    # expected to populate the same DataFrame slots with equivalent
    # schemas. See ``udp-perf/docs/wpr-mcp-native-etw-design.md`` §8.
    mode: str = "xperf"

    # Parsed DataFrames keyed by profile name
    raw_csv: dict[str, pd.DataFrame] = field(default_factory=dict)

    # Cached per-CPU sampling data (from xperf -a dumper)
    # Populated lazily by background thread after load_trace, or on first per-CPU query.
    dumper_df: pd.DataFrame | None = None

    # Cached parsed CSwitch events (also from xperf -a dumper, single pass).
    # Populated by the same background thread that fills ``dumper_df``. Each
    # row has TimeStamp, NewProcessName/PID/TID, OldProcessName/PID/TID,
    # WaitReason, WaitMode, OldThreadState, CPU, NewPriority, OldPriority,
    # Extra4. None until the extraction completes (use ``wait_for_dumper``
    # to block).
    cswitch_events_df: pd.DataFrame | None = None

    # Phase 3a: per-event-class networking DataFrames populated by the same
    # background dumper extraction. Schema notes in
    # :mod:`parsing.wpa_exporter` (search for "Phase 3a"). All are ``None``
    # until extraction completes; an empty DataFrame means extraction ran
    # but the trace had no events of that class (likely because the trace
    # was not collected with the TCPIP/UDP providers — see
    # ``udp-perf/scripts/networking.wprp``).
    tcpip_recv_df: pd.DataFrame | None = None
    tcpip_send_df: pd.DataFrame | None = None
    tcpip_retransmit_df: pd.DataFrame | None = None
    tcpip_connect_df: pd.DataFrame | None = None
    tcpip_accept_df: pd.DataFrame | None = None
    udp_recv_df: pd.DataFrame | None = None
    udp_send_df: pd.DataFrame | None = None

    # Phase 3b: AFD socket-level events + NDIS dropped packets. Same caveats
    # as the TCPIP/UDP DataFrames above — populated by the background dumper
    # extraction, empty when the trace lacks the Winsock-AFD / NDIS providers.
    afd_recv_df: pd.DataFrame | None = None
    afd_send_df: pd.DataFrame | None = None
    afd_connect_df: pd.DataFrame | None = None
    afd_accept_df: pd.DataFrame | None = None
    afd_close_df: pd.DataFrame | None = None
    ndis_drops_df: pd.DataFrame | None = None

    # Phase 4: NDIS PacketCapture events. One row per captured frame.
    # Columns: TimeStamp, Direction ("Recv"/"Send"), MiniportName,
    # PacketBytes (hex string), Size. Decoding into Ethernet/IP/L4 fields
    # is done lazily by the Phase 4 tools (see
    # :mod:`etw_analyzer.parsing.packet_decode`). Empty when the trace was
    # collected without the ``Microsoft-Windows-NDIS-PacketCapture``
    # provider (see ``udp-perf/scripts/networking.wprp``).
    packet_capture_df: pd.DataFrame | None = None

    # Phase 5: HTTP.sys request-lifecycle events
    # (``Microsoft-Windows-HttpService``). One row per opcode. Schemas are
    # speculative until validated against a real trace — see the
    # ``_handle_http_*`` handlers in :mod:`parsing.wpa_exporter`. Empty
    # when the trace was collected without the HttpService provider.
    http_recv_df: pd.DataFrame | None = None
    http_deliver_df: pd.DataFrame | None = None
    http_send_df: pd.DataFrame | None = None
    http_close_df: pd.DataFrame | None = None

    # Phase 5: MsQuic connection-state events (``Microsoft-Quic``). Same
    # caveats as the HTTP.sys DataFrames above. Schemas align with the
    # ``_handle_quic_*`` handlers; empty when the MsQuic provider was not
    # enabled at capture time.
    quic_conn_created_df: pd.DataFrame | None = None
    quic_conn_closed_df: pd.DataFrame | None = None
    quic_packet_recv_df: pd.DataFrame | None = None
    quic_packet_send_df: pd.DataFrame | None = None
    quic_ack_recv_df: pd.DataFrame | None = None

    # Background extraction state
    _dumper_future: threading.Thread | None = field(default=None, repr=False)
    _dumper_ready: threading.Event = field(default_factory=threading.Event, repr=False)
    _dumper_error: str | None = field(default=None, repr=False)

    # Phase N3: dbghelp-backed symbolizer. Populated in native mode by
    # ``tools.trace_mgmt._start_background_dumper`` once ImageLoad
    # events have been decoded. ``None`` for xperf-mode traces — the
    # xperf path uses ``xperf -a symcache -build`` instead, which
    # produces symbolized strings inline. Phase N4 aggregators
    # (butterfly, hot_functions) call into ``symbolizer.bulk_resolve``
    # when resolving SampledProfile stacks.
    symbolizer: Any = field(default=None, repr=False)

    # M2: per-ImageBase PDB identity stashed by the three
    # _build_symbolizer_from_images helpers so M3 can pass exact
    # GUID/Age/Name to the extended add_module without re-reading parquets.
    # Key: ImageBase (int); value: dict with keys
    # pdb_guid, pdb_age, pdb_name, time_date_stamp (each may be None).
    pdb_identity: dict[int, dict] = field(default_factory=dict, repr=False)

    # Phase 3 native large-ETL scaffolding: optional chunked event store.
    # This is opened from native cache-v2 manifests and is intentionally
    # separate from ``raw_csv`` so event chunks are not materialized on load.
    event_store: Any = field(default=None, repr=False)

    # Metadata
    duration_seconds: float | None = None
    cpu_count: int | None = None
    timestamp_frequency: float | None = None
    event_counts: dict[str, int] = field(default_factory=dict)
    export_errors: list[str] = field(default_factory=list)

    # Protect lazy per-trace cache population.
    lock: Any = field(default_factory=threading.RLock, repr=False)

    def wait_for_dumper(self) -> pd.DataFrame | None:
        """Block until the background dumper extraction completes, then return the DataFrame."""
        if self.dumper_df is not None:
            return self.dumper_df
        if self._dumper_future is not None:
            self._dumper_ready.wait()  # Block until background thread signals
        return self.dumper_df

    @property
    def cpu_sampling(self) -> pd.DataFrame | None:
        return self.raw_csv.get("cpu_sampling")

    @property
    def dpc_isr(self) -> pd.DataFrame | None:
        return self.raw_csv.get("dpc_isr")

    @property
    def cswitch(self) -> pd.DataFrame | None:
        return self.raw_csv.get("cswitch")


_traces: dict[str, TraceData] = {}
_registry_lock = threading.RLock()


def make_trace_id(etl_path: Path) -> str:
    """Create a stable ID for the current version of an ETL file."""
    path = etl_path.resolve()
    stat = path.stat()
    key = f"{str(path).lower()}|{stat.st_size}|{stat.st_mtime_ns}"
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
    return f"trace_{digest}"


def register_trace(trace: TraceData) -> str:
    """Register a loaded trace and return its trace ID."""
    with _registry_lock:
        _traces[trace.trace_id] = trace
    return trace.trace_id


def get_trace(trace_id: str) -> TraceData | None:
    """Return a loaded trace by ID."""
    with _registry_lock:
        return _traces.get(trace_id)


def require_trace(trace_id: str) -> TraceData:
    """Get a loaded trace by ID or raise a helpful error."""
    if not trace_id:
        raise ValueError(
            "trace_id is required. Call load_trace first and pass the returned trace_id."
        )

    trace = get_trace(trace_id)
    if trace is None:
        loaded = list_loaded_trace_ids()
        if loaded:
            loaded_msg = ", ".join(f"`{tid}`" for tid in loaded)
            raise ValueError(
                f"Unknown trace_id `{trace_id}`. Loaded trace IDs: {loaded_msg}"
            )
        raise ValueError(
            f"Unknown trace_id `{trace_id}`. No traces are loaded. Call load_trace first."
        )
    return trace


def list_loaded_traces() -> list[TraceData]:
    """Return all loaded traces."""
    with _registry_lock:
        return list(_traces.values())


def list_loaded_trace_ids() -> list[str]:
    """Return loaded trace IDs."""
    with _registry_lock:
        return sorted(_traces)


def unregister_trace(trace_id: str) -> bool:
    """Remove a loaded trace from the registry."""
    with _registry_lock:
        return _traces.pop(trace_id, None) is not None


def clear_traces() -> None:
    """Clear all loaded traces. Intended for tests."""
    with _registry_lock:
        _traces.clear()
