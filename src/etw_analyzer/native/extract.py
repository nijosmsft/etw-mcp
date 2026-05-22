"""Drop-in shape-compatible replacement for ``parse_dumper_events``.

Phase N1 ships the SHELL: the consumer is real, the dispatch table is
real, the public API matches ``parse_dumper_events``, but only a small
subset of handlers actually decode payloads:

    * ``SampledProfile`` — minimal decoder so existing aggregations
      (``get_cpu_samples``, ``get_hot_functions``, etc.) have data to
      chew on when the trace is loaded in native mode. Module/function
      symbolization is Phase N3 territory; for now we emit raw
      ``InstructionPointer`` values and empty ``Module``/``Function``
      strings.
    * Every other class returns an empty DataFrame.

This is intentional. Phase N2 fills in the kernel MOF table (per design
§4) and lights up CSwitch / TcpIp / UdpIp / etc. The architectural gap
this phase closes — manifest providers like TCPIP, AFD, MsQuic, HttpService
that ``xperf -a dumper`` cannot enumerate — is exposed by emitting their
event records into a single ``__providers__`` debug DataFrame keyed by
provider GUID and event id, so tests can prove visibility without
needing the full decoder set.
"""

from __future__ import annotations

import logging
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Optional

import pandas as pd

from .bindings.types import EVENT_RECORD, guid_string
from .consumer import EtwConsumer, NativeConsumerError


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Canonical event-class names — these must stay in lockstep with
# ``parsing.wpa_exporter.EVENT_HANDLERS`` and
# ``tools.trace_mgmt._DUMPER_EVENT_CLASSES``. Both keys appear in the output
# dict so calling code can iterate either map.
# ---------------------------------------------------------------------------
CANONICAL_EVENT_CLASSES: tuple[str, ...] = (
    "SampledProfile",
    "CSwitch",
    "TcpIp/Recv",
    "TcpIp/Send",
    "TcpIp/Retransmit",
    "TcpIp/Connect",
    "TcpIp/Accept",
    "UdpIp/Recv",
    "UdpIp/Send",
    "AFD/Recv",
    "AFD/Send",
    "AFD/Connect",
    "AFD/Accept",
    "AFD/Close",
    "NdisDrop",
    "NdisPacketCapture",
    "HttpService/Recv",
    "HttpService/Deliver",
    "HttpService/Send",
    "HttpService/Close",
    "Quic/ConnectionCreated",
    "Quic/ConnectionClosed",
    "Quic/PacketRecv",
    "Quic/PacketSend",
    "Quic/AckReceived",
)


# Kernel provider GUIDs (lowercase). The decoder routing table in Phase N2
# will key on these; for Phase N1 we only need them to identify which
# events to dispatch as kernel-MOF (vs manifest/TDH).
KERNEL_PERFINFO_GUID = "ce1dbfb4-137e-4da6-87b0-3f59aa102cbc"
KERNEL_THREAD_GUID = "3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c"


# ---------------------------------------------------------------------------
# Native handler dispatch table.
#
# Phase N1: a small registry keyed on (provider_guid_lower, event_id_or_opcode)
# pointing at functions that turn an EVENT_RECORD into a row dict — same
# shape as the existing text handlers, but consuming raw bytes rather than
# CSV columns. Only SampledProfile is wired up; the rest are deliberate
# placeholders so Phase N2 can drop the additional decoders in without
# changing the public surface.
# ---------------------------------------------------------------------------
NativeRowDict = dict
HandlerKey = tuple[str, int]   # (provider_guid_lower, opcode_or_event_id)
HandlerFn = Callable[[EVENT_RECORD], Optional[NativeRowDict]]


def _handle_sampled_profile_native(record: EVENT_RECORD) -> Optional[NativeRowDict]:
    """Native SampledProfile decoder.

    The kernel ``PerfInfo`` provider emits a 12-byte payload for opcode 46:
    ``InstructionPointer`` (u64), ``ThreadId`` (u32), ``Count`` (u32). For
    Phase N1 we read everything that lives in the headers and the first
    8 bytes of the payload; module/function resolution comes later.

    Output columns are aligned with ``_handle_sampled_profile`` so the
    downstream aggregators do not need to special-case mode:

        TimeStamp, Process Name, PID, CPU, Module, Function, Weight
    """

    import ctypes

    hdr = record.EventHeader
    timestamp = int(hdr.TimeStamp)
    pid = int(hdr.ProcessId)
    cpu = int(record.BufferContext.U.BC.ProcessorNumber)

    # We currently don't resolve PID -> process name. Phase N3 wires in
    # the dbghelp symbolizer plus a process-name map built from
    # Process/Start events; until then leave the column blank rather
    # than fabricate a value.
    process_name = ""
    module = ""
    function = ""

    # Payload: ``<QII`` per design §4.2. Weight defaults to 1 if we can't
    # read the count (rare — happens when ETW emits the legacy v=1 layout).
    weight = 1
    payload_len = int(record.UserDataLength)
    if payload_len >= 16 and record.UserData:
        try:
            payload = ctypes.string_at(record.UserData, 16)
            # InstructionPointer at offset 0..7, ThreadId at 8..11,
            # Count at 12..15. We only use Count.
            import struct
            weight = max(1, int(struct.unpack_from("<I", payload, 12)[0]))
        except (OSError, ValueError):
            pass

    return {
        "TimeStamp": timestamp,
        "Process Name": process_name,
        "PID": pid,
        "CPU": cpu,
        "Module": module,
        "Function": function,
        "Weight": weight,
    }


# (provider_guid_lower, opcode) -> (canonical_class, handler_fn)
_HANDLERS: dict[HandlerKey, tuple[str, HandlerFn]] = {
    (KERNEL_PERFINFO_GUID, 46): ("SampledProfile", _handle_sampled_profile_native),
}


@dataclass
class ExtractStats:
    """Diagnostic counters from a single :func:`extract_events` call."""

    event_count: int
    elapsed_seconds: float
    bytes_processed: int
    provider_counts: dict[str, int]
    decoded_counts: dict[str, int]
    events_lost: int


def extract_events(
    etl_paths: Path | str | Iterable[Path | str],
    *,
    event_classes: Optional[set[str]] = None,
    providers: Optional[set[str]] = None,
    stats_sink: Optional[list[ExtractStats]] = None,
) -> dict[str, pd.DataFrame]:
    """Native-mode equivalent of ``parsing.wpa_exporter.parse_dumper_events``.

    Parameters
    ----------
    etl_paths:
        Either a single path or an iterable. Single-path callers (the
        common case) can pass a ``Path`` / ``str`` directly.
    event_classes:
        Subset of :data:`CANONICAL_EVENT_CLASSES` to emit. Default: all
        classes (matching the ``parse_dumper_events`` contract — callers
        that want a smaller cut should pass it).
    providers:
        Optional provider-GUID filter. When set, events whose
        ``ProviderId`` is not in the set are dropped before dispatch.
        GUID strings must be lowercase (the format produced by
        :func:`bindings.types.guid_string`).
    stats_sink:
        If supplied, the call appends an :class:`ExtractStats` record so
        the caller can attribute counts to providers and decoded classes.
        Optional; used in tests.

    Returns
    -------
    dict[str, pd.DataFrame]
        One entry per requested canonical class. Empty DataFrames are
        returned for classes whose handler is not yet implemented — the
        caller does not need to special-case Phase N1's partial decoder
        coverage.
    """

    import time

    if isinstance(etl_paths, (str, Path)):
        paths_iter: Iterable[Path | str] = [etl_paths]
    else:
        paths_iter = list(etl_paths)

    requested = set(event_classes) if event_classes is not None else set(CANONICAL_EVENT_CLASSES)
    provider_filter: Optional[set[str]] = None
    if providers is not None:
        provider_filter = {g.lower() for g in providers}

    # Pre-build the result buckets. Even classes without handlers get a
    # bucket so the return shape is stable.
    rows_by_class: dict[str, list[NativeRowDict]] = {
        name: [] for name in requested
    }
    provider_counts: Counter[str] = Counter()
    decoded_counts: Counter[str] = Counter()

    # Restrict the handler dispatch to classes the caller asked for.
    active_handlers = {
        key: (canonical, fn)
        for key, (canonical, fn) in _HANDLERS.items()
        if canonical in requested
    }

    def on_event(record: EVENT_RECORD) -> None:
        guid = guid_string(record.EventHeader.ProviderId)
        provider_counts[guid] += 1
        if provider_filter is not None and guid not in provider_filter:
            return
        opcode = int(record.EventHeader.EventDescriptor.Opcode)
        key: HandlerKey = (guid, opcode)
        entry = active_handlers.get(key)
        if entry is None:
            return
        canonical, fn = entry
        try:
            row = fn(record)
        except Exception:
            # Defensive: a malformed payload should never break iteration.
            logger.debug("native handler %s raised", canonical, exc_info=True)
            return
        if row is None:
            return
        rows_by_class[canonical].append(row)
        decoded_counts[canonical] += 1

    start = time.perf_counter()
    with EtwConsumer(paths_iter, on_event) as cons:
        stats = cons.run()
    elapsed = time.perf_counter() - start

    if stats_sink is not None:
        stats_sink.append(
            ExtractStats(
                event_count=stats.event_count,
                elapsed_seconds=elapsed,
                bytes_processed=stats.bytes_processed,
                provider_counts=dict(provider_counts),
                decoded_counts=dict(decoded_counts),
                events_lost=stats.events_lost,
            )
        )

    return {
        name: pd.DataFrame(rows_by_class[name])
        for name in requested
    }


def count_events_by_provider(
    etl_path: Path | str,
    providers: Optional[set[str]] = None,
) -> dict[str, int]:
    """Run a stripped-down consumer that only counts events per provider.

    Used by the headline Phase N1 test to prove the architectural gap
    closure — TCPIP / AFD / MsQuic etc. all become visible. Returns a
    ``{provider_guid_lower: count}`` map.
    """

    counts: Counter[str] = Counter()
    provider_filter: Optional[set[str]] = None
    if providers is not None:
        provider_filter = {g.lower() for g in providers}

    def on_event(record: EVENT_RECORD) -> None:
        guid = guid_string(record.EventHeader.ProviderId)
        if provider_filter is not None and guid not in provider_filter:
            return
        counts[guid] += 1

    with EtwConsumer([etl_path], on_event) as cons:
        cons.run()
    return dict(counts)


__all__ = [
    "CANONICAL_EVENT_CLASSES",
    "ExtractStats",
    "extract_events",
    "count_events_by_provider",
]
