"""Native-mode extract pipeline.

Phase N2 expands the Phase N1 shell into a working extractor for the
~15 kernel-logger providers covered by ``native/mof/``. Manifest
providers (TCPIP / AFD / MsQuic / HttpService) still wait on the
Phase N1 TDH path to grow struct-aware decoding.

What this module does:

1. Walks the trace via :class:`EtwConsumer` once.
2. For every event, looks up ``(provider_guid, opcode, version)`` in a
   pre-built dispatch table populated by :func:`mof.register_kernel_handlers`.
3. Decodes via the matching MOF handler, attaches CPU / TimeStamp /
   ProcessId / ThreadId from the event record header.
4. Pairs ``StackWalk`` events with the prior ``SampledProfile`` /
   ``CSwitch`` / etc. event on the same QPC timestamp via a small LRU
   ring buffer (feasibility ``exp4c`` showed the join key works under
   ``PROCESS_TRACE_MODE_RAW_TIMESTAMP``).
5. Buckets row dicts into the canonical-class DataFrame map so the
   ``_DUMPER_EVENT_CLASSES`` consumer in ``tools.trace_mgmt`` can use
   them without special-casing the mode.

The dispatch table is keyed on ``(guid, opcode, version)`` with a
``(guid, opcode, None)`` wildcard fallback for version-agnostic
decoders (most kernel events).
"""

from __future__ import annotations

import ctypes
import logging
import time
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Optional

import pandas as pd

from .bindings.types import EVENT_RECORD, guid_string
from .consumer import EtwConsumer, NativeConsumerError
from .decoder import TdhDecoder
from .manifest import MANIFEST_PROVIDERS, lookup as manifest_lookup
from .mof import kernel_provider_guids, register_kernel_handlers


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Canonical event-class names — must stay in lockstep with
# ``parsing.wpa_exporter.EVENT_HANDLERS`` and
# ``tools.trace_mgmt._DUMPER_EVENT_CLASSES``.
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


# Additional kernel canonical classes the MOF tree decodes that aren't in
# the dumper class list. They land in result keys, but the trace-mgmt
# layer will only persist the ones it knows about. Keeping them visible
# helps tests assert that decode coverage is wide.
KERNEL_AUXILIARY_CLASSES: tuple[str, ...] = (
    "StackWalk",
    "PerfInfo/DPC",
    "PerfInfo/ThreadedDPC",
    "PerfInfo/TimerDPC",
    "PerfInfo/ISR",
    "Thread/Start",
    "Thread/End",
    "Thread/DCStart",
    "Thread/DCEnd",
    "Thread/SetName",
    "ReadyThread",
    "Process/Start",
    "Process/End",
    "Process/DCStart",
    "Process/DCEnd",
    "Process/Defunct",
    "Image/Load",
    "Image/Unload",
    "Image/DCStart",
    "Image/DCEnd",
    "Image/KernelBase",
    "Image/HypercallPage",
    "DiskIo/Read",
    "DiskIo/Write",
    "DiskIo/FlushBuffers",
    "FileIo/Name",
    "FileIo/Create",
    "FileIo/Read",
    "FileIo/Write",
    "FileIo/Close",
    "EventTrace/Header",
    "EventTrace/Extension",
    "EventTrace/RDComplete",
    "EventTrace/EndExtension",
    "EventTrace/PartitionInfoExtension",
    "SystemConfig",
)


# Build the kernel-MOF dispatch table once at import time. Keyed on
# (provider_guid_lower, opcode, version_or_None).
_DISPATCH: dict[tuple[str, int, Optional[int]], tuple[str, Callable]] = {}
register_kernel_handlers(_DISPATCH)


# Kernel-MOF provider GUIDs — we pre-mark these on every TdhDecoder
# instance so TdhGetEventInformation isn't called per kernel event
# (which is the bulk of every trace). The first event from a non-kernel
# provider still pays the GUID-formatting cost once.
_KERNEL_PROVIDER_GUIDS: frozenset[str] = frozenset(kernel_provider_guids())


def _lookup_handler(
    guid: str, opcode: int, version: Optional[int]
) -> Optional[tuple[str, Callable]]:
    """Look up a dispatch entry with version-fallback per design §4.3.

    Tries the version-specific key first, then the wildcard (version=None).
    Most kernel decoders register under the wildcard; CSwitch v=5 vs v=4
    is handled inside its decoder rather than by separate dispatch entries.
    """
    if version is not None:
        entry = _DISPATCH.get((guid, opcode, version))
        if entry is not None:
            return entry
    return _DISPATCH.get((guid, opcode, None))


# ---------------------------------------------------------------------------
# Stack-walk pairing buffer.
# ---------------------------------------------------------------------------
# StackWalk events arrive after the event they describe, with the same
# QPC timestamp. We retain the row dicts emitted by the most recent N
# "stackable" events (SampledProfile, CSwitch, DPC, ISR) keyed by
# (TimeStamp, ThreadId). When a Stack event arrives, we pop its match
# and attach the address list to the row's ``Stack`` column.
#
# 1024 keeps the buffer cheap (~64KB) and easily covers the burstiness
# we've seen: stack events arrive within a handful of events of their
# pair. If the trace overruns this window the event ships without a
# stack — same behaviour as xperf when symcache trimming hits.
_PENDING_STACK_CAPACITY = 1024

# Classes whose rows are eligible to receive a Stack. Tied to the
# stack-walking flag set on the kernel logger: SampledProfile gets
# stacks unconditionally; DPC/ISR/CSwitch get them when the
# corresponding flag was set at trace capture time.
_STACKABLE_CLASSES: frozenset[str] = frozenset({
    "SampledProfile",
    "CSwitch",
    "ReadyThread",
    "PerfInfo/DPC",
    "PerfInfo/ThreadedDPC",
    "PerfInfo/TimerDPC",
    "PerfInfo/ISR",
})


NativeRowDict = dict


@dataclass
class ExtractStats:
    """Diagnostic counters from a single :func:`extract_events` call."""

    event_count: int
    elapsed_seconds: float
    bytes_processed: int
    provider_counts: dict[str, int]
    decoded_counts: dict[str, int]
    events_lost: int
    stacks_paired: int
    stacks_orphan: int
    tdh_schemas_cached: int = 0
    tdh_negative_cached: int = 0


def _header_to_dict(record: EVENT_RECORD) -> dict:
    """Pull the canonical header fields out of an EVENT_RECORD.

    These are what every MOF decoder needs (kernel events typically don't
    repeat them inside the payload). We avoid creating the dict
    per-decoder-call by extracting them once here.
    """
    hdr = record.EventHeader
    return {
        "TimeStamp": int(hdr.TimeStamp),
        "ProcessorNumber": int(record.BufferContext.U.BC.ProcessorNumber),
        "ProcessId": int(hdr.ProcessId),
        "ThreadId": int(hdr.ThreadId),
        "Opcode": int(hdr.EventDescriptor.Opcode),
        "Version": int(hdr.EventDescriptor.Version),
    }


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
        Either a single path or an iterable.
    event_classes:
        Subset of canonical classes to emit. Defaults to the full
        :data:`CANONICAL_EVENT_CLASSES` set. Kernel auxiliary classes
        (StackWalk, Process/*, Image/*, etc.) are always decoded — they're
        cheap to capture and useful for diagnostics — but a class that
        isn't in this set returns an empty DataFrame.
    providers:
        Optional provider-GUID filter. Events whose ``ProviderId`` isn't
        in the set are dropped before dispatch. GUID strings must be
        lowercase.
    stats_sink:
        If supplied, the call appends an :class:`ExtractStats` record.

    Returns
    -------
    dict[str, pd.DataFrame]
        One entry per requested canonical class plus every auxiliary
        kernel class the MOF tree decoded.
    """
    if isinstance(etl_paths, (str, Path)):
        paths_iter: Iterable[Path | str] = [etl_paths]
    else:
        paths_iter = list(etl_paths)

    requested = set(event_classes) if event_classes is not None else set(CANONICAL_EVENT_CLASSES)
    provider_filter: Optional[set[str]] = None
    if providers is not None:
        provider_filter = {g.lower() for g in providers}

    # Output buckets. Requested classes always appear so the return shape
    # is stable. Auxiliary classes are appended on first decode.
    rows_by_class: dict[str, list[NativeRowDict]] = {name: [] for name in requested}
    provider_counts: Counter[str] = Counter()
    decoded_counts: Counter[str] = Counter()

    # LRU pairing buffer for StackWalk events.
    pending: "OrderedDict[tuple[int, int], NativeRowDict]" = OrderedDict()
    stacks_paired = 0
    stacks_orphan = 0

    # TDH-based manifest decoder. We instantiate lazily — many traces
    # will never need it (pure kernel-logger captures) and creating it
    # is cheap but pre-marking the kernel providers takes a couple of
    # microseconds we'd rather skip.
    tdh_decoder: Optional[TdhDecoder] = None

    def _ensure_tdh() -> TdhDecoder:
        nonlocal tdh_decoder
        if tdh_decoder is None:
            tdh_decoder = TdhDecoder()
            for kg in _KERNEL_PROVIDER_GUIDS:
                tdh_decoder.mark_provider_skip(kg)
        return tdh_decoder

    def _record_class(canonical: str, row: NativeRowDict) -> None:
        bucket = rows_by_class.get(canonical)
        if bucket is None:
            bucket = []
            rows_by_class[canonical] = bucket
        bucket.append(row)
        decoded_counts[canonical] += 1

    def on_event(record: EVENT_RECORD) -> None:
        nonlocal stacks_paired, stacks_orphan

        guid = guid_string(record.EventHeader.ProviderId)
        provider_counts[guid] += 1
        if provider_filter is not None and guid not in provider_filter:
            return

        opcode = int(record.EventHeader.EventDescriptor.Opcode)
        version = int(record.EventHeader.EventDescriptor.Version)
        entry = _lookup_handler(guid, opcode, version)

        # Pull payload bytes. ``ctypes.string_at`` is cheap (memcpy into a
        # bytes object), and the buffer is reused by ETW after the
        # callback returns so we can't keep a pointer.
        payload_len = int(record.UserDataLength)
        if payload_len and record.UserData:
            try:
                payload = ctypes.string_at(record.UserData, payload_len)
            except OSError:
                return
        else:
            payload = b""

        hdr = _header_to_dict(record)

        if entry is not None:
            canonical, fn = entry
            try:
                row = fn(payload, hdr)
            except Exception:
                logger.debug("MOF decoder for %s raised", canonical, exc_info=True)
                return
            if row is None:
                return
        else:
            # No kernel-MOF handler — try the TDH path. The manifest
            # registry is keyed on (guid, event_id) so the dispatch is
            # version-agnostic; the mapper itself tolerates field-name
            # drift across manifest versions.
            event_id = int(record.EventHeader.EventDescriptor.Id)
            manifest_entry = manifest_lookup(guid, event_id)
            if manifest_entry is None:
                return
            canonical, mapper = manifest_entry
            decoder = _ensure_tdh()
            try:
                fields = decoder.decode_event(record)
            except Exception:
                logger.debug(
                    "TDH decode for (%s,%d) raised", guid, event_id, exc_info=True
                )
                return
            if fields is None:
                # TDH had no manifest — probably a misregistered ID.
                return
            try:
                row = mapper(fields, hdr, payload, decoder)
            except Exception:
                logger.debug(
                    "Manifest mapper for %s raised", canonical, exc_info=True
                )
                return
            if row is None:
                return

        # StackWalk: pair against the pending buffer instead of buffering
        # by itself. The decoded row has ``EventTimeStamp`` (the QPC of
        # the event being annotated) and ``ThreadId`` (payload-supplied);
        # the pairing key is the event TimeStamp (preceding event's
        # header TimeStamp == this StackWalk's EventTimeStamp).
        if canonical == "StackWalk":
            target_ts = int(row.get("EventTimeStamp", 0))
            # First try the (ts, tid) join; on miss fall back to ts-only
            # because some kernel events emit TID=0 in the header but
            # carry it in the payload.
            target_tid = int(row.get("ThreadId", 0))
            paired_row = pending.pop((target_ts, target_tid), None)
            if paired_row is None:
                # Fall back: scan pending for any entry sharing this ts.
                for k in list(pending.keys()):
                    if k[0] == target_ts:
                        paired_row = pending.pop(k)
                        break
            if paired_row is not None:
                paired_row["Stack"] = row["Stack"]
                stacks_paired += 1
            else:
                stacks_orphan += 1
            # We still emit the StackWalk row for diagnostics. Many
            # callers ignore it, but having the column means tests can
            # assert pairing rates without reading internal state.
            _record_class(canonical, row)
            return

        # For events that may be followed by a stack: stash a reference
        # in the pending buffer keyed by (TimeStamp, ThreadId). The
        # reference is the row dict itself so the StackWalk handler can
        # mutate it in-place.
        if canonical in _STACKABLE_CLASSES:
            row.setdefault("Stack", None)
            key = (int(hdr["TimeStamp"]), int(hdr["ThreadId"]))
            pending[key] = row
            # Evict the oldest entries to keep the buffer bounded.
            while len(pending) > _PENDING_STACK_CAPACITY:
                pending.popitem(last=False)

        _record_class(canonical, row)

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
                stacks_paired=stacks_paired,
                stacks_orphan=stacks_orphan,
                tdh_schemas_cached=(tdh_decoder.schema_count() if tdh_decoder else 0),
                tdh_negative_cached=(tdh_decoder.negative_count() if tdh_decoder else 0),
            )
        )

    # Build the result map. Every requested class is present (empty
    # DataFrame if nothing decoded). Auxiliary classes (StackWalk,
    # Image/Load, etc.) are *also* returned when the caller hasn't pinned
    # the result to a specific subset — otherwise the explicit filter
    # wins and we drop the auxiliaries to keep the result shape minimal.
    result: dict[str, pd.DataFrame] = {}
    for name in requested:
        result[name] = pd.DataFrame(rows_by_class.get(name, []))
    if event_classes is None:
        for name, rows in rows_by_class.items():
            if name in result:
                continue
            result[name] = pd.DataFrame(rows)

    return result


def count_events_by_provider(
    etl_path: Path | str,
    providers: Optional[set[str]] = None,
) -> dict[str, int]:
    """Run a stripped-down consumer that only counts events per provider.

    Same as Phase N1 — kept here so existing tests don't move.
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
    "KERNEL_AUXILIARY_CLASSES",
    "ExtractStats",
    "extract_events",
    "count_events_by_provider",
]
