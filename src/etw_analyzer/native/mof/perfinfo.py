"""Binary MOF decoders for the ``PerfInfo`` kernel provider.

Provider GUID: ``ce1dbfb4-137e-4da6-87b0-3f59aa102cbc``

Decoded events (design doc table, §4.1):

+--------+--------------------------+
| Opcode | Event                    |
+========+==========================+
| 46     | SampledProfile           |
+--------+--------------------------+
| 66     | DPC start (ThreadedDPC)  |
+--------+--------------------------+
| 67     | ISR                      |
+--------+--------------------------+
| 68     | DPC                      |
+--------+--------------------------+
| 69     | TimerDPC                 |
+--------+--------------------------+

Layouts come straight from the SDK ``wmicore.mof`` and were validated by the
``exp4c_stacks_pair`` feasibility experiment (the ``<Q`` for the instruction
pointer is identical to what xperf prints).

All payloads carry their timestamps and CPU in the surrounding
``EVENT_RECORD`` rather than in ``UserData`` — the decoders honour that and
take ``cpu`` from ``BufferContext.ProcessorNumber`` not the payload.
"""

from __future__ import annotations

import struct
from typing import Optional


PROVIDER_GUID = "ce1dbfb4-137e-4da6-87b0-3f59aa102cbc"


# SampledProfile payload (opcode 46) — 16 bytes.
#   <       little-endian
#   Q       InstructionPointer  (u64)
#   I       ThreadId            (u32)
#   I       Count               (u32) — sample weight, almost always 1
_SAMPLED_PROFILE = struct.Struct("<QII")
assert _SAMPLED_PROFILE.size == 16


# DPC / ISR payload (opcode 66/67/68/69) — 16 bytes.
#   <
#   Q       InitialTime  (u64, QPC)  — when the DPC/ISR started
#   Q       Routine      (u64, function address)
_DPC_ISR = struct.Struct("<QQ")
assert _DPC_ISR.size == 16


def decode_sampled_profile(payload: bytes, hdr: dict) -> Optional[dict]:
    """Decode a ``PerfInfo/SampledProfile`` (opcode 46) MOF payload.

    Returned dict matches the schema produced by
    ``parsing.wpa_exporter._handle_sampled_profile`` so downstream code is
    mode-agnostic::

        TimeStamp, Process Name, PID, CPU, Module, Function, Weight

    ``Process Name`` / ``Module`` / ``Function`` are blank — symbol
    resolution lives in Phase N3 (see design §6).
    """
    if len(payload) < _SAMPLED_PROFILE.size:
        return None
    ip, payload_tid, count = _SAMPLED_PROFILE.unpack_from(payload, 0)

    cpu = hdr.get("ProcessorNumber")
    if cpu is None:
        cpu = hdr.get("CPU", -1)

    # weight = max(1, count). A few WPR profiles emit Count=0 sentinel,
    # which would make every aggregation produce zero rows.
    weight = int(count) if count > 0 else 1

    return {
        "TimeStamp": int(hdr.get("TimeStamp", 0)),
        "Process Name": "",
        "PID": int(hdr.get("ProcessId", 0)),
        "CPU": int(cpu),
        "Module": "",
        "Function": "",
        "Weight": weight,
        # The IP and per-payload TID are kept around so Phase N3
        # symbolisation can resolve module!function pairs without
        # re-reading the trace.
        "InstructionPointer": int(ip),
        "PayloadThreadId": int(payload_tid),
    }


def _decode_dpc_isr_common(payload: bytes, hdr: dict, opcode_name: str) -> Optional[dict]:
    if len(payload) < _DPC_ISR.size:
        return None
    initial_time, routine = _DPC_ISR.unpack_from(payload, 0)

    cpu = hdr.get("ProcessorNumber")
    if cpu is None:
        cpu = hdr.get("CPU", -1)

    return {
        "TimeStamp": int(hdr.get("TimeStamp", 0)),
        "CPU": int(cpu),
        "InitialTime": int(initial_time),
        "Routine": int(routine),
        "Type": opcode_name,
        # Resolved later (Phase N3) — keep the slots so the schema is stable.
        "Module": "",
        "Function": "",
    }


def decode_dpc(payload: bytes, hdr: dict) -> Optional[dict]:
    """Decode a ``PerfInfo/DPC`` (opcode 68) — a regular deferred-procedure
    call. Pairs with the routine start opcode (66) by ``(cpu, Routine)``."""
    return _decode_dpc_isr_common(payload, hdr, "DPC")


def decode_dpc_threaded(payload: bytes, hdr: dict) -> Optional[dict]:
    """Decode a ``PerfInfo/ThreadedDPC`` (opcode 66) DPC start marker."""
    return _decode_dpc_isr_common(payload, hdr, "ThreadedDPC")


def decode_dpc_timer(payload: bytes, hdr: dict) -> Optional[dict]:
    """Decode a ``PerfInfo/TimerDPC`` (opcode 69)."""
    return _decode_dpc_isr_common(payload, hdr, "TimerDPC")


def decode_isr(payload: bytes, hdr: dict) -> Optional[dict]:
    """Decode a ``PerfInfo/ISR`` (opcode 67) interrupt service routine."""
    return _decode_dpc_isr_common(payload, hdr, "ISR")


# (opcode, version) -> (canonical_class, decoder_fn)
# Version ``None`` is the wildcard fallback per design §4.3.
HANDLERS: dict[tuple[int, Optional[int]], tuple[str, callable]] = {
    (46, None): ("SampledProfile", decode_sampled_profile),
    (66, None): ("PerfInfo/ThreadedDPC", decode_dpc_threaded),
    (67, None): ("PerfInfo/ISR", decode_isr),
    (68, None): ("PerfInfo/DPC", decode_dpc),
    (69, None): ("PerfInfo/TimerDPC", decode_dpc_timer),
}


__all__ = [
    "PROVIDER_GUID",
    "HANDLERS",
    "decode_sampled_profile",
    "decode_dpc",
    "decode_dpc_threaded",
    "decode_dpc_timer",
    "decode_isr",
]
