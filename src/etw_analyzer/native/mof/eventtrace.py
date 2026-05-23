"""Binary MOF decoders for the ``EventTrace`` metadata events.

Provider GUID: ``68fdd900-4a3e-11d1-84f4-0000f80464e3``

These are the synthetic header / rundown / extension events ETW prepends
to every kernel-logger trace. They are mostly used for bookkeeping (the
``LogfileHeader`` already exposes everything we need), but we still
register decoders so the dispatch table is complete and so the
``__providers__`` debug counter doesn't miscount them as "unknown".

+--------+--------------------------+
| Opcode | Event                    |
+========+==========================+
| 0      | EventTrace/Header        |
+--------+--------------------------+
| 5      | Extension                |
+--------+--------------------------+
| 8      | RDComplete               |
+--------+--------------------------+
| 16     | EndExtension             |
+--------+--------------------------+
| 32     | PartitionInfoExtension   |
+--------+--------------------------+

Only the header opcode carries a typed payload; the others are mostly
fixed-byte markers we surface as opaque dicts.
"""

from __future__ import annotations

import struct
from typing import Optional


PROVIDER_GUID = "68fdd900-4a3e-11d1-84f4-0000f80464e3"


# EventTrace/Header — large fixed payload. We only decode the first
# few fields and treat the rest as opaque; ``TRACE_LOGFILE_HEADER``
# already gives the same data via the consumer.
#
# Layout (SDK ``_EventTrace_Header``):
#   <I      BufferSize
#   <I      Version
#   <I      ProviderVersion
#   <I      NumberOfProcessors
#   <q      EndTime         (FILETIME)
#   <I      TimerResolution
#   <I      MaxFileSize
#   <I      LogFileMode
#   <I      BuffersWritten
#   <I      StartBuffers
#   <I      PointerSize
#   <I      EventsLost
#   <I      CpuSpeedInMHz
_HEADER = struct.Struct("<IIIIqIIIIIIII")
assert _HEADER.size == 56


def decode_header(payload: bytes, hdr: dict) -> Optional[dict]:
    """Decode an ``EventTrace/Header`` opcode 0 payload (first 60 bytes)."""
    if len(payload) < _HEADER.size:
        return None
    (
        buffer_size,
        version,
        provider_version,
        num_processors,
        end_time,
        timer_resolution,
        max_file_size,
        log_file_mode,
        buffers_written,
        start_buffers,
        pointer_size,
        events_lost,
        cpu_speed_mhz,
    ) = _HEADER.unpack_from(payload, 0)
    return {
        "TimeStamp": int(hdr.get("TimeStamp", 0)),
        "BufferSize": int(buffer_size),
        "Version": int(version),
        "ProviderVersion": int(provider_version),
        "NumberOfProcessors": int(num_processors),
        "EndTime": int(end_time),
        "TimerResolution": int(timer_resolution),
        "MaximumFileSize": int(max_file_size),
        "LogFileMode": int(log_file_mode),
        "BuffersWritten": int(buffers_written),
        "StartBuffers": int(start_buffers),
        "PointerSize": int(pointer_size),
        "EventsLost": int(events_lost),
        "CpuSpeedInMHz": int(cpu_speed_mhz),
    }


def decode_rdcomplete(payload: bytes, hdr: dict) -> Optional[dict]:
    """Decode an ``EventTrace/RDComplete`` (opcode 8). Empty payload by spec."""
    return {
        "TimeStamp": int(hdr.get("TimeStamp", 0)),
        "Type": "RDComplete",
        "PayloadBytes": int(len(payload)),
    }


def decode_extension(payload: bytes, hdr: dict) -> Optional[dict]:
    """Decode an ``EventTrace/Extension`` (opcode 5). Opaque payload."""
    return {
        "TimeStamp": int(hdr.get("TimeStamp", 0)),
        "Type": "Extension",
        "PayloadBytes": int(len(payload)),
    }


def decode_end_extension(payload: bytes, hdr: dict) -> Optional[dict]:
    return {
        "TimeStamp": int(hdr.get("TimeStamp", 0)),
        "Type": "EndExtension",
        "PayloadBytes": int(len(payload)),
    }


def decode_partition_info(payload: bytes, hdr: dict) -> Optional[dict]:
    return {
        "TimeStamp": int(hdr.get("TimeStamp", 0)),
        "Type": "PartitionInfoExtension",
        "PayloadBytes": int(len(payload)),
    }


HANDLERS: dict[tuple[int, Optional[int]], tuple[str, callable]] = {
    (0, None): ("EventTrace/Header", decode_header),
    (5, None): ("EventTrace/Extension", decode_extension),
    (8, None): ("EventTrace/RDComplete", decode_rdcomplete),
    (16, None): ("EventTrace/EndExtension", decode_end_extension),
    (32, None): ("EventTrace/PartitionInfoExtension", decode_partition_info),
}


__all__ = [
    "PROVIDER_GUID",
    "HANDLERS",
    "decode_header",
    "decode_rdcomplete",
    "decode_extension",
]
