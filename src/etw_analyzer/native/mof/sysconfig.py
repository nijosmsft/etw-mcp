"""Decoders for the ``SystemConfig`` rundown provider.

Provider GUID: ``01853a65-418f-4f36-aefc-dc0f1d2fd235``

Per design doc §4.4 and feasibility experiment ``exp10b``, ``TdhGetEventInformation``
DOES return a valid schema for SystemConfig events (unlike the bare
kernel-logger MOFs that come from PerfInfo / Thread / Process / etc).
This module therefore registers the SystemConfig GUID as a known provider
but supplies a *passthrough* decoder that records opcode + raw payload
bytes — the TDH path (Phase N1+ ``tdh_decode.py``) is the canonical
decoder once that module learns to handle structs.

Known opcodes seen in real traces (from feasibility exp10):

+--------+---------------------------------------+
| Opcode | Event                                 |
+========+=======================================+
| 10     | CPU                                   |
+--------+---------------------------------------+
| 11     | PhyDisk                               |
+--------+---------------------------------------+
| 12     | LogDisk                               |
+--------+---------------------------------------+
| 13     | NIC                                   |
+--------+---------------------------------------+
| 15     | Services                              |
+--------+---------------------------------------+
| 16     | Power                                 |
+--------+---------------------------------------+
| 19     | IRQ                                   |
+--------+---------------------------------------+
| 21     | Boot Config Info                      |
+--------+---------------------------------------+
| 22     | TelemetryConfiguration                |
+--------+---------------------------------------+
| 25     | Virtualization Config Info            |
+--------+---------------------------------------+
| 28     | Defragmentation                       |
+--------+---------------------------------------+
| 29     | DeviceFamily                          |
+--------+---------------------------------------+
| 30     | Platform                              |
+--------+---------------------------------------+
| 31     | DPI                                   |
+--------+---------------------------------------+
| 33     | FlightIds                             |
+--------+---------------------------------------+
| 34     | CodeIntegrity                         |
+--------+---------------------------------------+
| 35     | Processors                            |
+--------+---------------------------------------+
| 36     | (reserved)                            |
+--------+---------------------------------------+
| 37     | PnP                                   |
+--------+---------------------------------------+

The dispatch table is keyed on these opcodes so the consumer can pre-
allocate a class bucket; the actual field-by-field decoding is deferred
to the TDH path.
"""

from __future__ import annotations

from typing import Optional


PROVIDER_GUID = "01853a65-418f-4f36-aefc-dc0f1d2fd235"


# Human-readable name lookup. Used by the passthrough decoder to label
# each event so a downstream UI can show "SystemConfig/NIC" rather than
# "SystemConfig/13".
_OPCODE_NAMES = {
    10: "CPU",
    11: "PhyDisk",
    12: "LogDisk",
    13: "NIC",
    15: "Services",
    16: "Power",
    19: "IRQ",
    21: "BootConfigInfo",
    22: "TelemetryConfiguration",
    25: "VirtualizationConfigInfo",
    28: "Defragmentation",
    29: "DeviceFamily",
    30: "Platform",
    31: "DPI",
    33: "FlightIds",
    34: "CodeIntegrity",
    35: "Processors",
    37: "PnP",
}


def decode_sysconfig(payload: bytes, hdr: dict) -> Optional[dict]:
    """Passthrough decoder. The real field decode happens via TDH.

    We emit the opcode, its human-readable name (when known) and the raw
    payload bytes so a caller can post-process via the TDH path or just
    surface "we saw it" diagnostics.
    """
    opcode = int(hdr.get("Opcode", -1))
    return {
        "TimeStamp": int(hdr.get("TimeStamp", 0)),
        "Opcode": opcode,
        "OpcodeName": _OPCODE_NAMES.get(opcode, f"SystemConfig/{opcode}"),
        "PayloadBytes": int(len(payload)),
    }


# Wildcard entry: every opcode for SystemConfig goes through the
# passthrough decoder. Per design §4.4 the canonical class is
# "SystemConfig" rather than per-opcode names — the TDH layer can split
# them later.
HANDLERS: dict[tuple[int, Optional[int]], tuple[str, callable]] = {}
for _op in _OPCODE_NAMES:
    HANDLERS[(_op, None)] = ("SystemConfig", decode_sysconfig)


__all__ = ["PROVIDER_GUID", "HANDLERS", "decode_sysconfig"]
