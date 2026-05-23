"""Binary MOF decoder for the ``StackWalk`` kernel provider.

Provider GUID: ``def2fe46-7bd6-4b80-bd94-f57fe20d0ce3``

A StackWalk event is the kernel-logger's way of attaching a call chain to
*another* event (typically the immediately-preceding SampledProfile, CSwitch
or DPC). Its payload starts with the original event's QPC timestamp, then a
PID and TID, then ``(UserDataLength - 16) / 8`` return addresses.

Pairing
-------
StackWalk events arrive AFTER the event they describe with the SAME
``EventTimeStamp`` (which lives in the first 8 bytes of the StackWalk
payload — NOT in the EVENT_HEADER, which carries the StackWalk's *own*
emit time). This was the discovery of feasibility experiment ``exp4c``:
``RAW_TIMESTAMP`` mode is required so both timestamps stay in QPC units,
and the join key is ``stack.payload_ts == sample.hdr_ts``.

The pairing itself happens in ``extract.py`` (it owns the LRU buffer of
pending events); this module just decodes the payload.
"""

from __future__ import annotations

import struct
from typing import Optional


PROVIDER_GUID = "def2fe46-7bd6-4b80-bd94-f57fe20d0ce3"


# Fixed header (16 bytes):
#   <Q      EventTimeStamp  (u64 QPC of the original event)
#   <I      StackProcess    (u32)
#   <I      StackThread     (u32)
_STACK_HDR = struct.Struct("<QII")
assert _STACK_HDR.size == 16


def decode_stack(payload: bytes, hdr: dict) -> Optional[dict]:
    """Decode a ``StackWalk/Stack`` (opcode 32) payload.

    Returns a dict with::

        EventTimeStamp  — QPC timestamp of the *paired* event
        ProcessId       — payload-supplied PID
        ThreadId        — payload-supplied TID
        Stack           — tuple[int, ...] of return addresses, leaf first
        CPU             — taken from BufferContext (StackWalk's own emit CPU)
        StackTimeStamp  — header timestamp (the StackWalk's own emit time)
    """
    if len(payload) < _STACK_HDR.size:
        return None

    event_ts, pid, tid = _STACK_HDR.unpack_from(payload, 0)
    n_frames = (len(payload) - _STACK_HDR.size) // 8

    if n_frames > 0:
        frames = struct.unpack_from(f"<{n_frames}Q", payload, _STACK_HDR.size)
    else:
        frames = ()

    cpu = hdr.get("ProcessorNumber")
    if cpu is None:
        cpu = hdr.get("CPU", -1)

    return {
        "EventTimeStamp": int(event_ts),
        "ProcessId": int(pid),
        "ThreadId": int(tid),
        "Stack": tuple(int(a) for a in frames),
        "CPU": int(cpu),
        "StackTimeStamp": int(hdr.get("TimeStamp", 0)),
    }


# Opcodes used for StackWalk. Stack (32) is the dominant one; the other
# values exist for differentiation between kernel/user stacks on some
# Windows builds. We decode all of them the same way — they share the
# layout above.
HANDLERS: dict[tuple[int, Optional[int]], tuple[str, callable]] = {
    (32, None): ("StackWalk", decode_stack),
}


__all__ = ["PROVIDER_GUID", "HANDLERS", "decode_stack"]
