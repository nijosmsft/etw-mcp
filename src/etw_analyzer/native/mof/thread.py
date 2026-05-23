"""Binary MOF decoders for the ``Thread`` kernel provider.

Provider GUID: ``3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c``

Decoded events:

+--------+--------------------+
| Opcode | Event              |
+========+====================+
| 1      | Thread/Start       |
+--------+--------------------+
| 2      | Thread/End         |
+--------+--------------------+
| 3      | Thread/DCStart     |
+--------+--------------------+
| 4      | Thread/DCEnd       |
+--------+--------------------+
| 36     | CSwitch (v=4/v=5)  |
+--------+--------------------+
| 50     | ReadyThread        |
+--------+--------------------+
| 72     | Thread/SetName     |
+--------+--------------------+

CSwitch (the high-frequency one) is delegated to the existing decoder in
``parsing.mof_cswitch`` so this module doesn't fork its enum tables. The
Start/End/SetName events have ImageFileName / ThreadName tails the
existing CSwitch decoder doesn't need.
"""

from __future__ import annotations

import struct
from typing import Optional

from etw_analyzer.parsing.mof_cswitch import decode_cswitch_v5


PROVIDER_GUID = "3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c"


# Thread/Start, /End, /DCStart, /DCEnd payload — modern packed layout on
# 64-bit Windows. The SDK MOF documents several versions across builds;
# we lock to the v=3 / v=4 layout that ships on Win10+ kernel logger.
#
# Captured payloads have proved the following packed offsets:
#
#   off  len  field
#   0    4    ProcessId
#   4    4    TThreadId   (TThreadId is the kernel name for ThreadId)
#   8    8    StackBase
#   16   8    StackLimit
#   24   8    UserStackBase
#   32   8    UserStackLimit
#   40   8    StartAddr
#   48   8    Win32StartAddr
#   56   8    TebBase
#   64   4    SubProcessTag
#   68   1    BasePriority
#   69   1    PagePriority
#   70   1    IoPriority
#   71   1    ThreadFlags
#   72+  …    ThreadName (UTF-16, null-terminated, optional)
#
# Some older builds omit the SubProcessTag + priority bytes; we treat the
# fixed prefix as the 64 bytes through TebBase and pull the trailing
# fields defensively.
_THREAD_HDR = struct.Struct("<II")            # PID, TID
_THREAD_PTRS = struct.Struct("<QQQQQQQ")      # 7 pointer-sized fields
assert _THREAD_HDR.size == 8
assert _THREAD_PTRS.size == 56
_THREAD_FIXED_MIN = _THREAD_HDR.size + _THREAD_PTRS.size  # 64 bytes


# Thread/ReadyThread payload (opcode 50, v=2).
# 8 bytes:
#   <I      TThreadId          (u32)
#   <b      AdjustReason       (i8)
#   <b      AdjustIncrement    (i8)
#   <H      Flag + padding     (u16)
_READY_THREAD = struct.Struct("<IbbH")
assert _READY_THREAD.size == 8


def _read_utf16_z(payload: bytes, offset: int) -> str:
    """Read a UTF-16-LE null-terminated string starting at ``offset``.

    The kernel MOFs trail their fixed payload with a UTF-16 ImageFileName
    or ThreadName. Strings may also be missing entirely (the payload ends
    at the fixed-size boundary) — return "" in that case.
    """
    end = len(payload)
    # Walk in 2-byte steps looking for a U+0000.
    i = offset
    while i + 1 < end:
        if payload[i] == 0 and payload[i + 1] == 0:
            break
        i += 2
    raw = payload[offset:i]
    try:
        return raw.decode("utf-16-le", errors="replace")
    except UnicodeDecodeError:
        return ""


def decode_thread_start_end(payload: bytes, hdr: dict) -> Optional[dict]:
    """Decode a Thread Start/End/DCStart/DCEnd payload.

    The four opcodes share the same body — we set ``Type`` so the writer
    can demultiplex without inspecting the raw event record again.
    """
    if len(payload) < _THREAD_FIXED_MIN:
        return None

    process_id, thread_id = _THREAD_HDR.unpack_from(payload, 0)
    (
        stack_base,
        stack_limit,
        user_stack_base,
        user_stack_limit,
        start_addr,
        win32_start_addr,
        teb_base,
    ) = _THREAD_PTRS.unpack_from(payload, _THREAD_HDR.size)

    # Optional trailing fields (some builds omit them).
    sub_process_tag = 0
    base_pri = page_pri = io_pri = thread_flags = 0
    name_offset = _THREAD_FIXED_MIN
    if len(payload) >= _THREAD_FIXED_MIN + 8:
        sub_process_tag = struct.unpack_from("<I", payload, _THREAD_FIXED_MIN)[0]
        base_pri = payload[_THREAD_FIXED_MIN + 4]
        page_pri = payload[_THREAD_FIXED_MIN + 5]
        io_pri = payload[_THREAD_FIXED_MIN + 6]
        thread_flags = payload[_THREAD_FIXED_MIN + 7]
        name_offset = _THREAD_FIXED_MIN + 8

    thread_name = _read_utf16_z(payload, name_offset)

    cpu = hdr.get("ProcessorNumber")
    if cpu is None:
        cpu = hdr.get("CPU", -1)

    return {
        "TimeStamp": int(hdr.get("TimeStamp", 0)),
        "CPU": int(cpu),
        "ProcessId": int(process_id),
        "ThreadId": int(thread_id),
        "StackBase": int(stack_base),
        "StackLimit": int(stack_limit),
        "UserStackBase": int(user_stack_base),
        "UserStackLimit": int(user_stack_limit),
        "StartAddr": int(start_addr),
        "Win32StartAddr": int(win32_start_addr),
        "TebBase": int(teb_base),
        "SubProcessTag": int(sub_process_tag),
        "BasePriority": int(base_pri),
        "PagePriority": int(page_pri),
        "IoPriority": int(io_pri),
        "ThreadFlags": int(thread_flags),
        "ThreadName": thread_name,
    }


def decode_ready_thread(payload: bytes, hdr: dict) -> Optional[dict]:
    """Decode a ``Thread/ReadyThread`` (opcode 50) payload.

    The ReadyThread event signals that the kernel scheduler has placed a
    thread in the ready queue. ``AdjustReason`` is the priority-boost
    reason enum (``KPRIORITY_BOOST_REASON``); ``AdjustIncrement`` is the
    boost amount.
    """
    if len(payload) < _READY_THREAD.size:
        return None

    tid, adjust_reason, adjust_increment, flag = _READY_THREAD.unpack_from(payload, 0)

    cpu = hdr.get("ProcessorNumber")
    if cpu is None:
        cpu = hdr.get("CPU", -1)

    return {
        "TimeStamp": int(hdr.get("TimeStamp", 0)),
        "CPU": int(cpu),
        "ThreadId": int(tid),
        "AdjustReason": int(adjust_reason),
        "AdjustIncrement": int(adjust_increment),
        "Flag": int(flag) & 0xFF,
    }


def decode_thread_set_name(payload: bytes, hdr: dict) -> Optional[dict]:
    """Decode a ``Thread/SetName`` (opcode 72) payload.

    Layout: ProcessId (u32) + ThreadId (u32) + UTF-16 name.
    """
    if len(payload) < 8:
        return None
    pid, tid = struct.unpack_from("<II", payload, 0)
    name = _read_utf16_z(payload, 8)

    cpu = hdr.get("ProcessorNumber")
    if cpu is None:
        cpu = hdr.get("CPU", -1)

    return {
        "TimeStamp": int(hdr.get("TimeStamp", 0)),
        "CPU": int(cpu),
        "ProcessId": int(pid),
        "ThreadId": int(tid),
        "ThreadName": name,
    }


HANDLERS: dict[tuple[int, Optional[int]], tuple[str, callable]] = {
    (1, None): ("Thread/Start", decode_thread_start_end),
    (2, None): ("Thread/End", decode_thread_start_end),
    (3, None): ("Thread/DCStart", decode_thread_start_end),
    (4, None): ("Thread/DCEnd", decode_thread_start_end),
    # CSwitch uses the existing decoder. The version-specific wildcard
    # lets v=4 / v=5 / v=6 (future) all hit the same entry point.
    (36, None): ("CSwitch", decode_cswitch_v5),
    (50, None): ("ReadyThread", decode_ready_thread),
    (72, None): ("Thread/SetName", decode_thread_set_name),
}


__all__ = [
    "PROVIDER_GUID",
    "HANDLERS",
    "decode_thread_start_end",
    "decode_ready_thread",
    "decode_thread_set_name",
]
