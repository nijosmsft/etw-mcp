"""Binary MOF decoder for the kernel Thread/CSwitch (v=5) event.

Background
==========
The Windows kernel logger ``Thread`` provider emits ``CSwitch`` events
(GUID ``3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c``, opcode 36). The payload is
a hand-coded MOF struct — TDH has no schema for it (``TdhGetEventInformation``
returns ``ERROR_NOT_FOUND``), so anything decoding kernel-MOF events needs
the layout in code.

The current ``wpa_exporter._handle_cswitch`` shells out to ``xperf -a dumper``
and CSV-parses the text. The column layout in real builds drifted: newer
xperf builds insert a ``TmSinceLast`` column at position 6 (between ``NQnt``
and ``WaitTime``), pushing everything after it right by one. The old parser
read ``parts[8]`` for ``Old TID`` but ``parts[8]`` is now ``Old Process Name``,
so the integer parse fails and every CSwitch row is silently dropped. This
module is the proof of concept for replacing that text path with the binary
MOF layout.

Decoder API
===========
:func:`decode_cswitch_v5` decodes a single CSwitch payload into a row dict
in the same shape ``_handle_cswitch`` produces — but with the binary layout's
extra fields (``WaitMode``, ``Extra4``) preserved so future investigation
isn't blocked. The caller supplies the ``EVENT_HEADER`` fields
(``TimeStamp``, ``CPU``, ``ProcessId``, ``ThreadId``) since they live outside
the payload.

Binary layout (28 bytes for v=5; v=4 is 24 bytes and omits the trailing
``Extra4``). Verified from
``C:\\temp\\etw-feasibility\\exp3b_cswitch_manual.py`` and
``exp3b_cswitch_manual.out.txt``.

+-----+-----+-------------------------------+-------+
| off | len | field                         | type  |
+=====+=====+===============================+=======+
| 0   | 4   | NewThreadId                   | u32   |
| 4   | 4   | OldThreadId                   | u32   |
| 8   | 1   | NewThreadPriority             | i8    |
| 9   | 1   | OldThreadPriority             | i8    |
| 10  | 1   | PreviousCState                | u8    |
| 11  | 1   | SpareByte                     | i8    |
| 12  | 1   | OldThreadWaitReason           | i8    |
| 13  | 1   | OldThreadWaitMode             | i8    |
| 14  | 1   | OldThreadState                | i8    |
| 15  | 1   | OldThreadWaitIdealProcessor   | i8    |
| 16  | 4   | NewThreadWaitTime             | u32   |
| 20  | 4   | Reserved                      | u32   |
| 24  | 4   | Extra4 (v=5 only)             | u32   |
+-----+-----+-------------------------------+-------+

The 4-byte ``Extra4`` is not in the Windows SDK MOF that TDH knows about.
Feasibility data shows it always small (2 / 8 in the captured samples); the
design doc speculates ``CycleTime``-low or ``SwitchTime``-low half. We surface
it rather than drop it — the column will be ``None`` on the xperf-text adapter
path (text doesn't include it) and an integer on the binary path.

WaitReason / WaitMode / State enum tables come from the kernel ``WAIT_REASON``
/ ``KWAIT_REASON`` / ``KTHREAD_STATE`` enums in ntdef.h. The values match
what xperf prints in its dumper output so the binary and text paths produce
equivalent strings.
"""

from __future__ import annotations

import struct
from typing import Optional


# ---------------------------------------------------------------------------
# Kernel enums (values must match what xperf prints in dumper text output).
# ---------------------------------------------------------------------------

# WAIT_REASON (`ntdef.h`). Matches the names ``xperf -a dumper`` prints in
# the ``Wait Reason`` column.
_WAIT_REASON: tuple[str, ...] = (
    "Executive",          # 0
    "FreePage",           # 1
    "PageIn",             # 2
    "PoolAllocation",     # 3
    "DelayExecution",     # 4
    "Suspended",          # 5
    "UserRequest",        # 6
    "WrExecutive",        # 7
    "WrFreePage",         # 8
    "WrPageIn",           # 9
    "WrPoolAllocation",   # 10
    "WrDelayExecution",   # 11
    "WrSuspended",        # 12
    "WrUserRequest",      # 13
    "WrEventPair",        # 14
    "WrQueue",            # 15
    "WrLpcReceive",       # 16
    "WrLpcReply",         # 17
    "WrVirtualMemory",    # 18
    "WrPageOut",          # 19
    "WrRendezvous",       # 20
    "WrKeyedEvent",       # 21
    "WrTerminated",       # 22
    "WrProcessInSwap",    # 23
    "WrCpuRateControl",   # 24
    "WrCalloutStack",     # 25
    "WrKernel",           # 26
    "WrResource",         # 27
    "WrPushLock",         # 28
    "WrMutex",            # 29
    "WrQuantumEnd",       # 30
    "WrDispatchInt",      # 31
    "WrPreempted",        # 32
    "WrYieldExecution",   # 33
    "WrFastMutex",        # 34
    "WrGuardedMutex",     # 35
    "WrRundown",          # 36
    "WrAlertByThreadId",  # 37
    "WrDeferredPreempt",  # 38
    "WrPhysicalFault",    # 39
)

# KPROCESSOR_MODE: KernelMode=0, UserMode=1.
_WAIT_MODE: tuple[str, ...] = ("KernelMode", "UserMode")

# KTHREAD_STATE.
_THREAD_STATE: tuple[str, ...] = (
    "Initialized",  # 0
    "Ready",        # 1
    "Running",      # 2
    "Standby",      # 3
    "Terminated",   # 4
    "Waiting",      # 5
    "Transition",   # 6
    "DeferredReady",  # 7
    "GateWaitObsolete",  # 8
    "WaitingForProcessInSwap",  # 9
)


def _enum_lookup(table: tuple[str, ...], idx: Optional[int]) -> str:
    """Look up an integer enum index; fall back to the raw int if out-of-range."""
    if idx is None:
        return ""
    if 0 <= idx < len(table):
        return table[idx]
    return str(idx)


# Pre-compiled struct format for the 24 bytes that v=4 and v=5 share.
#   <       little-endian, no padding
#   I I     NewThreadId, OldThreadId               (u32, u32)
#   b b B b NewPri, OldPri, PrevCState, Spare      (i8, i8, u8, i8)
#   b b b b OldWaitReason, OldWaitMode, OldState,
#           OldWaitIdealProc                       (i8 x4)
#   I I     NewThreadWaitTime, Reserved            (u32, u32)
_CSWITCH_COMMON = struct.Struct("<IIbbBbbbbbII")
assert _CSWITCH_COMMON.size == 24

# The v=5 tail.
_CSWITCH_EXTRA = struct.Struct("<I")
assert _CSWITCH_EXTRA.size == 4


def decode_cswitch_v5(payload: bytes, hdr: dict) -> Optional[dict]:
    """Decode a Thread/CSwitch v=5 (or v=4) MOF payload into a row dict.

    Args:
        payload: ``EVENT_RECORD.UserData`` bytes for the CSwitch event.
            Must be at least 24 bytes (v=4 layout). The trailing 4 bytes
            for v=5 are decoded into ``Extra4`` when present.
        hdr: Dict supplying the ``EVENT_HEADER`` / ``BufferContext`` fields
            the binary payload does not carry. Recognised keys (all optional
            but recommended): ``TimeStamp``, ``ProcessorNumber`` / ``CPU``,
            ``ProcessId``, ``ThreadId``. The ``ProcessId``/``ThreadId`` are
            used to identify the *new* thread/process; the payload's own
            ``NewThreadId`` field is preferred when both are present.

    Returns:
        A dict with the canonical CSwitch columns
        (``TimeStamp, OldProcessName, OldPID, OldTID, NewProcessName, NewPID,
        NewTID, WaitReason, WaitMode, OldThreadState, NewPriority,
        OldPriority, CPU, Extra4``), or ``None`` if ``payload`` is too short
        to contain the v=4 common header. Process *names* are not in the
        payload — the caller is responsible for resolving PID → name (the
        binary CSwitch path leaves them empty strings).
    """
    if len(payload) < _CSWITCH_COMMON.size:
        return None

    (
        new_tid,
        old_tid,
        new_pri,
        old_pri,
        _prev_cstate,
        _spare,
        wait_reason_idx,
        wait_mode_idx,
        old_state_idx,
        _old_wait_ideal_proc,
        _new_thread_wait_time,
        _reserved,
    ) = _CSWITCH_COMMON.unpack_from(payload, 0)

    # v=5 has a 4-byte tail. Keep its raw integer value as ``Extra4`` rather
    # than dropping it silently — the design doc explicitly asks for this so
    # future debugging can investigate what the field actually represents.
    extra4: Optional[int]
    if len(payload) >= _CSWITCH_COMMON.size + _CSWITCH_EXTRA.size:
        (extra4,) = _CSWITCH_EXTRA.unpack_from(payload, _CSWITCH_COMMON.size)
    else:
        extra4 = None

    # CPU comes from BufferContext.ProcessorNumber in the binary path.
    cpu = hdr.get("ProcessorNumber")
    if cpu is None:
        cpu = hdr.get("CPU", -1)

    # The new thread/process is the one being switched IN. EVENT_HEADER's
    # ProcessId/ThreadId identify the thread that logged the event (the new
    # thread); fall back to the payload field if hdr didn't supply them.
    hdr_new_tid = hdr.get("ThreadId")
    if hdr_new_tid is not None:
        new_tid_final = int(hdr_new_tid)
    else:
        new_tid_final = new_tid

    new_pid = hdr.get("ProcessId", 0) or 0

    return {
        "TimeStamp": hdr.get("TimeStamp", 0),
        # Process names aren't in the MOF payload. The native consumer will
        # resolve them from a PID → name map built from Process events; for
        # now leave them blank on the binary path. The xperf-text adapter
        # fills them in from the dumper's "Process Name ( PID)" column.
        "OldProcessName": "",
        "OldPID": 0,
        "OldTID": old_tid,
        "NewProcessName": "",
        "NewPID": int(new_pid),
        "NewTID": new_tid_final,
        "WaitReason": _enum_lookup(_WAIT_REASON, wait_reason_idx),
        "WaitMode": _enum_lookup(_WAIT_MODE, wait_mode_idx),
        "OldThreadState": _enum_lookup(_THREAD_STATE, old_state_idx),
        "NewPriority": new_pri,
        "OldPriority": old_pri,
        "CPU": int(cpu),
        "Extra4": extra4,
    }


__all__ = ["decode_cswitch_v5"]
