"""Binary MOF decoders for the ``Process`` kernel provider.

Provider GUID: ``3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c``

Decoded events:

+--------+----------------------+
| Opcode | Event                |
+========+======================+
| 1      | Process/Start        |
+--------+----------------------+
| 2      | Process/End          |
+--------+----------------------+
| 3      | Process/DCStart      |
+--------+----------------------+
| 4      | Process/DCEnd        |
+--------+----------------------+
| 39     | Process/Defunct      |
+--------+----------------------+

Variable-length layout — the trickiest in Phase N2 per design §4.2 because
the payload is::

    UniqueProcessKey (u64 ptr)
    ProcessId        (u32)
    ParentId         (u32)
    SessionId        (u32)
    ExitStatus       (i32)
    DirectoryTableBase (u64)
    Flags            (u32)
    UserSID          (variable: 1 byte rev + 1 byte SubAuthCount + 6 bytes
                       IdentifierAuthority + 4*SubAuthCount bytes)
    ImageFileName    (ASCII, null-terminated)
    CommandLine      (UTF-16, null-terminated)

The SID parser walks the SubAuthorityCount byte to know how long the SID
is; without it every subsequent string read drifts.
"""

from __future__ import annotations

import struct
from typing import Optional


PROVIDER_GUID = "3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c"


# Fixed prefix — through Flags.
#   <Q      UniqueProcessKey
#   <I      ProcessId
#   <I      ParentId
#   <I      SessionId
#   <i      ExitStatus      (signed)
#   <Q      DirectoryTableBase
#   <I      Flags
_PROCESS_HEADER = struct.Struct("<QIIIiQI")
assert _PROCESS_HEADER.size == 36


def _parse_sid(payload: bytes, offset: int) -> tuple[Optional[str], int]:
    """Parse a Windows SID at ``offset`` and return ``(sid_string, end_offset)``.

    Layout of the SID (`SID` struct from ``ntdef.h``)::

        Revision               u8
        SubAuthorityCount      u8
        IdentifierAuthority    u8[6] (big-endian)
        SubAuthority[SubAuthorityCount] u32 little-endian

    Returns ``(None, offset)`` if the SID is empty or malformed; the
    caller should then assume there is no SID and continue at ``offset``.
    A 4-byte all-zero TOKEN_USER prefix is common when the process has
    no user (e.g. system processes); we skip it and re-try.
    """
    if offset + 2 > len(payload):
        return None, offset

    # Some Process Start payloads prefix a zero TOKEN_USER pointer-sized
    # field before the SID itself. If the SID's Revision byte is zero,
    # the SID is the "null SID" (zero-length); just skip the 8 bytes and
    # move on.
    rev = payload[offset]
    if rev == 0:
        # If we see four zero bytes at offset, it's the TOKEN_USER pad —
        # skip 8 bytes and retry. If still zero, give up.
        if offset + 8 <= len(payload) and payload[offset : offset + 8] == b"\x00" * 8:
            return None, offset + 8
        return None, offset + 1

    sub_count = payload[offset + 1]
    sid_size = 8 + 4 * sub_count
    if offset + sid_size > len(payload):
        return None, offset

    auth_bytes = payload[offset + 2 : offset + 8]
    # 48-bit big-endian authority.
    auth = int.from_bytes(auth_bytes, "big")
    sub_authorities = struct.unpack_from(f"<{sub_count}I", payload, offset + 8)
    sid_str = "S-{}-{}".format(rev, auth)
    for sa in sub_authorities:
        sid_str += "-" + str(sa)
    return sid_str, offset + sid_size


def _read_ascii_z(payload: bytes, offset: int) -> tuple[str, int]:
    """Read an ASCII null-terminated string from ``offset``.

    Returns ``(string, end_offset_after_null)``. If no NUL is found before
    end-of-buffer, returns the trailing bytes decoded best-effort.
    """
    end = payload.find(b"\x00", offset)
    if end < 0:
        return payload[offset:].decode("ascii", errors="replace"), len(payload)
    return payload[offset:end].decode("ascii", errors="replace"), end + 1


def _read_utf16_z(payload: bytes, offset: int) -> tuple[str, int]:
    """Read a UTF-16-LE null-terminated string. Returns ``(string, end)``."""
    end = len(payload)
    i = offset
    while i + 1 < end:
        if payload[i] == 0 and payload[i + 1] == 0:
            raw = payload[offset:i]
            return raw.decode("utf-16-le", errors="replace"), i + 2
        i += 2
    return payload[offset:].decode("utf-16-le", errors="replace"), len(payload)


def decode_process_start_end(payload: bytes, hdr: dict) -> Optional[dict]:
    """Decode Process Start/End/DCStart/DCEnd.

    The four opcodes share their body; the caller demultiplexes them into
    different DataFrames via the canonical-name in the dispatch table.
    """
    if len(payload) < _PROCESS_HEADER.size:
        return None

    (
        unique_key,
        process_id,
        parent_id,
        session_id,
        exit_status,
        dtb,
        flags,
    ) = _PROCESS_HEADER.unpack_from(payload, 0)

    offset = _PROCESS_HEADER.size
    sid, offset = _parse_sid(payload, offset)
    image_name, offset = _read_ascii_z(payload, offset)
    # Align to 2-byte boundary for the UTF-16 CommandLine that follows.
    if offset & 1:
        offset += 1
    command_line, offset = _read_utf16_z(payload, offset)

    cpu = hdr.get("ProcessorNumber")
    if cpu is None:
        cpu = hdr.get("CPU", -1)

    return {
        "TimeStamp": int(hdr.get("TimeStamp", 0)),
        "CPU": int(cpu),
        "UniqueProcessKey": int(unique_key),
        "ProcessId": int(process_id),
        "ParentId": int(parent_id),
        "SessionId": int(session_id),
        "ExitStatus": int(exit_status),
        "DirectoryTableBase": int(dtb),
        "Flags": int(flags),
        "UserSID": sid if sid is not None else "",
        "ImageFileName": image_name,
        "CommandLine": command_line,
    }


def decode_process_defunct(payload: bytes, hdr: dict) -> Optional[dict]:
    """Decode a ``Process/Defunct`` (opcode 39) — same body as Start/End on
    modern Windows, sometimes truncated."""
    return decode_process_start_end(payload, hdr)


HANDLERS: dict[tuple[int, Optional[int]], tuple[str, callable]] = {
    (1, None): ("Process/Start", decode_process_start_end),
    (2, None): ("Process/End", decode_process_start_end),
    (3, None): ("Process/DCStart", decode_process_start_end),
    (4, None): ("Process/DCEnd", decode_process_start_end),
    (39, None): ("Process/Defunct", decode_process_defunct),
}


__all__ = [
    "PROVIDER_GUID",
    "HANDLERS",
    "decode_process_start_end",
    "decode_process_defunct",
]
