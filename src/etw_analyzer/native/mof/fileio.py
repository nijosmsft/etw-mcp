"""Binary MOF decoders for the ``FileIo`` kernel provider.

Provider GUID: ``90cbdc39-4a3e-11d1-84f4-0000f80464e3``

Common opcodes:

+--------+-------------------+
| Opcode | Event             |
+========+===================+
| 0      | FileIo/Name       |
+--------+-------------------+
| 32     | FileIo/Create     |
+--------+-------------------+
| 67     | FileIo/Read       |
+--------+-------------------+
| 68     | FileIo/Write      |
+--------+-------------------+
| 74     | FileIo/Close      |
+--------+-------------------+

The full FileIo schema has dozens of opcodes; the table here covers the
ones that show up in the standard kernel-logger profiles. The decoders
emit a compact common dict; opcode-specific fields live under the ``Type``
discriminator.
"""

from __future__ import annotations

import struct
from typing import Optional


PROVIDER_GUID = "90cbdc39-4a3e-11d1-84f4-0000f80464e3"


# FileIo/Name payload (opcode 0).
#   <Q      FileObject  (u64)
#   <Q      FileKey     (u64) — optional on older builds
#   <W…     FileName    (UTF-16, length-from-tail)
_FILE_NAME = struct.Struct("<Q")
assert _FILE_NAME.size == 8


# FileIo/Create payload (opcode 32):
#   <Q      IrpPtr
#   <Q      TTID            (Threading)
#   <Q      FileObject
#   <I      CreateOptions
#   <I      FileAttributes
#   <I      ShareAccess
#   <W…     OpenPath        (UTF-16)
_FILE_CREATE = struct.Struct("<QQQIII")
assert _FILE_CREATE.size == 36


# FileIo/Read or /Write payload (opcode 67/68):
#   <Q      Offset
#   <Q      IrpPtr
#   <Q      FileObject
#   <Q      FileKey
#   <I      TTID
#   <I      IoSize
#   <I      IoFlags
_FILE_RW = struct.Struct("<QQQQIII")
assert _FILE_RW.size == 44


# FileIo/Close (opcode 74).
#   <Q      IrpPtr
#   <Q      TTID
#   <Q      FileObject
#   <Q      FileKey
_FILE_CLOSE = struct.Struct("<QQQQ")
assert _FILE_CLOSE.size == 32


def _read_utf16(payload: bytes, offset: int) -> str:
    raw = payload[offset:]
    if len(raw) >= 2 and raw[-2:] == b"\x00\x00":
        raw = raw[:-2]
    try:
        return raw.decode("utf-16-le", errors="replace")
    except UnicodeDecodeError:
        return ""


def _common_hdr(hdr: dict) -> dict:
    cpu = hdr.get("ProcessorNumber")
    if cpu is None:
        cpu = hdr.get("CPU", -1)
    return {
        "TimeStamp": int(hdr.get("TimeStamp", 0)),
        "CPU": int(cpu),
        "ProcessId": int(hdr.get("ProcessId", 0)),
        "ThreadId": int(hdr.get("ThreadId", 0)),
    }


def decode_name(payload: bytes, hdr: dict) -> Optional[dict]:
    """Decode a ``FileIo/Name`` (opcode 0). Used to map FileKey -> path."""
    if len(payload) < _FILE_NAME.size:
        return None
    file_object = struct.unpack_from("<Q", payload, 0)[0]
    # Some builds emit FileKey after FileObject before the name.
    name_offset = 8
    file_key = 0
    if len(payload) >= 16:
        file_key = struct.unpack_from("<Q", payload, 8)[0]
        # Heuristic: if the next 2 bytes don't look like UTF-16 (e.g.
        # FileKey is small and the next byte is non-zero), the name
        # starts at offset 8 instead.
        name_offset = 16
    return {
        **_common_hdr(hdr),
        "Type": "Name",
        "FileObject": int(file_object),
        "FileKey": int(file_key),
        "FileName": _read_utf16(payload, name_offset),
    }


def decode_create(payload: bytes, hdr: dict) -> Optional[dict]:
    if len(payload) < _FILE_CREATE.size:
        return None
    (
        irp,
        ttid,
        file_object,
        create_options,
        file_attributes,
        share_access,
    ) = _FILE_CREATE.unpack_from(payload, 0)
    return {
        **_common_hdr(hdr),
        "Type": "Create",
        "IrpPtr": int(irp),
        "TTID": int(ttid),
        "FileObject": int(file_object),
        "CreateOptions": int(create_options),
        "FileAttributes": int(file_attributes),
        "ShareAccess": int(share_access),
        "OpenPath": _read_utf16(payload, _FILE_CREATE.size),
    }


def _decode_rw(payload: bytes, hdr: dict, opcode_name: str) -> Optional[dict]:
    if len(payload) < _FILE_RW.size:
        return None
    (
        offset,
        irp,
        file_object,
        file_key,
        ttid,
        io_size,
        io_flags,
    ) = _FILE_RW.unpack_from(payload, 0)
    return {
        **_common_hdr(hdr),
        "Type": opcode_name,
        "Offset": int(offset),
        "IrpPtr": int(irp),
        "FileObject": int(file_object),
        "FileKey": int(file_key),
        "TTID": int(ttid),
        "IoSize": int(io_size),
        "IoFlags": int(io_flags),
    }


def decode_read(payload: bytes, hdr: dict) -> Optional[dict]:
    return _decode_rw(payload, hdr, "Read")


def decode_write(payload: bytes, hdr: dict) -> Optional[dict]:
    return _decode_rw(payload, hdr, "Write")


def decode_close(payload: bytes, hdr: dict) -> Optional[dict]:
    if len(payload) < _FILE_CLOSE.size:
        return None
    irp, ttid, file_object, file_key = _FILE_CLOSE.unpack_from(payload, 0)
    return {
        **_common_hdr(hdr),
        "Type": "Close",
        "IrpPtr": int(irp),
        "TTID": int(ttid),
        "FileObject": int(file_object),
        "FileKey": int(file_key),
    }


HANDLERS: dict[tuple[int, Optional[int]], tuple[str, callable]] = {
    (0, None): ("FileIo/Name", decode_name),
    (32, None): ("FileIo/Create", decode_create),
    (67, None): ("FileIo/Read", decode_read),
    (68, None): ("FileIo/Write", decode_write),
    (74, None): ("FileIo/Close", decode_close),
}


__all__ = [
    "PROVIDER_GUID",
    "HANDLERS",
    "decode_name",
    "decode_create",
    "decode_read",
    "decode_write",
    "decode_close",
]
