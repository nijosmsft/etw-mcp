"""Binary MOF decoders for the ``DiskIo`` kernel provider.

Provider GUID: ``3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c``

Decoded events:

+--------+----------------------+
| Opcode | Event                |
+========+======================+
| 10     | DiskIo/Read          |
+--------+----------------------+
| 11     | DiskIo/Write         |
+--------+----------------------+
| 14     | DiskIo/FlushBuffers  |
+--------+----------------------+

Layout (SDK ``_DiskIo_TypeGroup1``)::

    DiskNumber          u32
    IrpFlags            u32
    TransferSize        u32
    Reserved            u32
    ByteOffset          u64
    FileObject          u64
    Irp                 u64
    HighResResponseTime u64
    IssuingThreadId     u32  (optional on older builds)
"""

from __future__ import annotations

import struct
from typing import Optional


PROVIDER_GUID = "3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c"


# Fixed prefix: 48 bytes through HighResResponseTime.
_DISKIO = struct.Struct("<IIIIQQQQ")
assert _DISKIO.size == 48


def _decode_diskio(payload: bytes, hdr: dict, opcode_name: str) -> Optional[dict]:
    if len(payload) < _DISKIO.size:
        return None

    (
        disk_number,
        irp_flags,
        transfer_size,
        _reserved,
        byte_offset,
        file_object,
        irp,
        hi_res_time,
    ) = _DISKIO.unpack_from(payload, 0)

    issuing_tid = 0
    if len(payload) >= _DISKIO.size + 4:
        issuing_tid = struct.unpack_from("<I", payload, _DISKIO.size)[0]

    cpu = hdr.get("ProcessorNumber")
    if cpu is None:
        cpu = hdr.get("CPU", -1)

    return {
        "TimeStamp": int(hdr.get("TimeStamp", 0)),
        "CPU": int(cpu),
        "DiskNumber": int(disk_number),
        "IrpFlags": int(irp_flags),
        "TransferSize": int(transfer_size),
        "ByteOffset": int(byte_offset),
        "FileObject": int(file_object),
        "Irp": int(irp),
        "HighResResponseTime": int(hi_res_time),
        "IssuingThreadId": int(issuing_tid),
        "Type": opcode_name,
    }


def decode_read(payload: bytes, hdr: dict) -> Optional[dict]:
    return _decode_diskio(payload, hdr, "Read")


def decode_write(payload: bytes, hdr: dict) -> Optional[dict]:
    return _decode_diskio(payload, hdr, "Write")


def decode_flush(payload: bytes, hdr: dict) -> Optional[dict]:
    return _decode_diskio(payload, hdr, "FlushBuffers")


HANDLERS: dict[tuple[int, Optional[int]], tuple[str, callable]] = {
    (10, None): ("DiskIo/Read", decode_read),
    (11, None): ("DiskIo/Write", decode_write),
    (14, None): ("DiskIo/FlushBuffers", decode_flush),
}


__all__ = [
    "PROVIDER_GUID",
    "HANDLERS",
    "decode_read",
    "decode_write",
    "decode_flush",
]
