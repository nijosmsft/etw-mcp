"""Binary MOF decoders for the ``Image`` (ImageLoad) kernel provider.

Provider GUID: ``2cb15d1d-5fc1-11d2-abe1-00a0c911f518``

Decoded events:

+--------+--------------------------+
| Opcode | Event                    |
+========+==========================+
| 10     | Image/Load               |
+--------+--------------------------+
| 2      | Image/Unload             |
+--------+--------------------------+
| 3      | Image/DCStart            |
+--------+--------------------------+
| 4      | Image/DCEnd              |
+--------+--------------------------+
| 33     | Image/KernelBase         |
+--------+--------------------------+
| 34     | Image/HypercallPage      |
+--------+--------------------------+

Variable-length: 56-byte fixed prefix + UTF-16 ``FileName``. The string
length is ``(UserDataLength - 56) / 2``.

Layout (SDK ``_Image_Load_V3``)::

    ImageBase        u64
    ImageSize        u64
    ProcessId        u32
    ImageChecksum    u32
    TimeDateStamp    u32
    DefaultBase      u64  (called Reserved0 in some MOFs)
    Reserved1        u32
    Reserved2        u32
    Reserved3        u32
    Reserved4        u32
    FileName         WCHAR[…] (UTF-16, length from payload tail)

Total fixed = 8 + 8 + 4 + 4 + 4 + 8 + 4*4 = 52 bytes; with trailing
padding for 8-byte alignment some captures land on 56. We accept both
by reading the file name from the byte that immediately follows the
fixed payload computed for *this* layout version.

The decoder is forgiving: on a too-short payload it falls back to the
minimal Image-DCStart-style 36-byte body (ImageBase, ImageSize, ProcessId,
ImageChecksum, TimeDateStamp, FileName) used on older builds.
"""

from __future__ import annotations

import struct
from typing import Optional


PROVIDER_GUID = "2cb15d1d-5fc1-11d2-abe1-00a0c911f518"


# Modern Image MOF (v=3): 52-byte fixed prefix.
#   <QQ     ImageBase, ImageSize
#   <II     ProcessId, ImageChecksum
#   <I      TimeDateStamp
#   <Q      DefaultBase
#   <IIII   Reserved1..4
_IMAGE_V3 = struct.Struct("<QQIIIQIIII")
assert _IMAGE_V3.size == 52


# Older / simpler Image MOF: 36-byte fixed prefix.
#   <QQ     ImageBase, ImageSize
#   <I      ProcessId
#   <I      ImageChecksum
#   <I      TimeDateStamp
#   <Q      DefaultBase
_IMAGE_OLD = struct.Struct("<QQIIIQ")
assert _IMAGE_OLD.size == 36


def _read_utf16(payload: bytes, offset: int) -> str:
    """Read a UTF-16-LE string from ``offset`` to end-of-buffer.

    Strips a trailing NUL pair if present.
    """
    raw = payload[offset:]
    if len(raw) >= 2 and raw[-2:] == b"\x00\x00":
        raw = raw[:-2]
    try:
        return raw.decode("utf-16-le", errors="replace")
    except UnicodeDecodeError:
        return ""


def _looks_like_utf16_le(payload: bytes, offset: int) -> bool:
    """Heuristic: a UTF-16-LE string of ASCII / common characters has a
    zero high byte for the first WCHAR. Returns True if the two bytes at
    ``offset`` plausibly start a printable UTF-16 string.
    """
    if offset + 1 >= len(payload):
        return False
    lo, hi = payload[offset], payload[offset + 1]
    # Skip empty pad cells (two zeros — those would be a trailing NUL).
    if lo == 0:
        return False
    return hi == 0 and 0x20 <= lo < 0x7F


def decode_image_load(payload: bytes, hdr: dict) -> Optional[dict]:
    """Decode an ``Image/Load`` / ``Image/Unload`` / DCStart / DCEnd payload."""
    if len(payload) < _IMAGE_OLD.size:
        return None

    # Decode the 36-byte common prefix unconditionally — its layout matches
    # both V2 and V3.
    (
        image_base,
        image_size,
        process_id,
        image_checksum,
        time_date_stamp,
        default_base,
    ) = _IMAGE_OLD.unpack_from(payload, 0)

    # Pick name offset. The bytes at the V2 boundary (36) are the most
    # reliable signal — V3 reserved fields are zero/random while a string
    # there is rare on the older layout. If the V2 boundary looks like a
    # printable UTF-16 character we use it; otherwise we step to the V3
    # boundary (52 bytes), the modern packed layout.
    if _looks_like_utf16_le(payload, _IMAGE_OLD.size):
        name_offset = _IMAGE_OLD.size
    elif len(payload) >= _IMAGE_V3.size:
        name_offset = _IMAGE_V3.size
    else:
        name_offset = _IMAGE_OLD.size

    file_name = _read_utf16(payload, name_offset)

    cpu = hdr.get("ProcessorNumber")
    if cpu is None:
        cpu = hdr.get("CPU", -1)

    return {
        "TimeStamp": int(hdr.get("TimeStamp", 0)),
        "CPU": int(cpu),
        "ProcessId": int(process_id),
        "ImageBase": int(image_base),
        "ImageSize": int(image_size),
        "ImageChecksum": int(image_checksum),
        "TimeDateStamp": int(time_date_stamp),
        "DefaultBase": int(default_base),
        "FileName": file_name,
    }


HANDLERS: dict[tuple[int, Optional[int]], tuple[str, callable]] = {
    (10, None): ("Image/Load", decode_image_load),
    (2, None): ("Image/Unload", decode_image_load),
    (3, None): ("Image/DCStart", decode_image_load),
    (4, None): ("Image/DCEnd", decode_image_load),
    (33, None): ("Image/KernelBase", decode_image_load),
    (34, None): ("Image/HypercallPage", decode_image_load),
}


__all__ = ["PROVIDER_GUID", "HANDLERS", "decode_image_load"]
