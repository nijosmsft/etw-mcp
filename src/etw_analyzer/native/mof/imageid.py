"""Binary MOF decoders for the ImageID/DbgID_RSDS provider.

Provider GUID: ``b059b83f-d946-4b13-87ca-4292839dc2f2``
(``Microsoft-Windows-Kernel-ImageID``)

This provider emits per-image PDB debug-signature records that the kernel
image-rundown logs at trace start.  The ``DbgID_RSDS`` opcode (36) carries
the exact (GUID, Age, PdbFileName) triple that ``SymFindFileInPathW`` needs to
locate the correct PDB on a symbol server.  Without this, dbghelp derives the
wrong GUID from whatever local image happens to be at the same path (which
differs across builds), silently falls back to PE export-table names, and
produces plausible-but-wrong kernel symbols.

Decoded events:

+--------+--------------------------+
| Opcode | Event                    |
+========+==========================+
| 36     | ImageID/DbgID_RSDS       |
+--------+--------------------------+

``DbgID_RSDS`` payload layout (28-byte fixed prefix + null-terminated string)::

    ImageBase   uint64     8 bytes  -- load address of the image
    Guid        16 bytes   16 bytes -- Data1=u32LE, Data2=u16LE,
                                       Data3=u16LE, Data4[8]=bytes
    Age         uint32     4 bytes
    PdbFileName variable   null-terminated ASCII/UTF-8
                           (may be a full build path -- use basename only)

``ProcessId`` comes from the event header (EventHeader.ProcessId), not from
the payload.  For kernel images this is typically 0 or 4 (System).

Payload layout confirmed against the reference ETL
(``wpa5-1M-260615-143816.etl``, first decoded record):
  base=0xfffff8057e600000, GUID=AFB1E3B1-3754-8BA7-3B92-C060D6D5605F,
  age=1, pdb=ntkrnlmp.pdb
Synthetic bytes for this record reproduce the same values via unit tests.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Optional


PROVIDER_GUID = "b059b83f-d946-4b13-87ca-4292839dc2f2"

# ImageBase (u64) + GUID (16 bytes) + Age (u32) = 28 bytes.
_FIXED_PREFIX = 8 + 16 + 4

# A 16-byte all-zero GUID is invalid (no real PDB has it).
_ZERO_GUID = bytes(16)


def _format_guid(guid_bytes: bytes) -> str:
    """Format 16 raw GUID bytes (Windows on-wire layout) to canonical form.

    Windows GUID wire layout: Data1 (4B LE), Data2 (2B LE), Data3 (2B LE),
    Data4[8] (8 bytes, not byte-swapped).

    Returns the canonical 8-4-4-4-12 uppercase string, e.g.::

        AFB1E3B1-3754-8BA7-3B92-C060D6D5605F
    """
    if len(guid_bytes) < 16:
        return ""
    d1 = struct.unpack_from("<I", guid_bytes, 0)[0]
    d2 = struct.unpack_from("<H", guid_bytes, 4)[0]
    d3 = struct.unpack_from("<H", guid_bytes, 6)[0]
    d4 = guid_bytes[8:16]
    return (
        f"{d1:08X}-{d2:04X}-{d3:04X}"
        f"-{d4[0]:02X}{d4[1]:02X}"
        f"-{d4[2]:02X}{d4[3]:02X}{d4[4]:02X}{d4[5]:02X}{d4[6]:02X}{d4[7]:02X}"
    )


def decode_dbgid_rsds(payload: bytes, hdr: dict) -> Optional[dict]:
    """Decode an ``ImageID/DbgID_RSDS`` (opcode 36) event payload.

    Returns a row dict with ``ImageBase``, ``PdbGuid`` (canonical uppercase
    GUID string), ``PdbAge`` (int), ``PdbName`` (basename), and
    ``PdbFullPath`` (raw, may be a full build path such as
    ``C:\\\\__w\\\\1\\\\s\\\\build\\\\...\\\\symcryptk.pdb``).

    Returns ``None`` for too-short or clearly-invalid payloads.
    """
    if len(payload) < _FIXED_PREFIX:
        return None

    image_base = struct.unpack_from("<Q", payload, 0)[0]
    guid_bytes = payload[8:24]
    age = struct.unpack_from("<I", payload, 24)[0]

    if guid_bytes == _ZERO_GUID:
        return None

    pdb_guid = _format_guid(guid_bytes)
    if not pdb_guid:
        return None

    # PdbFileName: null-terminated ASCII/UTF-8 starting at byte 28.
    fname_raw = payload[_FIXED_PREFIX:]
    null_idx = fname_raw.find(b"\x00")
    if null_idx >= 0:
        fname_raw = fname_raw[:null_idx]
    try:
        pdb_full_path = fname_raw.decode("utf-8", errors="replace")
    except Exception:
        pdb_full_path = fname_raw.decode("ascii", errors="replace")

    # Design doc 3.2: store raw value AND basename; the symbol-server lookup
    # uses the basename.  PdbFileName may be a full build path.
    pdb_name = Path(pdb_full_path).name if pdb_full_path else ""

    cpu = hdr.get("ProcessorNumber")
    if cpu is None:
        cpu = hdr.get("CPU", -1)

    return {
        "TimeStamp": int(hdr.get("TimeStamp", 0)),
        "CPU": int(cpu),
        "ProcessId": int(hdr.get("ProcessId", 0)),
        "ImageBase": int(image_base),
        "PdbGuid": pdb_guid,
        "PdbAge": int(age),
        "PdbName": pdb_name,
        "PdbFullPath": pdb_full_path,
    }


HANDLERS: dict[tuple[int, Optional[int]], tuple[str, callable]] = {
    (36, None): ("ImageID/DbgID_RSDS", decode_dbgid_rsds),
}


__all__ = [
    "PROVIDER_GUID",
    "HANDLERS",
    "decode_dbgid_rsds",
    "_format_guid",
]
