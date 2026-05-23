"""Tests for the DiskIo / FileIo MOF decoders.

These two providers are optional in the standard kernel-logger profile —
the test traces under ``C:\\traces`` don't always include them — so we
unit-test with synthetic payloads matching the SDK MOF layout.
"""

from __future__ import annotations

import struct

from etw_analyzer.native.mof.diskio import (
    HANDLERS as DISKIO_HANDLERS,
    PROVIDER_GUID as DISKIO_GUID,
    decode_read,
    decode_write,
)
from etw_analyzer.native.mof.fileio import (
    HANDLERS as FILEIO_HANDLERS,
    PROVIDER_GUID as FILEIO_GUID,
    decode_close,
    decode_create,
    decode_read as file_read,
    decode_write as file_write,
)


# ---------------------------------------------------------------------------
# DiskIo
# ---------------------------------------------------------------------------
def test_diskio_read():
    payload = struct.pack(
        "<IIIIQQQQI",
        0,                    # DiskNumber
        0x40,                 # IrpFlags
        0x1000,               # TransferSize
        0,                    # Reserved
        0xDEAD_BEEF_0000,     # ByteOffset
        0xFFFF_C000_1234_5678,  # FileObject
        0xFFFF_F800_AAAA_BBBB,  # Irp
        12345678,             # HighResResponseTime
        1024,                 # IssuingThreadId
    )
    row = decode_read(payload, hdr={"TimeStamp": 100, "ProcessorNumber": 4})
    assert row is not None
    assert row["Type"] == "Read"
    assert row["TransferSize"] == 0x1000
    assert row["ByteOffset"] == 0xDEAD_BEEF_0000
    assert row["IssuingThreadId"] == 1024
    assert row["CPU"] == 4


def test_diskio_write_without_tid():
    """Older builds omit the IssuingThreadId field (48-byte payload)."""
    payload = struct.pack(
        "<IIIIQQQQ",
        0, 0, 0x2000, 0,
        0, 0, 0, 0,
    )
    assert len(payload) == 48
    row = decode_write(payload, hdr={"ProcessorNumber": 0})
    assert row is not None
    assert row["IssuingThreadId"] == 0
    assert row["Type"] == "Write"


def test_diskio_short_returns_none():
    assert decode_read(b"\x00" * 16, hdr={}) is None


def test_diskio_handlers():
    assert (10, None) in DISKIO_HANDLERS
    assert (11, None) in DISKIO_HANDLERS
    assert (14, None) in DISKIO_HANDLERS


def test_diskio_provider_guid():
    assert DISKIO_GUID == "3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c"


# ---------------------------------------------------------------------------
# FileIo
# ---------------------------------------------------------------------------
def test_fileio_create():
    body = struct.pack(
        "<QQQIII",
        0xFFFF_F800_1111_2222,    # IrpPtr
        0x1234,                    # TTID
        0xFFFF_C000_3333_4444,    # FileObject
        0x00000040,                # CreateOptions
        0,                         # FileAttributes
        0x7,                       # ShareAccess
    )
    body += r"\Device\Foo".encode("utf-16-le") + b"\x00\x00"
    row = decode_create(body, hdr={"TimeStamp": 1, "ProcessorNumber": 0})
    assert row is not None
    assert row["Type"] == "Create"
    assert row["OpenPath"] == r"\Device\Foo"
    assert row["FileObject"] == 0xFFFF_C000_3333_4444


def test_fileio_read_write():
    body = struct.pack(
        "<QQQQIII",
        0,                        # Offset
        0xFFFF_F800_AAAA_BBBB,    # IrpPtr
        0xFFFF_C000_3333_4444,    # FileObject
        0xFFFF_C000_5555_6666,    # FileKey
        0x1234,                    # TTID
        4096,                      # IoSize
        0,                         # IoFlags
    )
    for fn, expected in ((file_read, "Read"), (file_write, "Write")):
        row = fn(body, hdr={"ProcessorNumber": 0})
        assert row is not None
        assert row["Type"] == expected
        assert row["IoSize"] == 4096


def test_fileio_close():
    body = struct.pack(
        "<QQQQ",
        0xDEAD, 0xBEEF, 0xC0DE, 0xCAFE,
    )
    row = decode_close(body, hdr={"ProcessorNumber": 0})
    assert row is not None
    assert row["Type"] == "Close"
    assert row["FileKey"] == 0xCAFE


def test_fileio_handlers():
    for op in (0, 32, 67, 68, 74):
        assert (op, None) in FILEIO_HANDLERS


def test_fileio_provider_guid():
    assert FILEIO_GUID == "90cbdc39-4a3e-11d1-84f4-0000f80464e3"
