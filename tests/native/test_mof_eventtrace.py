"""Tests for :mod:`etw_analyzer.native.mof.eventtrace`."""

from __future__ import annotations

import struct

from etw_analyzer.native.mof.eventtrace import (
    HANDLERS,
    PROVIDER_GUID,
    decode_extension,
    decode_header,
    decode_rdcomplete,
)


def test_header_decode():
    body = struct.pack(
        "<IIIIqIIIIIIII",
        0x10000,             # BufferSize = 64K
        0x0001_0002,         # Version
        0x0001_0003,         # ProviderVersion
        80,                  # NumberOfProcessors
        0x01D9_8765_4321,    # EndTime (FILETIME)
        100,                 # TimerResolution
        0xFFFF_FFFF,         # MaxFileSize
        0x101,               # LogFileMode
        12345,               # BuffersWritten
        1,                   # StartBuffers
        8,                   # PointerSize
        0,                   # EventsLost
        2400,                # CpuSpeedInMHz
    )
    assert len(body) == 56

    row = decode_header(body, hdr={"TimeStamp": 1})
    assert row is not None
    assert row["BufferSize"] == 0x10000
    assert row["NumberOfProcessors"] == 80
    assert row["CpuSpeedInMHz"] == 2400
    assert row["PointerSize"] == 8
    assert row["EventsLost"] == 0


def test_header_truncated_returns_none():
    assert decode_header(b"\x00" * 32, hdr={}) is None


def test_rdcomplete():
    row = decode_rdcomplete(b"", hdr={"TimeStamp": 1234})
    assert row is not None
    assert row["Type"] == "RDComplete"
    assert row["PayloadBytes"] == 0


def test_extension():
    row = decode_extension(b"\x00" * 16, hdr={"TimeStamp": 1})
    assert row is not None
    assert row["Type"] == "Extension"
    assert row["PayloadBytes"] == 16


def test_handlers_register_known_opcodes():
    for op in (0, 5, 8, 16, 32):
        assert (op, None) in HANDLERS


def test_provider_guid():
    assert PROVIDER_GUID == "68fdd900-4a3e-11d1-84f4-0000f80464e3"
