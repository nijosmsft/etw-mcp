"""Tests for :mod:`etw_analyzer.native.mof.imageload`."""

from __future__ import annotations

import struct

from etw_analyzer.native.mof.imageload import (
    HANDLERS,
    PROVIDER_GUID,
    decode_image_load,
)


def _build_v3_payload(
    image_base: int = 0xFFFFF8060_0000000,
    image_size: int = 0x10_0000,
    pid: int = 0,
    file_name: str = r"\SystemRoot\System32\ntoskrnl.exe",
) -> bytes:
    body = struct.pack(
        "<QQIIIQIIII",
        image_base,
        image_size,
        pid,
        0xDEADBEEF,                # ImageChecksum
        0x60001234,                # TimeDateStamp
        0xFFFFF80000000000,        # DefaultBase
        0, 0, 0, 0,                # Reserved1..4
    )
    body += file_name.encode("utf-16-le") + b"\x00\x00"
    return body


def test_decode_modern_image_load():
    payload = _build_v3_payload()
    row = decode_image_load(
        payload, hdr={"TimeStamp": 1, "ProcessorNumber": 0}
    )
    assert row is not None
    assert row["ImageBase"] == 0xFFFFF8060_0000000
    assert row["ImageSize"] == 0x10_0000
    assert row["TimeDateStamp"] == 0x60001234
    assert row["FileName"] == r"\SystemRoot\System32\ntoskrnl.exe"


def test_decode_tcpip_sys():
    """The canonical use case — symbolize tcpip.sys."""
    payload = _build_v3_payload(
        image_base=0xFFFFF80700000000,
        file_name=r"\SystemRoot\System32\drivers\tcpip.sys",
    )
    row = decode_image_load(payload, hdr={"ProcessorNumber": 0})
    assert row is not None
    assert "tcpip.sys" in row["FileName"].lower()


def test_decode_old_short_payload():
    """Older Image MOFs (v=2) pack only the 36-byte minimum prefix."""
    body = struct.pack(
        "<QQIIIQ",
        0xFFFFF80700000000,        # ImageBase
        0x80_000,                  # ImageSize
        1234,                       # ProcessId
        0xDEADBEEF,
        0x60001234,
        0xFFFFF80000000000,         # DefaultBase
    )
    body += "kernel32.dll".encode("utf-16-le") + b"\x00\x00"
    row = decode_image_load(body, hdr={})
    assert row is not None
    assert row["FileName"] == "kernel32.dll"


def test_too_short_returns_none():
    assert decode_image_load(b"\x00" * 8, hdr={}) is None


def test_handlers_register_unload():
    assert (2, None) in HANDLERS
    assert (10, None) in HANDLERS
    assert HANDLERS[(10, None)][0] == "Image/Load"
    assert HANDLERS[(2, None)][0] == "Image/Unload"


def test_provider_guid():
    assert PROVIDER_GUID == "2cb15d1d-5fc1-11d2-abe1-00a0c911f518"
