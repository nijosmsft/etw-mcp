"""Tests for :mod:`etw_analyzer.native.mof.process`.

The Process Start payload has a variable-length SID prefix between the
fixed header and the ImageFileName/CommandLine string pair. This file
covers both shapes (with-SID and without).
"""

from __future__ import annotations

import struct

from etw_analyzer.native.mof.process import (
    HANDLERS,
    PROVIDER_GUID,
    _parse_sid,
    decode_process_start_end,
)


def _build_payload(
    pid: int = 4242,
    parent_id: int = 1,
    session: int = 2,
    exit_status: int = 0,
    user_sid: bytes = b"",
    image_name: str = "explorer.exe",
    command_line: str = '"C:\\Windows\\explorer.exe" /factory',
) -> bytes:
    """Construct a synthetic Process Start payload."""
    body = struct.pack(
        "<QIIIiQI",
        0xAAAA_BBBB_CCCC_DDDD,  # UniqueProcessKey
        pid,
        parent_id,
        session,
        exit_status,
        0x1234_5678_9ABC_DEF0,  # DirectoryTableBase
        0,                       # Flags
    )
    body += user_sid
    body += image_name.encode("ascii") + b"\x00"
    # Pad to 2-byte boundary before the UTF-16 command line.
    if len(body) & 1:
        body += b"\x00"
    body += command_line.encode("utf-16-le") + b"\x00\x00"
    return body


def test_decode_with_full_sid():
    """A SID with revision=1, authority=5 (NT), subAuth=[18] is the LocalSystem
    SID. Two sub-authorities push the SID total to 16 bytes."""
    # SID: rev=1, count=1, authority=NT (5), subauth=18.
    sid_bytes = struct.pack("<BB6sI", 1, 1, b"\x00\x00\x00\x00\x00\x05", 18)
    assert len(sid_bytes) == 12

    row = decode_process_start_end(
        _build_payload(user_sid=sid_bytes),
        hdr={"TimeStamp": 9999, "ProcessorNumber": 1},
    )
    assert row is not None
    assert row["ProcessId"] == 4242
    assert row["ImageFileName"] == "explorer.exe"
    assert row["CommandLine"].startswith('"C:')
    assert row["UserSID"] == "S-1-5-18"


def test_decode_with_two_subauthorities():
    """Domain Admins-style SID: rev=1, auth=5, 2 sub-authorities."""
    sid_bytes = struct.pack(
        "<BB6sII", 1, 2, b"\x00\x00\x00\x00\x00\x05", 21, 1000
    )
    assert len(sid_bytes) == 16

    row = decode_process_start_end(
        _build_payload(user_sid=sid_bytes),
        hdr={"ProcessorNumber": 0},
    )
    assert row is not None
    assert row["UserSID"] == "S-1-5-21-1000"


def test_decode_with_zero_sid_pad():
    """The 8-byte TOKEN_USER zero-pad is the common case for system
    processes; the decoder must skip it and still find the strings."""
    row = decode_process_start_end(
        _build_payload(user_sid=b"\x00" * 8, image_name="System"),
        hdr={"ProcessorNumber": 0},
    )
    assert row is not None
    assert row["UserSID"] == ""
    assert row["ImageFileName"] == "System"


def test_too_short_returns_none():
    assert decode_process_start_end(b"\x00" * 16, hdr={}) is None


def test_exit_status_signed():
    """ExitStatus is signed; STATUS_ABANDONED = 0x80000000 must come back
    as a negative number after the int32 cast."""
    payload = struct.pack(
        "<QIIIiQI",
        0, 1, 0, 0, -2147483648, 0, 0,  # ExitStatus = INT32_MIN
    ) + b"\x00\x00\x00\x00"  # zero SID pad + ASCII null + UTF-16 null
    row = decode_process_start_end(payload, hdr={"ProcessorNumber": 0})
    assert row is not None
    assert row["ExitStatus"] == -2147483648


class TestSidParser:
    def test_localsystem_sid(self):
        sid_bytes = struct.pack("<BB6sI", 1, 1, b"\x00\x00\x00\x00\x00\x05", 18)
        sid, end = _parse_sid(sid_bytes, 0)
        assert sid == "S-1-5-18"
        assert end == 12

    def test_zero_revision_skips_pad(self):
        sid, end = _parse_sid(b"\x00" * 8 + b"AAAA", 0)
        assert sid is None
        assert end == 8

    def test_truncated(self):
        """Sub-auth count claims 5 but only 1 subauth byte present."""
        sid, end = _parse_sid(b"\x01\x05\x00\x00\x00\x00\x00\x05" + b"\x01", 0)
        assert sid is None


class TestDispatchTable:
    def test_all_process_opcodes(self):
        opcodes = {opcode for (opcode, _v) in HANDLERS}
        for needed in (1, 2, 3, 4, 39):
            assert needed in opcodes

    def test_provider_guid(self):
        assert PROVIDER_GUID == "3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c"


# Regression: Windows 10/11 kernel logger prefixes the SID with a full
# TOKEN_USER struct (8-byte kernel PSID pointer + 4-byte Attributes +
# 4-byte alignment padding). The previous decoder only skipped 8 zero
# bytes, so when the PSID pointer was non-zero the decoder fell out of
# alignment and read garbled binary as the ImageFileName (visible as
# ``Image='M�����'``-style output). See
# ``udp-perf/docs/wpr-mcp-native-etw-verification.md`` §"Residual Issues 1".
def test_decode_with_token_user_prefix():
    """Real-world payload shape: 16-byte TOKEN_USER prefix before the SID,
    and **no padding** between the ASCII ImageFileName null terminator and
    the UTF-16 LE CommandLine — the kernel writes them back-to-back."""
    # Kernel-mode PSID pointer — non-zero so the legacy "zero pad" check
    # would miss it.
    token_user = b"\xd0\x4b\xb2\xbe\xbd\xf1\xff\xff"
    token_user += b"\x00" * 8  # Attributes (4) + padding (4)

    # LocalSystem SID, rev=1, count=1, NT, subauth=18.
    sid_bytes = struct.pack("<BB6sI", 1, 1, b"\x00\x00\x00\x00\x00\x05", 18)

    body = struct.pack(
        "<QIIIiQI",
        0xC090_FCE8_8A8B_FFFF,
        3052,   # PID
        4,      # ParentId
        0xFFFFFFFF,
        0,
        0,
        4,
    )
    body += token_user + sid_bytes
    # ASCII name + null, then UTF-16 LE cmdline. NO PADDING — that's the
    # whole point of this regression test.
    body += b"smss.exe\x00"
    body += '"C:\\Windows\\System32\\smss.exe"'.encode("utf-16-le") + b"\x00\x00"

    row = decode_process_start_end(body, hdr={"ProcessorNumber": 0})
    assert row is not None
    assert row["ProcessId"] == 3052
    # Image must be a clean ASCII name — not garbled binary.
    assert row["ImageFileName"] == "smss.exe"
    assert row["ImageFileName"].isprintable()
    assert row["UserSID"] == "S-1-5-18"
    # CommandLine must decode as ASCII characters, not as CJK kanji
    # (which is what the byte-shifted UTF-16 decode produces).
    assert row["CommandLine"] == '"C:\\Windows\\System32\\smss.exe"'
    assert all(ord(c) < 256 for c in row["CommandLine"]), (
        f"CmdLine appears byte-shifted (CJK codepoints): {row['CommandLine']!r}"
    )


def test_decode_with_token_user_prefix_zero_low_byte():
    """The PSID pointer's low byte can be zero — must not be mistaken for
    a zero-SID pad. Sample observed: ``00 4c b2 be bd f1 ff ff``."""
    token_user = b"\x00\x4c\xb2\xbe\xbd\xf1\xff\xff"
    token_user += b"\x00" * 8

    sid_bytes = struct.pack("<BB6sI", 1, 1, b"\x00\x00\x00\x00\x00\x05", 18)

    body = struct.pack(
        "<QIIIiQI",
        0xAAAA_BBBB_CCCC_DDDD,
        1068,  # PID
        4,
        0xFFFFFFFF,
        0,
        0,
        4,
    )
    body += token_user + sid_bytes
    body += b"Registry\x00"
    if len(body) & 1:
        body += b"\x00"
    body += b"\x00\x00"  # empty UTF-16 command line

    row = decode_process_start_end(body, hdr={})
    assert row is not None
    assert row["ProcessId"] == 1068
    assert row["ImageFileName"] == "Registry"
    assert row["ImageFileName"].isprintable()
