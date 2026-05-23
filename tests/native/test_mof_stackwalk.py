"""Tests for :mod:`etw_analyzer.native.mof.stackwalk`.

The fixture is a real captured StackWalk payload from feasibility
experiment ``exp4c_stacks_pair.py`` — 13 frames, EventTimeStamp matches a
preceding SampledProfile on the same trace.

Pairing logic itself is exercised in
``tests/test_native_consumer.py::test_load_trace_native_large_*`` end-to-end;
this file unit-tests the byte-level decoder.
"""

from __future__ import annotations

import struct

from etw_analyzer.native.mof.stackwalk import (
    HANDLERS,
    PROVIDER_GUID,
    decode_stack,
)


# Build a synthetic StackWalk payload that mirrors the first pair from
# exp4c_stacks_pair.out.txt:
#   EventTimeStamp = 4250801903602  (QPC)
#   ProcessId      = 8260  (the sample's sp_tid was 8260; we put the
#                           process there since we don't have a real PID)
#   ThreadId       = 8260
#   13 frames starting at 0xfffff806b09383ac (matches the leaf of the
#   captured stack)
_FRAMES = (
    0xFFFFF806B09383AC,
    0xFFFFF806B065E309,
    0xFFFFF806B0502D9B,
    0xFFFFF806B0502ACF,
    0xFFFFF806B05A543D,
    0xFFFFF806B0446FD0,
    0xFFFFF806B0C84FB0,
    0xFFFFF806B06A6FF5,
    0xFFFFF806B0C44C8E,
    0xFFFFF806B0C45842,
    0xFFFFF806B0C44C8E,
    0xFFFFF806B0C45842,
    0xFFFFF806B09383AC,
)
_STACK_PAYLOAD = (
    struct.pack("<QII", 4250801903602, 8260, 8260)
    + struct.pack(f"<{len(_FRAMES)}Q", *_FRAMES)
)


def test_decode_stack_matches_feasibility_fixture():
    row = decode_stack(
        _STACK_PAYLOAD,
        hdr={"TimeStamp": 4250801903864, "ProcessorNumber": 79},
    )
    assert row is not None
    assert row["EventTimeStamp"] == 4250801903602
    assert row["StackTimeStamp"] == 4250801903864
    assert row["ProcessId"] == 8260
    assert row["ThreadId"] == 8260
    assert row["CPU"] == 79
    assert row["Stack"] == _FRAMES
    assert len(row["Stack"]) == 13


def test_zero_frames_decodes_cleanly():
    """A stack-walk header with no frames (16-byte payload) is valid."""
    payload = struct.pack("<QII", 12345, 1, 2)
    row = decode_stack(payload, hdr={"ProcessorNumber": 0})
    assert row is not None
    assert row["Stack"] == ()
    assert row["EventTimeStamp"] == 12345


def test_too_short_returns_none():
    for bad_len in (0, 1, 8, 15):
        assert decode_stack(_STACK_PAYLOAD[:bad_len], hdr={}) is None


def test_handlers_register_opcode_32():
    """StackWalk uses opcode 32; design §4.1."""
    assert (32, None) in HANDLERS
    canonical, _fn = HANDLERS[(32, None)]
    assert canonical == "StackWalk"


def test_provider_guid_is_stackwalk_kernel():
    assert PROVIDER_GUID == "def2fe46-7bd6-4b80-bd94-f57fe20d0ce3"


def test_partial_frame_count_truncates():
    """If the payload tail isn't a multiple of 8 bytes the decoder drops
    the trailing partial frame rather than crash."""
    # 17 bytes = header (16) + 1 byte. n_frames = (1) // 8 = 0.
    payload = struct.pack("<QII", 0, 0, 0) + b"\x99"
    row = decode_stack(payload, hdr={})
    assert row is not None
    assert row["Stack"] == ()
