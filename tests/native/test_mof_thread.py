"""Tests for :mod:`etw_analyzer.native.mof.thread`.

Covers ReadyThread, Thread Start/End, and Thread SetName. CSwitch is
already exhaustively tested via ``tests/test_mof_cswitch.py`` (the
Phase N0 decoder).
"""

from __future__ import annotations

import struct

from etw_analyzer.native.mof.thread import (
    HANDLERS,
    PROVIDER_GUID,
    decode_ready_thread,
    decode_thread_set_name,
    decode_thread_start_end,
)


class TestReadyThread:
    def test_basic(self):
        payload = struct.pack("<IbbH", 4242, 5, 1, 0)
        row = decode_ready_thread(
            payload, hdr={"TimeStamp": 1000, "ProcessorNumber": 7}
        )
        assert row is not None
        assert row["ThreadId"] == 4242
        assert row["AdjustReason"] == 5
        assert row["AdjustIncrement"] == 1
        assert row["CPU"] == 7
        assert row["TimeStamp"] == 1000

    def test_too_short(self):
        assert decode_ready_thread(b"\x00" * 4, hdr={}) is None

    def test_negative_adjust_increment(self):
        """AdjustIncrement is signed; negative values must round-trip."""
        payload = struct.pack("<IbbH", 1, 0, -3, 0)
        row = decode_ready_thread(payload, hdr={"ProcessorNumber": 0})
        assert row is not None
        assert row["AdjustIncrement"] == -3

    def test_readied_and_readying_fields(self):
        """The payload TThreadId is the *readied* thread; the ETW header
        ThreadId/ProcessId identify the *readying* thread/process."""
        payload = struct.pack("<IbbH", 4242, 5, 1, 0)
        row = decode_ready_thread(
            payload,
            hdr={
                "TimeStamp": 1000,
                "ProcessorNumber": 7,
                "ThreadId": 999,     # readying thread (running on-CPU)
                "ProcessId": 888,    # readying process
            },
        )
        assert row is not None
        # Readied (target) thread — payload TThreadId, back-compat ThreadId.
        assert row["ThreadId"] == 4242
        assert row["ReadiedThreadId"] == 4242
        # Readying (source) thread/process — from the header.
        assert row["ReadyingThreadId"] == 999
        assert row["ReadyingProcessId"] == 888

    def test_readying_fields_default_zero_without_header(self):
        """When the header omits ThreadId/ProcessId, readying fields are 0."""
        payload = struct.pack("<IbbH", 4242, 5, 1, 0)
        row = decode_ready_thread(
            payload, hdr={"TimeStamp": 1000, "ProcessorNumber": 7}
        )
        assert row is not None
        assert row["ReadiedThreadId"] == 4242
        assert row["ReadyingThreadId"] == 0
        assert row["ReadyingProcessId"] == 0


class TestThreadStartEnd:
    def _build_payload(self, with_name: bool = False, with_priorities: bool = True):
        # Build a packed Thread_V3 payload: 64 bytes minimum, optional 8
        # bytes priorities, optional trailing UTF-16 name.
        body = struct.pack(
            "<IIQQQQQQQ",
            1234,            # ProcessId
            5678,            # ThreadId
            0xAAAA_AAAA_AAAA_AAAA,  # StackBase
            0xBBBB_BBBB_BBBB_BBBB,  # StackLimit
            0xCCCC_CCCC_CCCC_CCCC,  # UserStackBase
            0xDDDD_DDDD_DDDD_DDDD,  # UserStackLimit
            0xEEEE_EEEE_EEEE_EEEE,  # StartAddr
            0xFFFF_FFFF_FFFF_FFFE,  # Win32StartAddr
            0x1111_2222_3333_4444,  # TebBase
        )
        if with_priorities:
            body += struct.pack("<IBBBB", 0xAB, 8, 3, 2, 0)  # tag,base,page,io,flags
        if with_name:
            body += "worker-thread".encode("utf-16-le") + b"\x00\x00"
        return body

    def test_basic(self):
        row = decode_thread_start_end(
            self._build_payload(), hdr={"TimeStamp": 1, "ProcessorNumber": 0}
        )
        assert row is not None
        assert row["ProcessId"] == 1234
        assert row["ThreadId"] == 5678
        assert row["StackBase"] == 0xAAAA_AAAA_AAAA_AAAA
        assert row["Win32StartAddr"] == 0xFFFF_FFFF_FFFF_FFFE
        assert row["BasePriority"] == 8
        assert row["IoPriority"] == 2
        assert row["SubProcessTag"] == 0xAB

    def test_with_thread_name(self):
        row = decode_thread_start_end(
            self._build_payload(with_name=True), hdr={}
        )
        assert row is not None
        assert row["ThreadName"] == "worker-thread"

    def test_no_priority_tail(self):
        """Older builds omit the priority bytes — must still decode the
        ProcessId / ThreadId / stack pointers correctly."""
        row = decode_thread_start_end(
            self._build_payload(with_priorities=False), hdr={}
        )
        assert row is not None
        assert row["ProcessId"] == 1234
        assert row["BasePriority"] == 0  # default when omitted

    def test_too_short_returns_none(self):
        assert decode_thread_start_end(b"\x00" * 8, hdr={}) is None


class TestThreadSetName:
    def test_decodes_name(self):
        payload = struct.pack("<II", 4, 100) + "io-thread".encode("utf-16-le") + b"\x00\x00"
        row = decode_thread_set_name(payload, hdr={"ProcessorNumber": 0})
        assert row is not None
        assert row["ProcessId"] == 4
        assert row["ThreadId"] == 100
        assert row["ThreadName"] == "io-thread"

    def test_short_returns_none(self):
        assert decode_thread_set_name(b"\x00" * 4, hdr={}) is None


class TestDispatchTable:
    def test_cswitch_uses_existing_decoder(self):
        """Opcode 36 must point at the existing Phase N0 decoder."""
        from etw_analyzer.parsing.mof_cswitch import decode_cswitch_v5
        assert (36, None) in HANDLERS
        canonical, fn = HANDLERS[(36, None)]
        assert canonical == "CSwitch"
        assert fn is decode_cswitch_v5

    def test_all_thread_opcodes_covered(self):
        opcodes = {opcode for (opcode, _v) in HANDLERS}
        # Start/End/DCStart/DCEnd, CSwitch, ReadyThread, SetName
        for needed in (1, 2, 3, 4, 36, 50, 72):
            assert needed in opcodes

    def test_provider_guid_matches_kernel_thread(self):
        assert PROVIDER_GUID == "3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c"
