"""Tests for the binary CSwitch MOF decoder.

Fixture payloads come from
``C:\\temp\\etw-feasibility\\exp3b_cswitch_manual.out.txt`` — real
EVENT_RECORD.UserData bytes captured from the kernel ``Thread`` provider on
the ``C:\\traces\\vmserver-networking-test.etl`` trace.

The decoded values in the asserts were produced by the feasibility
experiment script and verified by hand against the MOF layout
(`NewThreadId` u32, `OldThreadId` u32, then six i8/u8 byte fields, then
two u32s, plus a v=5-only u32 tail).
"""

from __future__ import annotations

from etw_analyzer.parsing.mof_cswitch import decode_cswitch_v5


# ---------------------------------------------------------------------------
# Fixture #1 — exp3b_cswitch_manual sample #1
#
#   Raw 28 bytes: 3c0d000000000000080001000000023e0000000003b2d64f02000000
#   CPU=62 (from BufferContext.ProcessorNumber)
#   NewThreadId=3388  OldThreadId=0
#   NewPri=8  OldPri=0
#   PrevCState=1  Spare=0
#   OldWaitReason=0 (Executive)  OldWaitMode=0 (KernelMode)
#   OldState=2 (Running)  OldWaitIdealProc=62
#   NewThreadWaitTime=0  Reserved=0x4fd6b203
#   Extra4=2
# ---------------------------------------------------------------------------
_PAYLOAD_1 = bytes.fromhex("3c0d000000000000080001000000023e0000000003b2d64f02000000")

# Fixture #2 — exp3b sample #2 (the reverse switch-out):
#   Raw: 000000003c0d0000000800000000054baf1d9f01ee0a000008000000
#   CPU=62
#   NewThreadId=0  OldThreadId=3388  NewPri=0 OldPri=8
#   OldState=5 (Waiting)  Extra4=8
_PAYLOAD_2 = bytes.fromhex("000000003c0d0000000800000000054baf1d9f01ee0a000008000000")

# Fixture #3 — exp3b sample #3 on a different CPU.
#   Raw: 3c0d000000000000080001000000024000000000e32e304c02000000
#   CPU=64  NewThreadId=3388  OldState=2 (Running)
_PAYLOAD_3 = bytes.fromhex("3c0d000000000000080001000000024000000000e32e304c02000000")


class TestDecodeCSwitchV5:
    """Unit tests for :func:`decode_cswitch_v5`."""

    def test_v5_full_payload(self):
        row = decode_cswitch_v5(
            _PAYLOAD_1,
            hdr={
                "TimeStamp": 56678,
                "ProcessorNumber": 62,
                "ProcessId": 4,
                "ThreadId": 3388,
            },
        )
        assert row is not None
        assert row["TimeStamp"] == 56678
        assert row["CPU"] == 62
        assert row["NewTID"] == 3388
        assert row["OldTID"] == 0
        assert row["NewPriority"] == 8
        assert row["OldPriority"] == 0
        assert row["WaitReason"] == "Executive"
        assert row["WaitMode"] == "KernelMode"
        assert row["OldThreadState"] == "Running"
        assert row["NewPID"] == 4
        assert row["Extra4"] == 2

    def test_v5_reverse_switch(self):
        """Switch-out side: New=Idle, Old=3388, OldState=Waiting."""
        row = decode_cswitch_v5(
            _PAYLOAD_2,
            hdr={"TimeStamp": 56763, "ProcessorNumber": 62, "ProcessId": 0, "ThreadId": 0},
        )
        assert row is not None
        assert row["NewTID"] == 0
        assert row["OldTID"] == 3388
        assert row["NewPriority"] == 0
        assert row["OldPriority"] == 8
        assert row["WaitReason"] == "Executive"
        assert row["OldThreadState"] == "Waiting"
        assert row["Extra4"] == 8

    def test_cpu_from_buffer_context_not_payload(self):
        """CPU must come from BufferContext.ProcessorNumber, not the payload's
        OldThreadWaitIdealProcessor byte (the two coincide on sample #1 but
        diverge in general). Verified explicitly with a synthetic header CPU
        that does not match the payload's ideal-processor byte."""
        row = decode_cswitch_v5(
            _PAYLOAD_3,
            hdr={"ProcessorNumber": 7, "TimeStamp": 12345, "ProcessId": 4, "ThreadId": 3388},
        )
        assert row is not None
        # Payload's OldThreadWaitIdealProcessor is 64; header says CPU=7. We
        # must trust the header.
        assert row["CPU"] == 7

    def test_v5_extra4_preserved(self):
        """Extra4 is not silently dropped — design doc requires it surface."""
        row = decode_cswitch_v5(_PAYLOAD_1, hdr={"ProcessorNumber": 62})
        assert row is not None
        assert row["Extra4"] == 2

    def test_v4_short_payload_no_extra4(self):
        """v=4 (24 bytes) decodes cleanly without an Extra4 field."""
        v4 = _PAYLOAD_1[:24]
        assert len(v4) == 24
        row = decode_cswitch_v5(v4, hdr={"ProcessorNumber": 62, "TimeStamp": 1})
        assert row is not None
        assert row["NewTID"] == 3388
        assert row["WaitReason"] == "Executive"
        assert row["OldThreadState"] == "Running"
        assert row["Extra4"] is None

    def test_truncated_payload_returns_none(self):
        """A payload shorter than the v=4 common header (24 bytes) must not
        crash — the decoder returns None so callers can skip the row."""
        for bad_len in (0, 1, 8, 16, 23):
            assert decode_cswitch_v5(_PAYLOAD_1[:bad_len], hdr={}) is None

    def test_empty_payload_returns_none(self):
        assert decode_cswitch_v5(b"", hdr={"ProcessorNumber": 0}) is None

    def test_payload_thread_id_used_when_hdr_missing(self):
        """If the caller didn't pass ThreadId, fall back to the payload's
        NewThreadId field rather than emitting None."""
        row = decode_cswitch_v5(_PAYLOAD_1, hdr={"ProcessorNumber": 62})
        assert row is not None
        # No ThreadId in hdr → use payload's NewThreadId (3388).
        assert row["NewTID"] == 3388

    def test_default_cpu_when_hdr_missing(self):
        """Decoder doesn't blow up when the header is empty; CPU defaults
        to -1 sentinel."""
        row = decode_cswitch_v5(_PAYLOAD_1, hdr={})
        assert row is not None
        assert row["CPU"] == -1

    def test_sentinel_hdr_pid_tid_falls_back_to_payload(self):
        """Regression: real kernel CSwitch events arrive with EventHeader
        ProcessId / ThreadId set to ``0xFFFFFFFF`` (kernel scheduling
        events have no thread context). The decoder must detect that
        sentinel and fall back to the payload-supplied NewThreadId,
        leaving NewPID=0 for the downstream TID-to-PID join to fill.

        Before the fix all 393K cswitch rows on the VM-Server trace had
        NewTID=0xFFFFFFFF, which made
        ``get_network_wait_chain(trace_id, "nslookup")`` return
        "No threads matched process substring `nslookup`" — see
        ``udp-perf/docs/wpr-mcp-native-etw-verification.md`` §"Residual
        Issues 2".
        """
        SENTINEL = 0xFFFFFFFF
        row = decode_cswitch_v5(
            _PAYLOAD_1,
            hdr={
                "TimeStamp": 1,
                "ProcessorNumber": 0,
                "ProcessId": SENTINEL,
                "ThreadId": SENTINEL,
            },
        )
        assert row is not None
        # Payload says NewThreadId=3388 — header sentinel must not win.
        assert row["NewTID"] == 3388
        assert row["NewPID"] == 0  # left for downstream TID-to-PID fill

    def test_emits_canonical_schema_keys(self):
        """The dict shape must match the unified schema documented in
        wpa_exporter._handle_cswitch so downstream code is uniform."""
        row = decode_cswitch_v5(_PAYLOAD_1, hdr={"ProcessorNumber": 0})
        assert row is not None
        expected = {
            "TimeStamp", "OldProcessName", "OldPID", "OldTID",
            "NewProcessName", "NewPID", "NewTID",
            "WaitReason", "WaitMode", "OldThreadState",
            "NewPriority", "OldPriority", "CPU", "Extra4",
        }
        assert expected == set(row.keys())


class TestEnumLookup:
    """The WaitReason / WaitMode / OldThreadState enum strings must match
    what xperf prints. Sanity-check the common values directly via the
    decoder (no exposed helper for the enum tables)."""

    def _decode_with_byte(self, off: int, value: int) -> dict:
        """Helper: clone PAYLOAD_1, overwrite one byte, decode."""
        buf = bytearray(_PAYLOAD_1)
        buf[off] = value & 0xFF
        row = decode_cswitch_v5(bytes(buf), hdr={"ProcessorNumber": 0})
        assert row is not None
        return row

    def test_wait_reason_executive(self):
        row = self._decode_with_byte(12, 0)
        assert row["WaitReason"] == "Executive"

    def test_wait_reason_wr_queue(self):
        # Index 15 in the WAIT_REASON table.
        row = self._decode_with_byte(12, 15)
        assert row["WaitReason"] == "WrQueue"

    def test_wait_reason_wr_dispatch_int(self):
        row = self._decode_with_byte(12, 31)
        assert row["WaitReason"] == "WrDispatchInt"

    def test_wait_mode_kernel(self):
        row = self._decode_with_byte(13, 0)
        assert row["WaitMode"] == "KernelMode"

    def test_wait_mode_user(self):
        row = self._decode_with_byte(13, 1)
        assert row["WaitMode"] == "UserMode"

    def test_thread_state_running(self):
        row = self._decode_with_byte(14, 2)
        assert row["OldThreadState"] == "Running"

    def test_thread_state_waiting(self):
        row = self._decode_with_byte(14, 5)
        assert row["OldThreadState"] == "Waiting"

    def test_thread_state_standby(self):
        row = self._decode_with_byte(14, 3)
        assert row["OldThreadState"] == "Standby"

    def test_out_of_range_enum_falls_back_to_int(self):
        # Set OldThreadState to 99 — outside the table. Should fall back to
        # the raw integer rendered as a string, not crash.
        row = self._decode_with_byte(14, 99)
        assert row["OldThreadState"] == "99"
