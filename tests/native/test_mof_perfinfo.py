"""Tests for :mod:`etw_analyzer.native.mof.perfinfo`.

Synthetic-payload tests cover the SampledProfile / DPC / ISR decoders.
The payload layouts are documented in the design doc §4.2 and validated
against feasibility experiment ``exp4c_stacks_pair.py`` (the SampledProfile
``<QII`` layout).
"""

from __future__ import annotations

import struct

import pytest

from etw_analyzer.native.mof.perfinfo import (
    HANDLERS,
    PROVIDER_GUID,
    decode_dpc,
    decode_dpc_threaded,
    decode_dpc_timer,
    decode_isr,
    decode_sampled_profile,
)


# A synthetic SampledProfile payload built from the same shape exp4c
# captured: IP=0xfffff806b09383ac, TID=8260, Count=1.
_SAMPLED = struct.pack("<QII", 0xFFFFF806B09383AC, 8260, 1)
assert len(_SAMPLED) == 16


# Synthetic DPC payload: InitialTime=0x1122334455667788, Routine=0xfffff80012345678.
_DPC = struct.pack("<QQ", 0x1122334455667788, 0xFFFFF80012345678)
assert len(_DPC) == 16


class TestSampledProfile:
    def test_basic_decode(self):
        row = decode_sampled_profile(
            _SAMPLED,
            hdr={"TimeStamp": 4250801903602, "ProcessorNumber": 79, "ProcessId": 1234},
        )
        assert row is not None
        assert row["TimeStamp"] == 4250801903602
        assert row["CPU"] == 79
        assert row["PID"] == 1234
        assert row["Weight"] == 1
        assert row["InstructionPointer"] == 0xFFFFF806B09383AC
        assert row["PayloadThreadId"] == 8260

    def test_zero_count_normalizes_to_weight_one(self):
        """Count=0 sentinels (rare) must produce Weight=1, not zero."""
        payload = struct.pack("<QII", 0x1234, 8260, 0)
        row = decode_sampled_profile(payload, hdr={"ProcessorNumber": 0})
        assert row is not None
        assert row["Weight"] == 1

    def test_large_count_preserved(self):
        """Count>1 (multi-sample compression) must survive verbatim."""
        payload = struct.pack("<QII", 0x1234, 8260, 7)
        row = decode_sampled_profile(payload, hdr={"ProcessorNumber": 1})
        assert row is not None
        assert row["Weight"] == 7

    def test_too_short_returns_none(self):
        for bad_len in (0, 1, 8, 15):
            assert decode_sampled_profile(_SAMPLED[:bad_len], hdr={}) is None

    def test_canonical_schema(self):
        """Schema must match parsing.wpa_exporter._handle_sampled_profile so
        downstream code doesn't special-case the mode."""
        row = decode_sampled_profile(_SAMPLED, hdr={"ProcessorNumber": 0})
        assert row is not None
        expected_keys = {
            "TimeStamp", "Process Name", "PID", "CPU",
            "Module", "Function", "Weight",
            "InstructionPointer", "PayloadThreadId",
        }
        assert expected_keys == set(row.keys())

    def test_cpu_from_buffer_context(self):
        """CPU must come from ProcessorNumber, not from the payload."""
        row = decode_sampled_profile(_SAMPLED, hdr={"ProcessorNumber": 42})
        assert row is not None
        assert row["CPU"] == 42


class TestDpcIsr:
    def test_decode_dpc(self):
        row = decode_dpc(_DPC, hdr={"TimeStamp": 1000, "ProcessorNumber": 3})
        assert row is not None
        assert row["Type"] == "DPC"
        assert row["TimeStamp"] == 1000
        assert row["CPU"] == 3
        assert row["InitialTime"] == 0x1122334455667788
        assert row["Routine"] == 0xFFFFF80012345678

    def test_decode_dpc_threaded(self):
        row = decode_dpc_threaded(_DPC, hdr={"ProcessorNumber": 0})
        assert row is not None
        assert row["Type"] == "ThreadedDPC"

    def test_decode_dpc_timer(self):
        row = decode_dpc_timer(_DPC, hdr={"ProcessorNumber": 0})
        assert row is not None
        assert row["Type"] == "TimerDPC"

    def test_decode_isr(self):
        row = decode_isr(_DPC, hdr={"ProcessorNumber": 0})
        assert row is not None
        assert row["Type"] == "ISR"

    def test_too_short_returns_none(self):
        for fn in (decode_dpc, decode_isr, decode_dpc_threaded, decode_dpc_timer):
            assert fn(b"\x00" * 8, hdr={}) is None


class TestHandlers:
    def test_dispatch_keys(self):
        """The dispatch table must cover every PerfInfo opcode the design doc
        names (46 = SampledProfile, 66-69 = DPC family)."""
        expected_opcodes = {46, 66, 67, 68, 69}
        actual_opcodes = {opcode for (opcode, _v) in HANDLERS}
        assert expected_opcodes == actual_opcodes

    def test_provider_guid_lowercase(self):
        assert PROVIDER_GUID == PROVIDER_GUID.lower()
        assert len(PROVIDER_GUID) == 36
