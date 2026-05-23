"""Tests for :mod:`etw_analyzer.native.decoder`.

These tests don't exercise ``TdhFormatProperty`` directly — that would
require a real EVENT_RECORD from an ETL file, which lives in the
integration test path. Instead we verify the cache plumbing (positive,
negative, provider-wide) and the property descriptor parsing.
"""

from __future__ import annotations

import pytest

from etw_analyzer.native.decoder import (
    EVENT_HEADER_FLAG_32_BIT_HEADER,
    PROPERTY_PARAM_LENGTH,
    PROPERTY_STRUCT,
    TdhDecoder,
    _SchemaEntry,
)


def test_decoder_constructs_clean():
    """A fresh decoder has no schemas and no negative entries."""
    d = TdhDecoder()
    assert d.schema_count() == 0
    assert d.negative_count() == 0


def test_negative_provider_skip_persists():
    """Provider-wide skip should be respected on every subsequent event."""
    d = TdhDecoder()
    d.mark_provider_skip("ce1dbfb4-137e-4da6-87b0-3f59aa102cbc")
    # Internal state check — the public API doesn't expose this list
    # by design, but verifying it directly is acceptable in a test.
    assert "ce1dbfb4-137e-4da6-87b0-3f59aa102cbc" in d._negative_providers


def test_provider_skip_is_case_insensitive():
    d = TdhDecoder()
    d.mark_provider_skip("CE1DBFB4-137E-4DA6-87B0-3F59AA102CBC")
    assert "ce1dbfb4-137e-4da6-87b0-3f59aa102cbc" in d._negative_providers


def test_event_header_flag_32_bit_is_0x20():
    """The header flag constant must match the ``evntcons.h`` value.

    The Phase N4b bug we worked through: 32_BIT_HEADER is 0x20 (NOT
    0x40 as in some older docs). Getting this wrong silently breaks
    POINTER property decoding because TDH is told pointer_size=4
    when the trace was captured on x64.
    """
    assert EVENT_HEADER_FLAG_32_BIT_HEADER == 0x20


def test_schema_entry_slots():
    """The dataclass-like ``_SchemaEntry`` uses __slots__ — make sure
    every documented attribute can be assigned without raising."""
    entry = _SchemaEntry()
    entry.buf = b""
    entry.tei_ptr = None
    entry.properties = [("a", 8, 0, 4, "fixed")]
    entry.provider_name = "X"
    entry.task_name = "T"
    entry.opcode_name = "O"
    # Adding an unknown attribute should fail (__slots__ contract).
    with pytest.raises(AttributeError):
        entry.unknown_attr = 1


def test_property_flag_constants_match_tdh_h():
    """Spot-check the ``EVENT_PROPERTY_INFO.Flags`` bits."""
    assert PROPERTY_STRUCT == 0x1
    assert PROPERTY_PARAM_LENGTH == 0x2
