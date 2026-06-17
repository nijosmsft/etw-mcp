"""M2 regression tests: image schema identity columns + symbolizer identity seam.

Tests covered:
  1. Parquet round-trip: image rows with PdbGuid/PdbAge/PdbName/TimeDateStamp
     written via rows_to_table survive read-back with correct types and values.
  2. event_schema_version is embedded in the image parquet metadata at the
     new value (EVENT_SCHEMA_VERSION == 2).
  3. build_symbolizer_from_dotnet_images populates trace.pdb_identity when
     raw_csv["image"] rows carry the 4 identity columns.
  4. build_symbolizer_from_dotnet_images still works (returns True, registers
     modules) when identity columns are absent (backward compat for callers
     that don't yet emit them).
"""

from __future__ import annotations

import io
from pathlib import Path

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import pytest

import etw_analyzer.native as _native_pkg
from etw_analyzer.native.schemas import (
    EVENT_SCHEMA_VERSION,
    EVENT_SCHEMAS,
    rows_to_table,
)
from etw_analyzer.native.aggregation_worker_adapters import (
    build_symbolizer_from_dotnet_images,
)


# ---------------------------------------------------------------------------
# Stub Symbolizer (mirrors test_symbolizer_cache_rebuild.py)
# ---------------------------------------------------------------------------

class _StubSymbolizer:
    def __init__(self, symbol_path=None):
        self._modules: dict[int, tuple[int, str]] = {}

    def add_module(self, base: int, size: int, file_name: str, **kwargs) -> None:
        self._modules[base] = (size, file_name)


@pytest.fixture(autouse=True)
def _stub_symbolizer(monkeypatch):
    monkeypatch.setattr(_native_pkg, "Symbolizer", _StubSymbolizer, raising=False)


class _FakeTrace:
    def __init__(self, raw_csv: dict):
        self.raw_csv = raw_csv
        self.symbolizer = None
        self.symbol_path = None
        self.pdb_identity: dict = {}


# ---------------------------------------------------------------------------
# Test 1: parquet round-trip carries the 4 identity columns
# ---------------------------------------------------------------------------

def test_image_schema_parquet_round_trip(tmp_path: Path):
    """rows_to_table + parquet write/read must preserve PdbGuid, PdbAge,
    PdbName, and TimeDateStamp for a kernel-mode image row.
    """
    row = {
        "EventSequence": 1,
        "TimeStampQpc": 1234567890,
        "CPU": 0,
        "ProcessId": 4,
        "ImageBase": 0xFFFFF8057E600000,
        "ImageSize": 0x900000,
        "FileName": r"\SystemRoot\System32\ntoskrnl.exe",
        "Type": "DCStart",
        "TimeDateStamp": 0x6471A2C0,
        "PdbGuid": "AFB1E3B1-3754-8BA7-3B92-C060D6D5605F",
        "PdbAge": 1,
        "PdbName": "ntkrnlmp.pdb",
    }

    table = rows_to_table("image", [row])

    # Round-trip via parquet bytes (no file I/O needed).
    buf = io.BytesIO()
    pq.write_table(table, buf)
    buf.seek(0)
    reloaded = pq.read_table(buf).to_pandas()

    assert reloaded["PdbGuid"].iloc[0] == "AFB1E3B1-3754-8BA7-3B92-C060D6D5605F", (
        f"PdbGuid must survive round-trip; got {reloaded['PdbGuid'].iloc[0]!r}"
    )
    assert int(reloaded["PdbAge"].iloc[0]) == 1, (
        f"PdbAge must survive round-trip as integer; got {reloaded['PdbAge'].iloc[0]!r}"
    )
    assert reloaded["PdbName"].iloc[0] == "ntkrnlmp.pdb", (
        f"PdbName must survive round-trip; got {reloaded['PdbName'].iloc[0]!r}"
    )
    assert int(reloaded["TimeDateStamp"].iloc[0]) == 0x6471A2C0, (
        f"TimeDateStamp must survive round-trip; got {reloaded['TimeDateStamp'].iloc[0]!r}"
    )
    assert reloaded["ImageBase"].iloc[0] == 0xFFFFF8057E600000


def test_image_schema_null_identity_round_trip(tmp_path: Path):
    """Rows without RSDS identity (nulls for all 4 columns) must also
    round-trip without error.
    """
    row = {
        "EventSequence": 2,
        "TimeStampQpc": 999,
        "CPU": 1,
        "ProcessId": 1234,
        "ImageBase": 0x7FF600000000,
        "ImageSize": 0x10000,
        "FileName": r"C:\Windows\System32\user32.dll",
        "Type": "Load",
        # identity columns intentionally absent -> will be None
    }

    table = rows_to_table("image", [row])
    buf = io.BytesIO()
    pq.write_table(table, buf)
    buf.seek(0)
    reloaded = pq.read_table(buf).to_pandas()

    assert pd.isna(reloaded["PdbGuid"].iloc[0]), "PdbGuid should be null when absent"
    assert pd.isna(reloaded["PdbAge"].iloc[0]), "PdbAge should be null when absent"
    assert pd.isna(reloaded["PdbName"].iloc[0]), "PdbName should be null when absent"
    assert pd.isna(reloaded["TimeDateStamp"].iloc[0]), "TimeDateStamp should be null when absent"


def test_image_schema_version_in_parquet_metadata():
    """The image parquet schema must embed the current EVENT_SCHEMA_VERSION."""
    schema = EVENT_SCHEMAS["image"].schema
    raw_version = schema.metadata.get(b"wpr_mcp_schema_version")
    assert raw_version is not None, "wpr_mcp_schema_version metadata key must be present"
    stored_version = int(raw_version.decode("ascii"))
    assert stored_version == EVENT_SCHEMA_VERSION, (
        f"image schema metadata version must equal EVENT_SCHEMA_VERSION={EVENT_SCHEMA_VERSION}, "
        f"got {stored_version}"
    )
    assert EVENT_SCHEMA_VERSION == 3, (
        f"Async-load Phase A bumped EVENT_SCHEMA_VERSION to 3; found {EVENT_SCHEMA_VERSION}"
    )


# ---------------------------------------------------------------------------
# Test 2: build_symbolizer_from_dotnet_images populates trace.pdb_identity
# ---------------------------------------------------------------------------

def test_build_symbolizer_populates_pdb_identity_from_combined_key():
    """When raw_csv['image'] has PdbGuid/PdbAge/PdbName/TimeDateStamp columns,
    build_symbolizer_from_dotnet_images must populate trace.pdb_identity with
    the per-base identity dict so M3 can pass exact GUID to add_module.
    """
    row = {
        "ImageBase": 0xFFFFF8057E600000,
        "ImageSize": 0x900000,
        "FileName": r"\SystemRoot\System32\ntoskrnl.exe",
        "PdbGuid": "AFB1E3B1-3754-8BA7-3B92-C060D6D5605F",
        "PdbAge": 1,
        "PdbName": "ntkrnlmp.pdb",
        "TimeDateStamp": 0x6471A2C0,
    }
    trace = _FakeTrace(raw_csv={"image": pd.DataFrame([row])})

    result = build_symbolizer_from_dotnet_images(trace)

    assert result is True
    assert trace.symbolizer is not None

    base = 0xFFFFF8057E600000
    assert base in trace.pdb_identity, (
        f"trace.pdb_identity must contain ntoskrnl's ImageBase {base:#x}"
    )
    identity = trace.pdb_identity[base]
    assert identity["pdb_guid"] == "AFB1E3B1-3754-8BA7-3B92-C060D6D5605F", (
        f"pdb_guid mismatch: {identity['pdb_guid']!r}"
    )
    assert identity["pdb_age"] == 1, f"pdb_age mismatch: {identity['pdb_age']!r}"
    assert identity["pdb_name"] == "ntkrnlmp.pdb", (
        f"pdb_name mismatch: {identity['pdb_name']!r}"
    )
    assert identity["time_date_stamp"] == 0x6471A2C0, (
        f"time_date_stamp mismatch: {identity['time_date_stamp']!r}"
    )


def test_build_symbolizer_pdb_identity_multiple_modules():
    """All modules with RSDS data appear in trace.pdb_identity."""
    rows = [
        {
            "ImageBase": 0xFFFFF8057E600000,
            "ImageSize": 0x900000,
            "FileName": r"\SystemRoot\System32\ntoskrnl.exe",
            "PdbGuid": "AFB1E3B1-3754-8BA7-3B92-C060D6D5605F",
            "PdbAge": 1,
            "PdbName": "ntkrnlmp.pdb",
            "TimeDateStamp": 0x6471A2C0,
        },
        {
            "ImageBase": 0xFFFFF8057FE00000,
            "ImageSize": 0x100000,
            "FileName": r"\SystemRoot\System32\drivers\hal.dll",
            "PdbGuid": "445777BE-1234-ABCD-EF01-020304050607",
            "PdbAge": 2,
            "PdbName": "hal.pdb",
            "TimeDateStamp": 0x64700000,
        },
    ]
    trace = _FakeTrace(raw_csv={"image": pd.DataFrame(rows)})

    build_symbolizer_from_dotnet_images(trace)

    assert len(trace.pdb_identity) == 2
    assert 0xFFFFF8057E600000 in trace.pdb_identity
    assert 0xFFFFF8057FE00000 in trace.pdb_identity
    assert trace.pdb_identity[0xFFFFF8057FE00000]["pdb_name"] == "hal.pdb"


def test_build_symbolizer_pdb_identity_absent_when_no_guid_columns():
    """When raw_csv['image'] has no identity columns, trace.pdb_identity stays
    empty (no crash, no spurious entries).
    """
    row = {
        "ImageBase": 0xFFFFF8057E600000,
        "ImageSize": 0x900000,
        "FileName": r"\SystemRoot\System32\ntoskrnl.exe",
        # No PdbGuid/PdbAge/PdbName/TimeDateStamp columns
    }
    trace = _FakeTrace(raw_csv={"image": pd.DataFrame([row])})

    result = build_symbolizer_from_dotnet_images(trace)

    assert result is True  # symbolizer still built; identity just absent
    assert trace.pdb_identity == {}, (
        "pdb_identity must be empty when row lacks identity columns"
    )
