"""Regression coverage for DBI PDB age and authoritative processor metadata."""

from __future__ import annotations

import struct
from pathlib import Path

import pandas as pd
import pytest

from etw_analyzer.native import config as native_config
from etw_analyzer.tools import symbol_diagnostics, trace_mgmt
from etw_analyzer.tools.cpu_sampling import _resolve_deferred_instruction_pointers
from etw_analyzer.tools.system_info import _metadata_summary
from etw_analyzer.trace_state import TraceData, clear_traces, register_trace


_PDB_GUID = "01234567-89AB-CDEF-1020-304050607080"
_PDB_GUID_NODASH = _PDB_GUID.replace("-", "")
_PDB_GUID_BYTES = bytes.fromhex("67452301AB89EFCD1020304050607080")


@pytest.fixture(autouse=True)
def _isolate_traces():
    clear_traces()
    native_config.reset_auto_cache()
    yield
    clear_traces()
    native_config.reset_auto_cache()


def _build_pdb_with_distinct_ages(
    path: Path,
    *,
    guid_bytes: bytes = _PDB_GUID_BYTES,
    info_age: int = 2,
    dbi_age: int = 1,
) -> None:
    """Write a minimal MSF 7 PDB with separate Info and DBI ages.

    Stream 1 is the PDB information stream. It supplies the exact GUID but
    intentionally carries age 2. Stream 3 is the DBI stream; its header carries
    age 1, matching the age recorded by the PE CodeView RSDS record and ETL
    image identity. Microsoft symchk reports this value as ``PdbDbiAge``.
    """

    page_size = 512
    magic = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"
    stream0 = b"old directory".ljust(32, b"\x00")
    pdb_stream = (
        struct.pack("<III", 20000404, 0x12345678, info_age)
        + guid_bytes
        # Empty named-stream map: zero-byte string table followed by an empty
        # serialized hash table (size, capacity, present/deleted bit vectors).
        + struct.pack("<IIIII", 0, 0, 1, 0, 0)
    )
    dbi_stream = struct.pack("<iII", -1, 19990903, dbi_age).ljust(64, b"\x00")

    # 0=superblock, 1=directory root, 2=directory, 3/4/5=streams 0/1/3.
    stream_sizes = [len(stream0), len(pdb_stream), 0xFFFFFFFF, len(dbi_stream)]
    directory = struct.pack("<I", len(stream_sizes))
    directory += struct.pack("<4I", *stream_sizes)
    directory += struct.pack("<III", 3, 4, 5)

    superblock = bytearray(magic)
    superblock += struct.pack("<I", page_size)
    superblock += struct.pack("<I", 1)
    superblock += struct.pack("<I", 6)
    superblock += struct.pack("<I", len(directory))
    superblock += struct.pack("<I", 0)
    superblock += struct.pack("<I", 1)

    data = bytearray(page_size * 6)

    def put(block: int, payload: bytes) -> None:
        start = block * page_size
        data[start:start + len(payload)] = payload

    put(0, bytes(superblock))
    put(1, struct.pack("<I", 2))
    put(2, directory)
    put(3, stream0)
    put(4, pdb_stream)
    put(5, dbi_stream)
    path.write_bytes(data)


def _register_symbol_trace(
    tmp_path: Path,
    *,
    trace_guid: str = _PDB_GUID,
    trace_age: int = 1,
    trace_id: str = "trace_dbi_age",
    symbolizer=None,
) -> TraceData:
    etl = tmp_path / f"{trace_id}.etl"
    etl.write_bytes(b"synthetic")
    trace = TraceData(
        trace_id=trace_id,
        etl_path=etl,
        export_dir=tmp_path / f".export-{trace_id}",
        symbol_path=str(tmp_path),
        mode="dotnet",
    )
    trace.raw_csv["image"] = pd.DataFrame([{
        "FileName": r"\Windows\System32\drivers\sample.sys",
        "ImageBase": 0x100000,
        "ImageSize": 0x10000,
        "PdbGuid": trace_guid,
        "PdbAge": trace_age,
        "PdbName": "sample.pdb",
    }])
    trace.raw_csv["cpu_sampling"] = pd.DataFrame({
        "Process Name": ["System"],
        "PID": [4],
        "Weight": [100],
        "% Weight": [100.0],
        "Module": ["sample.sys"],
        "Function": ["SampleFunction"],
        "SymbolSource": ["pdb"],
    })
    trace.symbolizer = symbolizer
    register_trace(trace)
    return trace


def test_pdb_identity_uses_info_guid_and_dbi_age(tmp_path: Path):
    pdb = tmp_path / "sample.pdb"
    _build_pdb_with_distinct_ages(pdb, info_age=2, dbi_age=1)

    assert symbol_diagnostics.read_pdb_signature(pdb) == (_PDB_GUID_NODASH, 1)


@pytest.mark.parametrize(
    ("trace_guid", "trace_age", "expected"),
    [
        (_PDB_GUID, 1, "match"),
        ("11234567-89AB-CDEF-1020-304050607080", 1, "mismatch"),
        (_PDB_GUID, 2, "mismatch"),
    ],
    ids=["dbi-age-match", "guid-mismatch", "dbi-age-mismatch"],
)
def test_strict_pdb_verdict_uses_exact_guid_and_dbi_age(
    tmp_path: Path,
    trace_guid: str,
    trace_age: int,
    expected: str,
):
    _build_pdb_with_distinct_ages(tmp_path / "sample.pdb")
    trace = _register_symbol_trace(
        tmp_path,
        trace_guid=trace_guid,
        trace_age=trace_age,
        trace_id=f"trace_{trace_age}_{trace_guid[:2]}",
    )

    verdict = trace_mgmt._trace_pdb_disk_verdict(
        trace, "sample.sys", str(tmp_path)
    )

    assert verdict == expected


def test_check_and_diagnose_agree_on_dbi_identity(tmp_path: Path):
    _build_pdb_with_distinct_ages(tmp_path / "sample.pdb")
    trace = _register_symbol_trace(tmp_path)

    status = trace_mgmt.check_symbols(trace.trace_id)
    diagnostic = symbol_diagnostics.diagnose_symbol_load(
        trace.trace_id, "sample.sys"
    )

    status_row = [
        line for line in status.splitlines()
        if "sample.sys" in line and "|" in line
    ]
    assert status_row
    assert "OK" in status_row[0]
    assert "MISMATCHED_PDB" not in status_row[0]
    assert "YES (trace)" in diagnostic
    assert "| 1 | YES (trace) |" in diagnostic


class _AvailableSymbolizer:
    def is_available(self) -> bool:
        return True


def test_resolve_symbols_reports_requested_module_not_loaded(tmp_path: Path):
    trace = _register_symbol_trace(
        tmp_path,
        trace_id="trace_missing_requested",
        symbolizer=_AvailableSymbolizer(),
    )

    output = trace_mgmt.resolve_symbols(trace.trace_id, modules="missing.sys")

    assert "missing.sys" in output
    assert any(
        word in output.lower()
        for word in ("missing", "unresolved", "not loaded", "not found")
    )
    assert "all symbols resolved successfully" not in output.lower()


class _UntrustedNameSymbolizer:
    def __init__(self, source: str):
        self.source = source

    def bulk_resolve_with_source(self, addresses):
        return {
            int(address): ("sample.sys!PlausibleButWrong+0x0", self.source)
            for address in addresses
        }


@pytest.mark.parametrize("source", ["mismatched", "unknown"])
def test_untrusted_dbghelp_names_are_not_exposed_as_functions(source: str):
    trace = TraceData(
        trace_id=f"trace_untrusted_{source}",
        etl_path=Path(r"C:\traces\synthetic.etl"),
        export_dir=Path(r"C:\traces\.synthetic"),
        mode="dotnet",
    )
    trace.symbolizer = _UntrustedNameSymbolizer(source)
    samples = pd.DataFrame({
        "InstructionPointer": [0x1010],
        "Module": ["sample.sys"],
        "Function": [""],
        "Weight": [1],
    })

    resolved = _resolve_deferred_instruction_pointers(
        trace,
        samples,
        module_col="Module",
        function_col="Function",
    )

    assert resolved.loc[0, "SymbolSource"] == source
    assert resolved.loc[0, "Function"] == ""
    assert "PlausibleButWrong" not in resolved.loc[0, "Function"]


def _metadata_trace(raw_csv: dict[str, pd.DataFrame]) -> TraceData:
    return TraceData(
        trace_id="trace_processor_metadata",
        etl_path=Path(r"C:\traces\synthetic.etl"),
        export_dir=Path(r"C:\traces\.synthetic"),
        mode="dotnet",
        raw_csv=raw_csv,
    )


def test_dotnet_header_processor_count_overrides_sparse_observation():
    observed = pd.DataFrame({"CPU": [0, 59], "TimeStamp": [100, 200]})
    header = pd.DataFrame({"NumberOfProcessors": [80]})
    cached_metadata = pd.DataFrame({"NumberOfProcessors": [80]})
    trace = _metadata_trace({
        "SampledProfile": observed,
        "EventTrace/Header": header,
        "trace_metadata": cached_metadata,
    })

    trace_mgmt._populate_metadata(trace)

    assert trace.cpu_count == 80
    assert _metadata_summary(trace)["NumberOfProcessors"] == 80
    assert int(trace.raw_csv["trace_metadata"].iloc[0]["NumberOfProcessors"]) == 80


def test_dotnet_processor_count_falls_back_to_observed_cpu_without_header():
    observed = pd.DataFrame({"CPU": [0, 59], "TimeStamp": [100, 200]})
    trace = _metadata_trace({"SampledProfile": observed})

    trace_mgmt._populate_metadata(trace)

    assert trace.cpu_count == 60
    assert _metadata_summary(trace)["NumberOfProcessors"] == 60
