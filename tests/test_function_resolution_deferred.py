"""Regression tests: function-level symbol resolution after a deferred load.

A normal (large) trace defers per-PDB function symbolization at load time:
``cpu_sampling`` carries module attribution but blank Function, and the raw
per-sample frame (with InstructionPointer) lives in ``sampled_profile.parquet``
on disk (excluded from raw_csv). Two bugs used to make function names never
appear:

1. On a cache hit no symbolizer was rebuilt (image parquets are excluded from
   raw_csv), so on-demand resolution had no resolver.
2. The query tools read the aggregated ``cpu_sampling`` (InstructionPointer
   grouped away), so the on-demand resolver no-oped.

These tests pin the fix: ``get_hot_functions`` / ``get_cpu_samples`` resolve
function names on demand from the raw samples, and the cache loader rehydrates
the image parquets so the symbolizer can be rebuilt.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

import etw_analyzer.tools.cpu_sampling as cs
import etw_analyzer.tools.trace_mgmt as trace_mgmt
from etw_analyzer.trace_state import clear_traces


@pytest.fixture(autouse=True)
def _isolate_traces():
    clear_traces()
    yield
    clear_traces()


# A module spanning [0xF000_0000, 0xF000_0000+0x10000) named "tcpip.sys",
# with two functions at known offsets.
_BASE = 0xF0000000


class _FakeSymbolizer:
    """Resolves addresses in the registered range to tcpip.sys!Func<n>."""

    def __init__(self, symbol_path=None):
        self.symbol_path = symbol_path
        self.modules: list[tuple[int, int, str]] = []

    def add_module(self, base, size, file_name, **_kwargs):
        self.modules.append((int(base), int(size), str(file_name)))

    def _find_module_for_address(self, addr):
        for base, size, name in self.modules:
            if base <= int(addr) < base + size:
                return name
        return "unknown"

    def bulk_resolve_with_source(self, addrs):
        out = {}
        for a in addrs:
            a = int(a)
            if _BASE <= a < _BASE + 0x10000:
                fn = "UdpSend" if (a - _BASE) < 0x8000 else "UdpRecv"
                out[a] = (f"tcpip.sys!{fn}+0x10", "pdb")
            else:
                out[a] = (f"unknown+0x{a:x}", "unknown")
        return out


def _raw_samples() -> pd.DataFrame:
    # 5 samples in UdpSend range, 3 in UdpRecv range, 2 outside (unknown).
    ips = [_BASE + 0x100] * 5 + [_BASE + 0x9000] * 3 + [0x1234] * 2
    return pd.DataFrame({
        "TimeStamp": list(range(len(ips))),
        "Process Name": ["app.exe"] * len(ips),
        "PID": [10] * len(ips),
        "CPU": [0] * len(ips),
        "Module": [""] * len(ips),
        "Function": [""] * len(ips),
        "Weight": [1] * len(ips),
        "InstructionPointer": ips,
    })


def _raw_samples_native_schema() -> pd.DataFrame:
    """Native-decoder schema: no Module / Function / Process Name columns.

    The native event-store writes raw samples without the dumper-normalized
    Module/Function columns, so the resolver must derive Module from the
    symbolizer label, not assume the column pre-exists.
    """
    ips = [_BASE + 0x100] * 5 + [_BASE + 0x9000] * 3 + [0x1234] * 2
    return pd.DataFrame({
        "EventSequence": list(range(len(ips))),
        "TimeStampQpc": list(range(len(ips))),
        "CPU": [0] * len(ips),
        "ProcessId": [10] * len(ips),
        "Weight": [1] * len(ips),
        "InstructionPointer": ips,
    })


def _deferred_cpu_sampling() -> pd.DataFrame:
    # Module attribution present, Function blank — the deferred-load shape.
    return pd.DataFrame({
        "Process Name": ["app.exe", "app.exe"],
        "PID": [10, 10],
        "Weight": [5, 3],
        "% Weight": [50.0, 30.0],
        "Module": ["tcpip.sys", "tcpip.sys"],
        "Function": ["", ""],
        "SymbolSource": ["unknown", "unknown"],
    })


def _make_trace(tmp_path: Path, *, with_symbolizer: bool, raw_on_disk: bool) -> trace_mgmt.TraceData:
    etl = tmp_path / "t.etl"
    etl.write_bytes(b"x")
    export_dir = tmp_path / ".export"
    export_dir.mkdir(parents=True, exist_ok=True)
    trace = trace_mgmt.TraceData(
        trace_id="trace_func", etl_path=etl, export_dir=export_dir,
        symbol_path="srv*C:\\symbols*https://msdl.microsoft.com/download/symbols",
    )
    trace.raw_csv["cpu_sampling"] = _deferred_cpu_sampling()
    if with_symbolizer:
        sym = _FakeSymbolizer()
        sym.add_module(_BASE, 0x10000, "tcpip.sys")
        trace.symbolizer = sym
    if raw_on_disk:
        _raw_samples().to_parquet(export_dir / "sampled_profile.parquet", index=False)
    trace_mgmt.register_trace(trace)
    return trace


def test_resolver_creates_module_column_for_native_schema(tmp_path: Path):
    # Native-schema raw samples have no Module column; the resolver must
    # derive it from the symbolizer label so module filtering works.
    trace = _make_trace(tmp_path, with_symbolizer=True, raw_on_disk=False)
    raw = _raw_samples_native_schema()
    assert "Module" not in raw.columns
    out = cs._resolve_deferred_instruction_pointers(
        trace, raw, module_col="Module", function_col="Function"
    )
    assert "Module" in out.columns
    assert (out["Module"] == "tcpip.sys").sum() == 8  # 5 + 3 resolved
    assert "UdpSend" in set(out["Function"])
    assert "UdpRecv" in set(out["Function"])


def test_get_hot_functions_module_filter_applies_native_schema(tmp_path: Path):
    # Regression: with native-schema samples (no Module column), the module
    # filter must still narrow results to the requested module.
    trace = _make_trace(tmp_path, with_symbolizer=True, raw_on_disk=False)
    _raw_samples_native_schema().to_parquet(
        trace.export_dir / "sampled_profile.parquet", index=False
    )
    out = cs.get_hot_functions("trace_func", modules="tcpip.sys", max_rows=10)
    assert "tcpip.sys" in out
    assert "UdpSend" in out and "UdpRecv" in out


def test_check_symbols_resolves_deferred(tmp_path: Path):
    # check_symbols must reflect on-demand resolution, not the deferred
    # placeholder (which would misreport 0% PDB).
    trace = _make_trace(tmp_path, with_symbolizer=True, raw_on_disk=True)
    out = trace_mgmt.check_symbols("trace_func")
    assert "Resolved on demand" in out
    assert "tcpip.sys" in out
    # The resolved tcpip.sys samples are SymbolSource="pdb" -> not MISSING.
    tcpip_line = next((ln for ln in out.splitlines() if "| tcpip.sys |" in ln), "")
    assert tcpip_line and "MISSING" not in tcpip_line


def test_function_col_all_empty():
    assert cs._function_col_all_empty(_deferred_cpu_sampling(), "Function") is True
    df = _deferred_cpu_sampling()
    df["Function"] = ["UdpSend", ""]
    assert cs._function_col_all_empty(df, "Function") is False
    assert cs._function_col_all_empty(df, "Missing") is True


def test_load_raw_samples_from_parquet(tmp_path: Path):
    trace = _make_trace(tmp_path, with_symbolizer=True, raw_on_disk=True)
    raw = cs._load_raw_samples(trace)
    assert raw is not None
    assert "InstructionPointer" in raw.columns
    assert len(raw) == 10


def test_load_raw_samples_prefers_dumper_df(tmp_path: Path):
    trace = _make_trace(tmp_path, with_symbolizer=True, raw_on_disk=False)
    trace.dumper_df = _raw_samples()
    raw = cs._load_raw_samples(trace)
    assert raw is not None and len(raw) == 10


def test_resolved_samples_memoizes(tmp_path: Path):
    trace = _make_trace(tmp_path, with_symbolizer=True, raw_on_disk=True)
    first = cs._resolved_samples(trace)
    assert first is not None
    assert (first["Function"].astype(str).str.strip() != "").any()
    assert getattr(trace, "_resolved_samples_df", None) is first
    # second call returns the memoized frame
    assert cs._resolved_samples(trace) is first


def test_resolved_samples_none_without_symbolizer(tmp_path: Path):
    trace = _make_trace(tmp_path, with_symbolizer=False, raw_on_disk=True)
    assert cs._resolved_samples(trace) is None


def test_get_hot_functions_resolves_deferred(tmp_path: Path):
    trace = _make_trace(tmp_path, with_symbolizer=True, raw_on_disk=True)
    out = cs.get_hot_functions("trace_func", modules="tcpip.sys", max_rows=10)
    assert "UdpSend" in out
    assert "UdpRecv" in out


def test_get_cpu_samples_function_group_resolves_deferred(tmp_path: Path):
    trace = _make_trace(tmp_path, with_symbolizer=True, raw_on_disk=True)
    out = cs.get_cpu_samples("trace_func", group_by="function", max_rows=10)
    assert "UdpSend" in out
    assert "UdpRecv" in out


def test_get_hot_functions_falls_back_without_symbolizer(tmp_path: Path):
    # No symbolizer (e.g. xperf mode) -> aggregated frame used unchanged,
    # no crash, just blank functions.
    trace = _make_trace(tmp_path, with_symbolizer=False, raw_on_disk=True)
    out = cs.get_hot_functions("trace_func", modules="tcpip.sys", max_rows=10)
    assert "Hot Functions" in out


def test_hydrate_cached_image_frames(tmp_path: Path):
    export_dir = tmp_path / ".export"
    export_dir.mkdir(parents=True, exist_ok=True)
    img = pd.DataFrame({
        "ImageBase": [_BASE], "ImageSize": [0x10000],
        "FileName": ["\\SystemRoot\\system32\\drivers\\tcpip.sys"],
        "PdbGuid": ["AABBCCDD-1122-3344-5566-7788990011"], "PdbAge": [1],
        "PdbName": ["tcpip.pdb"], "TimeDateStamp": [0],
    })
    img.to_parquet(export_dir / "image_dcend.parquet", index=False)
    etl = tmp_path / "t.etl"
    etl.write_bytes(b"x")
    trace = trace_mgmt.TraceData(
        trace_id="trace_hy", etl_path=etl, export_dir=export_dir, symbol_path=None,
    )
    trace_mgmt._hydrate_cached_image_frames(trace)
    assert "Image/DCEnd" in trace.raw_csv
    assert len(trace.raw_csv["Image/DCEnd"]) == 1
