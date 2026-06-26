"""Regression tests: the native path must consume Image/DCEnd.

The Windows kernel logger emits the already-loaded kernel module rundown
(ntoskrnl, tcpip, ndis, NIC drivers, ...) as Image/DCEnd when the session
STOPS -- not as Image/DCStart. The native in-process symbolizer build used
to read only Image/Load + Image/DCStart, so every kernel sample address
resolved to the "unknown" module (observed: 99.7% unknown). These tests pin
the fix so DCEnd stays wired into the symbolizer and the cache plumbing.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest


def _make_images() -> pd.DataFrame:
    """Image-row schema the symbolizer reads: ImageBase, ImageSize, FileName."""
    base = 0xFFFFF800_AABB0000
    rows = 3
    return pd.DataFrame({
        "EventSequence": list(range(rows)),
        "TimeStampQpc": [1_000_000 + i * 1000 for i in range(rows)],
        "CPU": [0] * rows,
        "PID": [4] * rows,
        "ImageBase": [base + i * 0x100_000 for i in range(rows)],
        "ImageSize": [0x80_000] * rows,
        "TimeDateStamp": [0] * rows,
        "FileName": [f"\\SystemRoot\\system32\\drivers\\krnlmod_{i}.sys" for i in range(rows)],
    })


class _FakeSymbolizer:
    """In-memory stand-in so the test needs no dbghelp/native bindings."""

    def __init__(self, symbol_path=None):
        self.symbol_path = symbol_path
        self.modules: list[tuple[int, int, str]] = []

    def add_module(self, base, size, file_name, **_kwargs) -> None:
        self.modules.append((int(base), int(size), str(file_name)))


def test_native_symbolizer_registers_image_dcend(tmp_path: Path, monkeypatch):
    from etw_analyzer.trace_state import TraceData
    import etw_analyzer.native as native_pkg
    from etw_analyzer.tools import trace_mgmt

    monkeypatch.setattr(native_pkg, "Symbolizer", _FakeSymbolizer, raising=False)

    trace = TraceData(
        trace_id="t", etl_path=tmp_path / "x.etl",
        export_dir=tmp_path, raw_csv={},
    )
    # The kernel module rundown arrives ONLY in Image/DCEnd for this capture.
    results = {"Image/DCEnd": _make_images()}
    trace_mgmt._build_symbolizer_from_images(trace, results)

    assert trace.symbolizer is not None
    assert len(trace.symbolizer.modules) == 3


def test_native_symbolizer_merges_load_and_dcend(tmp_path: Path, monkeypatch):
    from etw_analyzer.trace_state import TraceData
    import etw_analyzer.native as native_pkg
    from etw_analyzer.tools import trace_mgmt

    monkeypatch.setattr(native_pkg, "Symbolizer", _FakeSymbolizer, raising=False)

    trace = TraceData(
        trace_id="t", etl_path=tmp_path / "x.etl",
        export_dir=tmp_path, raw_csv={},
    )
    load = _make_images().copy()
    load["ImageBase"] = [0x00007FF000000000 + i * 0x100_000 for i in range(len(load))]
    results = {"Image/Load": load, "Image/DCEnd": _make_images()}
    trace_mgmt._build_symbolizer_from_images(trace, results)

    # 3 Load + 3 DCEnd, all distinct bases -> 6 registered modules.
    assert len(trace.symbolizer.modules) == 6


def test_image_dcend_in_dumper_event_classes():
    from etw_analyzer.tools import trace_mgmt

    assert "Image/DCEnd" in trace_mgmt._DUMPER_EVENT_CLASSES
    attr, stem = trace_mgmt._DUMPER_EVENT_CLASSES["Image/DCEnd"]
    assert attr == "image_dcend_df"
    assert stem == "image_dcend"
