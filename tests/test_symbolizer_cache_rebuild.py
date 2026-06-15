"""Regression tests for symbolizer rebuild on dotnet/native cache hit.

Covers two defects fixed in this PR:

1. build_symbolizer_from_dotnet_images previously ignored raw_csv["image"]
   (the combined key used by the sidecar's cache-hit hydration path), so
   every cache-hit load left trace.symbolizer = None and kernel addresses
   resolved to "unknown+0x...".

2. _register_cached_trace never called the symbolizer builder on cache hits
   in "dotnet" (or "native") mode; the fix calls
   build_symbolizer_from_dotnet_images after register_trace().

These tests use a synthetic stub Symbolizer so they run on any host
(no Windows dbghelp required).
"""

from __future__ import annotations

import pandas as pd
import pytest

# Pre-import the real package so the package namespace (with __path__)
# exists in sys.modules before any fixture patches Symbolizer on it.
# This prevents the "not a package" error that occurs when a stub
# ModuleType replaces a real package and submodule imports fail.
import etw_analyzer.native as _native_pkg
import etw_analyzer.native.aggregation_worker_adapters  # noqa: F401 (ensure submodule is cached)
from etw_analyzer.native.aggregation_worker_adapters import (
    build_symbolizer_from_dotnet_images,
)


# ---------------------------------------------------------------------------
# Stub Symbolizer -- injected so tests run without real dbghelp
# ---------------------------------------------------------------------------

class _StubSymbolizer:
    """Records add_module calls; resolve() returns a placeholder."""

    def __init__(self, symbol_path=None):
        self._modules: dict[int, tuple[int, str]] = {}

    def add_module(self, base: int, size: int, file_name: str) -> None:
        self._modules[base] = (size, file_name)

    def resolve(self, address: int) -> str:
        for base, (size, name) in self._modules.items():
            if base <= address < base + max(size, 1):
                return f"{name}+0x{address - base:x}"
        return f"unknown+0x{address:x}"


def _make_image_row(base: int, size: int, name: str) -> dict:
    return {"ImageBase": base, "ImageSize": size, "FileName": name}


@pytest.fixture(autouse=True)
def _stub_symbolizer(monkeypatch):
    """Patch Symbolizer on the already-imported etw_analyzer.native package.

    The function under test does ``from etw_analyzer.native import Symbolizer``
    at call time. Patching the attribute on the already-loaded package object
    ensures the dynamic import picks up the stub without replacing the package
    namespace (which would break submodule lookups).
    """
    monkeypatch.setattr(_native_pkg, "Symbolizer", _StubSymbolizer, raising=False)


# ---------------------------------------------------------------------------
# Helper: minimal TraceData-like object
# ---------------------------------------------------------------------------

class _FakeTrace:
    def __init__(self, raw_csv: dict):
        self.raw_csv = raw_csv
        self.symbolizer = None
        self.symbol_path = None


# ---------------------------------------------------------------------------
# Test 1: combined "image" key (cache-hit path)
# ---------------------------------------------------------------------------

def test_combined_image_key_populates_symbolizer():
    """Cache-hit path: raw_csv["image"] contains both Load and DCStart rows.

    build_symbolizer_from_dotnet_images must fall back to the combined key
    when canonical Image/Load and Image/DCStart are absent (empty or missing),
    and register all rows including the kernel-mode driver.
    """
    user_row = _make_image_row(0x00007FF600000000, 0x10000, "user_app.exe")
    kernel_row = _make_image_row(0xFFFFF80100000000, 0x800000, "ntoskrnl.exe")
    combined_df = pd.DataFrame([user_row, kernel_row])

    trace = _FakeTrace(raw_csv={"image": combined_df})
    result = build_symbolizer_from_dotnet_images(trace)

    assert result is True, "build_symbolizer_from_dotnet_images should return True"
    assert trace.symbolizer is not None, "symbolizer must be set after successful build"

    modules = trace.symbolizer._modules
    assert len(modules) == 2, f"expected 2 modules registered, got {len(modules)}: {modules}"
    assert 0x00007FF600000000 in modules, "user-mode module not registered"
    assert 0xFFFFF80100000000 in modules, "kernel-mode driver not registered"


def test_combined_image_key_deduplicates_by_base():
    """Duplicate ImageBase rows in the combined parquet are deduplicated."""
    row1 = _make_image_row(0xFFFFF80100000000, 0x800000, "ntoskrnl.exe")
    row2 = _make_image_row(0xFFFFF80100000000, 0x800000, "ntoskrnl.exe")  # duplicate
    combined_df = pd.DataFrame([row1, row2])

    trace = _FakeTrace(raw_csv={"image": combined_df})
    build_symbolizer_from_dotnet_images(trace)

    assert len(trace.symbolizer._modules) == 1, "duplicate base should be registered once"


# ---------------------------------------------------------------------------
# Test 2: canonical keys still work (backward compat)
# ---------------------------------------------------------------------------

def test_canonical_keys_image_load_and_dcstart():
    """Canonical Image/Load and Image/DCStart keys must still work correctly.

    This is the pre-cache-hit path used by fresh native/dotnet extractions.
    Both keys may be present simultaneously; all rows from both are merged
    before dedup.
    """
    load_row = _make_image_row(0x00007FF600000000, 0x10000, "user_app.exe")
    dcstart_row = _make_image_row(0xFFFFF80100000000, 0x800000, "ntoskrnl.exe")

    trace = _FakeTrace(raw_csv={
        "Image/Load": pd.DataFrame([load_row]),
        "Image/DCStart": pd.DataFrame([dcstart_row]),
    })
    result = build_symbolizer_from_dotnet_images(trace)

    assert result is True
    assert trace.symbolizer is not None
    modules = trace.symbolizer._modules
    assert len(modules) == 2, f"expected 2 modules, got {len(modules)}"
    assert 0x00007FF600000000 in modules
    assert 0xFFFFF80100000000 in modules


def test_canonical_keys_take_precedence_over_combined():
    """When canonical keys have rows, the combined 'image' key is NOT consulted.

    The combined fallback only activates when both canonical sources are empty.
    If canonical keys have data, adding a combined key with different rows
    must not inflate the module count.
    """
    load_row = _make_image_row(0x00007FF600000000, 0x10000, "user_app.exe")
    # "image" combined key has an extra row that should NOT be picked up
    combined_row = _make_image_row(0xFFFFF80200000000, 0x100000, "extra_driver.sys")

    trace = _FakeTrace(raw_csv={
        "Image/Load": pd.DataFrame([load_row]),
        "image": pd.DataFrame([combined_row]),
    })
    result = build_symbolizer_from_dotnet_images(trace)

    assert result is True
    modules = trace.symbolizer._modules
    assert len(modules) == 1, (
        "combined key must not be consulted when canonical keys have rows; "
        f"got modules: {modules}"
    )
    assert 0x00007FF600000000 in modules


# ---------------------------------------------------------------------------
# Test 3: no image rows -> returns False, symbolizer stays None
# ---------------------------------------------------------------------------

def test_no_image_rows_returns_false():
    """When all image sources are absent/empty, symbolizer must stay None."""
    trace = _FakeTrace(raw_csv={})
    result = build_symbolizer_from_dotnet_images(trace)

    assert result is False
    assert trace.symbolizer is None


def test_empty_dataframes_returns_false():
    """Empty DataFrames in all image slots must also return False."""
    trace = _FakeTrace(raw_csv={
        "Image/Load": pd.DataFrame(),
        "Image/DCStart": pd.DataFrame(),
        "image": pd.DataFrame(),
    })
    result = build_symbolizer_from_dotnet_images(trace)

    assert result is False
    assert trace.symbolizer is None


# ---------------------------------------------------------------------------
# Test 4: idempotent -- existing symbolizer is not replaced
# ---------------------------------------------------------------------------

def test_existing_symbolizer_not_replaced():
    """If trace.symbolizer is already set, the function returns True immediately."""
    existing = _StubSymbolizer()
    trace = _FakeTrace(raw_csv={"image": pd.DataFrame([_make_image_row(0x1000, 0x1000, "a.dll")])})
    trace.symbolizer = existing

    result = build_symbolizer_from_dotnet_images(trace)

    assert result is True
    assert trace.symbolizer is existing, "existing symbolizer must not be replaced"
    assert len(trace.symbolizer._modules) == 0, "no add_module should have been called"
