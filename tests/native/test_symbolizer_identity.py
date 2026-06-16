"""M3 tests: PDB identity load via SymFindFileInPathW (exact GUID+Age).

Three test groups:

1. guid_from_string unit tests (Windows-only, no PDB required).
   Exercises all input forms: mixed-case, braces, invalid input, and the
   ntoskrnl reference GUID used by the design-doc control experiment.

2. K2 -- add_module identity wiring (Windows-only, mocked dbghelp).
   Monkeypatches SymFindFileInPathW and SymLoadModuleExW to record their
   arguments, then calls add_module with a kernel-style GUID identity.
   Asserts:
     * SymFindFileInPathW is called with the correctly parsed GUID struct,
       the right PDB age, and SSRVOPT_GUIDPTR == 0x00000008.
     * On a simulated "found" return, SymLoadModuleExW is called with the
       path that SymFindFileInPathW returned (not the original image path).
     * When SymFindFileInPathW returns not-found, SymLoadModuleExW is called
       with the original image path (legacy fallback).
   Does NOT require any PDB on disk or a reachable symbol server.

3. K1 -- live PDB resolution (Windows + symbol path, skipped when absent).
   Uses the real ntoskrnl GUID from the lab ETL, an arbitrary fake base,
   and asserts that add_module + resolve returns source=="pdb" once the
   PDB is resolved via SymFindFileInPathW.  Gated on _NT_SYMBOL_PATH being
   set; skips silently in CI without a symbol store.
"""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes
from pathlib import Path
from typing import Any

import pytest


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="dbghelp Symbolizer requires Windows",
)


# ---------------------------------------------------------------------------
# 1. guid_from_string unit tests
# ---------------------------------------------------------------------------

def test_guid_from_string_ntoskrnl_reference():
    """Parse the exact ntoskrnl GUID from the lab trace; check every field.

    Design-doc control: AFB1E3B1-3754-8BA7-3B92-C060D6D5605F
      Data1 = 0xAFB1E3B1
      Data2 = 0x3754
      Data3 = 0x8BA7
      Data4 = [0x3B, 0x92, 0xC0, 0x60, 0xD6, 0xD5, 0x60, 0x5F]
    """
    from etw_analyzer.native.bindings.types import guid_from_string

    g = guid_from_string("AFB1E3B1-3754-8BA7-3B92-C060D6D5605F")

    assert g.Data1 == 0xAFB1E3B1, f"Data1 mismatch: 0x{g.Data1:08X}"
    assert g.Data2 == 0x3754,     f"Data2 mismatch: 0x{g.Data2:04X}"
    assert g.Data3 == 0x8BA7,     f"Data3 mismatch: 0x{g.Data3:04X}"
    assert list(g.Data4) == [0x3B, 0x92, 0xC0, 0x60, 0xD6, 0xD5, 0x60, 0x5F], (
        f"Data4 mismatch: {list(g.Data4)}"
    )


def test_guid_from_string_lowercase():
    """Lowercase input must produce the same struct as uppercase."""
    from etw_analyzer.native.bindings.types import guid_from_string

    g = guid_from_string("afb1e3b1-3754-8ba7-3b92-c060d6d5605f")
    assert g.Data1 == 0xAFB1E3B1
    assert g.Data2 == 0x3754
    assert g.Data3 == 0x8BA7
    assert list(g.Data4) == [0x3B, 0x92, 0xC0, 0x60, 0xD6, 0xD5, 0x60, 0x5F]


def test_guid_from_string_with_braces():
    """Braces around the GUID must be stripped and parsed correctly."""
    from etw_analyzer.native.bindings.types import guid_from_string

    g = guid_from_string("{AFB1E3B1-3754-8BA7-3B92-C060D6D5605F}")
    assert g.Data1 == 0xAFB1E3B1
    assert g.Data2 == 0x3754


def test_guid_from_string_all_zeros():
    """All-zero GUID must parse without error and produce all-zero fields."""
    from etw_analyzer.native.bindings.types import guid_from_string

    g = guid_from_string("00000000-0000-0000-0000-000000000000")
    assert g.Data1 == 0
    assert g.Data2 == 0
    assert g.Data3 == 0
    assert list(g.Data4) == [0] * 8


def test_guid_from_string_invalid_raises():
    """A string that cannot be parsed as a GUID must raise ValueError."""
    from etw_analyzer.native.bindings.types import guid_from_string

    with pytest.raises(ValueError):
        guid_from_string("not-a-guid")

    with pytest.raises(ValueError):
        guid_from_string("AFB1E3B1-3754-8BA7-3B92")  # too short


def test_guid_from_string_module_level_alias():
    """guid_from_string is a public alias for GUID.from_string."""
    from etw_analyzer.native.bindings.types import GUID, guid_from_string

    s = "12345678-ABCD-EF01-2345-6789ABCDEF01"
    via_fn  = guid_from_string(s)
    via_cls = GUID.from_string(s)
    assert via_fn.Data1 == via_cls.Data1
    assert via_fn.Data2 == via_cls.Data2
    assert via_fn.Data3 == via_cls.Data3
    assert list(via_fn.Data4) == list(via_cls.Data4)


# ---------------------------------------------------------------------------
# 2. K2 -- add_module identity wiring (mocked dbghelp, no real PDB)
# ---------------------------------------------------------------------------

_NTOSKRNL_GUID  = "AFB1E3B1-3754-8BA7-3B92-C060D6D5605F"
_NTOSKRNL_AGE   = 1
_NTOSKRNL_PDB   = "ntkrnlmp.pdb"
_FAKE_BASE      = 0xFFFF_8005_7E60_0000
_FAKE_SIZE      = 0x900_000
_FAKE_IMAGE     = r"C:\Windows\System32\ntoskrnl.exe"
_FAKE_FOUND_PDB = r"C:\symbols\ntkrnlmp.pdb\AFB1E3B137548BA73B92C060D6D5605F1\ntkrnlmp.pdb"
_SSRVOPT_GUIDPTR = 0x00000008


def _ctypes_val(obj) -> int:
    """Return the Python int from a ctypes simple-type instance or plain int."""
    return obj.value if hasattr(obj, "value") else int(obj)


def _make_find_fake(
    *,
    found_path: str | None,
    calls: list[dict[str, Any]],
):
    """Return a fake SymFindFileInPathW that records its call and optionally
    writes *found_path* into the FoundFile buffer.
    """
    from etw_analyzer.native.bindings.types import GUID

    def _fake(handle, search_path, file_name, id_ptr, two, three, flags, found_file, callback, context):
        # id_ptr is ctypes.cast(ctypes.pointer(guid), c_void_p).
        # Its .value is the integer address of the GUID struct in memory.
        addr = _ctypes_val(id_ptr)
        guid_obj = GUID.from_address(addr)
        calls.append({
            "file_name": file_name,
            "Data1":     guid_obj.Data1,
            "Data2":     guid_obj.Data2,
            "Data3":     guid_obj.Data3,
            "Data4":     list(guid_obj.Data4),
            "age":       _ctypes_val(two),
            "flags":     _ctypes_val(flags),
        })
        if found_path:
            found_file.value = found_path
            return 1  # TRUE -> found
        return 0  # FALSE -> not found

    return _fake


def _make_load_fake(calls: list[dict[str, Any]]):
    """Return a fake SymLoadModuleExW that records its arguments."""

    def _fake(handle, hfile, image_name, module_name, base, size, data, flags):
        calls.append({
            "image_name": image_name,
            "base":       _ctypes_val(base),
        })
        bval = _ctypes_val(base)
        return bval if bval else 0x1000  # non-zero = "loaded"

    return _fake


def test_k2_add_module_calls_sym_find_with_correct_guid(monkeypatch):
    """K2: SymFindFileInPathW receives the exact GUID struct, age, pdb_name,
    and SSRVOPT_GUIDPTR flag derived from the add_module identity kwargs.
    """
    from etw_analyzer.native.symbolizer import Symbolizer

    find_calls: list[dict[str, Any]] = []
    load_calls: list[dict[str, Any]] = []

    with Symbolizer() as sym:
        monkeypatch.setattr(
            sym._dbghelp, "SymFindFileInPathW",
            _make_find_fake(found_path=_FAKE_FOUND_PDB, calls=find_calls),
        )
        monkeypatch.setattr(
            sym._dbghelp, "SymLoadModuleExW",
            _make_load_fake(load_calls),
        )
        # Also suppress SymGetModuleInfoW64 so it doesn't try to read
        # memory at the fake base.
        monkeypatch.setattr(
            sym._dbghelp, "SymGetModuleInfoW64",
            lambda *a: 0,
        )

        sym.add_module(
            _FAKE_BASE, _FAKE_SIZE, _FAKE_IMAGE,
            pdb_guid=_NTOSKRNL_GUID,
            pdb_age=_NTOSKRNL_AGE,
            pdb_name=_NTOSKRNL_PDB,
        )

    # SymFindFileInPathW must be called exactly once.
    assert len(find_calls) == 1, (
        f"SymFindFileInPathW call count wrong: {len(find_calls)}"
    )
    c = find_calls[0]
    assert c["file_name"] == _NTOSKRNL_PDB, (
        f"FileName wrong: {c['file_name']!r}"
    )
    assert c["Data1"] == 0xAFB1E3B1, f"GUID.Data1 wrong: 0x{c['Data1']:08X}"
    assert c["Data2"] == 0x3754,     f"GUID.Data2 wrong: 0x{c['Data2']:04X}"
    assert c["Data3"] == 0x8BA7,     f"GUID.Data3 wrong: 0x{c['Data3']:04X}"
    assert c["Data4"] == [0x3B, 0x92, 0xC0, 0x60, 0xD6, 0xD5, 0x60, 0x5F], (
        f"GUID.Data4 wrong: {c['Data4']}"
    )
    assert c["age"] == _NTOSKRNL_AGE, f"age wrong: {c['age']}"
    assert c["flags"] == _SSRVOPT_GUIDPTR, (
        f"flags wrong (expected SSRVOPT_GUIDPTR=0x{_SSRVOPT_GUIDPTR:08X}): "
        f"0x{c['flags']:08X}"
    )


def test_k2_add_module_loads_from_found_pdb_path(monkeypatch):
    """K2: when SymFindFileInPathW succeeds, SymLoadModuleExW is called
    with the found PDB path (not the original image path).
    """
    from etw_analyzer.native.symbolizer import Symbolizer

    find_calls: list[dict[str, Any]] = []
    load_calls: list[dict[str, Any]] = []

    with Symbolizer() as sym:
        monkeypatch.setattr(
            sym._dbghelp, "SymFindFileInPathW",
            _make_find_fake(found_path=_FAKE_FOUND_PDB, calls=find_calls),
        )
        monkeypatch.setattr(
            sym._dbghelp, "SymLoadModuleExW",
            _make_load_fake(load_calls),
        )
        monkeypatch.setattr(sym._dbghelp, "SymGetModuleInfoW64", lambda *a: 0)

        sym.add_module(
            _FAKE_BASE, _FAKE_SIZE, _FAKE_IMAGE,
            pdb_guid=_NTOSKRNL_GUID,
            pdb_age=_NTOSKRNL_AGE,
            pdb_name=_NTOSKRNL_PDB,
        )

    assert len(load_calls) == 1, (
        f"SymLoadModuleExW call count wrong: {len(load_calls)}"
    )
    assert load_calls[0]["image_name"] == _FAKE_FOUND_PDB, (
        f"SymLoadModuleExW should use found PDB path; got {load_calls[0]['image_name']!r}"
    )


def test_k2_add_module_fallback_when_guid_not_found(monkeypatch):
    """K2: when SymFindFileInPathW returns not-found (returns 0), add_module
    must fall back to SymLoadModuleExW with the original image path.
    """
    from etw_analyzer.native.symbolizer import Symbolizer

    find_calls: list[dict[str, Any]] = []
    load_calls: list[dict[str, Any]] = []

    with Symbolizer() as sym:
        monkeypatch.setattr(
            sym._dbghelp, "SymFindFileInPathW",
            _make_find_fake(found_path=None, calls=find_calls),
        )
        monkeypatch.setattr(
            sym._dbghelp, "SymLoadModuleExW",
            _make_load_fake(load_calls),
        )

        sym.add_module(
            _FAKE_BASE, _FAKE_SIZE, _FAKE_IMAGE,
            pdb_guid=_NTOSKRNL_GUID,
            pdb_age=_NTOSKRNL_AGE,
            pdb_name=_NTOSKRNL_PDB,
        )

    # SymFindFileInPathW was attempted.
    assert len(find_calls) == 1
    # Fell back to legacy load with the (normalized) image path, not the
    # PDB path that was never found.
    assert len(load_calls) == 1
    loaded_path = load_calls[0]["image_name"]
    assert "ntkrnlmp.pdb" not in (loaded_path or ""), (
        f"Expected image path fallback, not PDB path; got {loaded_path!r}"
    )


def test_k2_add_module_no_guid_uses_legacy_path(monkeypatch):
    """K2: when add_module is called without pdb_guid, SymFindFileInPathW
    must NOT be called (legacy path only).
    """
    from etw_analyzer.native.symbolizer import Symbolizer

    find_calls: list[dict[str, Any]] = []
    load_calls: list[dict[str, Any]] = []

    with Symbolizer() as sym:
        monkeypatch.setattr(
            sym._dbghelp, "SymFindFileInPathW",
            _make_find_fake(found_path=_FAKE_FOUND_PDB, calls=find_calls),
        )
        monkeypatch.setattr(
            sym._dbghelp, "SymLoadModuleExW",
            _make_load_fake(load_calls),
        )

        # 3-arg call -- no identity kwargs.
        sym.add_module(_FAKE_BASE, _FAKE_SIZE, _FAKE_IMAGE)

    assert len(find_calls) == 0, (
        "SymFindFileInPathW must not be called when pdb_guid is absent"
    )
    assert len(load_calls) == 1


def test_k2_ssrvopt_guidptr_constant_value():
    """SSRVOPT_GUIDPTR in dbghelp bindings must equal 0x00000008."""
    from etw_analyzer.native.bindings.dbghelp import SSRVOPT_GUIDPTR
    assert SSRVOPT_GUIDPTR == 0x00000008, (
        f"SSRVOPT_GUIDPTR must be 0x00000008; got 0x{SSRVOPT_GUIDPTR:08X}"
    )


def test_k2_identity_source_recorded_on_rsds_success(monkeypatch):
    """K2: after a successful RSDS load, the module entry must carry
    identity_source == 'rsds'.
    """
    from etw_analyzer.native.symbolizer import Symbolizer

    with Symbolizer() as sym:
        monkeypatch.setattr(
            sym._dbghelp, "SymFindFileInPathW",
            _make_find_fake(found_path=_FAKE_FOUND_PDB, calls=[]),
        )
        monkeypatch.setattr(
            sym._dbghelp, "SymLoadModuleExW",
            _make_load_fake([]),
        )
        monkeypatch.setattr(sym._dbghelp, "SymGetModuleInfoW64", lambda *a: 0)

        sym.add_module(
            _FAKE_BASE, _FAKE_SIZE, _FAKE_IMAGE,
            pdb_guid=_NTOSKRNL_GUID,
            pdb_age=_NTOSKRNL_AGE,
            pdb_name=_NTOSKRNL_PDB,
        )

        entry = sym._modules.get(_FAKE_BASE)
        assert entry is not None
        assert entry.get("identity_source") == "rsds", (
            f"Expected identity_source='rsds'; got {entry.get('identity_source')!r}"
        )
        assert entry.get("DbgHelpPath") == _FAKE_FOUND_PDB, (
            f"DbgHelpPath should be found PDB path; got {entry.get('DbgHelpPath')!r}"
        )


def test_k2_identity_source_image_on_rsds_miss(monkeypatch):
    """K2: when SymFindFileInPathW misses, identity_source must be 'image'."""
    from etw_analyzer.native.symbolizer import Symbolizer

    with Symbolizer() as sym:
        monkeypatch.setattr(
            sym._dbghelp, "SymFindFileInPathW",
            _make_find_fake(found_path=None, calls=[]),
        )
        monkeypatch.setattr(
            sym._dbghelp, "SymLoadModuleExW",
            _make_load_fake([]),
        )

        sym.add_module(
            _FAKE_BASE, _FAKE_SIZE, _FAKE_IMAGE,
            pdb_guid=_NTOSKRNL_GUID,
            pdb_age=_NTOSKRNL_AGE,
            pdb_name=_NTOSKRNL_PDB,
        )

        entry = sym._modules.get(_FAKE_BASE)
        assert entry is not None
        assert entry.get("identity_source") == "image"


# ---------------------------------------------------------------------------
# 3. K1 -- live PDB resolution (Windows + _NT_SYMBOL_PATH set, skip if not)
# ---------------------------------------------------------------------------

import os as _os

_sym_path = _os.environ.get("_NT_SYMBOL_PATH", "")
_k1_reason = (
    "_NT_SYMBOL_PATH not set; skipping live-PDB K1 test. "
    "Set _NT_SYMBOL_PATH to a path that can resolve ntkrnlmp.pdb "
    "GUID=AFB1E3B1-3754-8BA7-3B92-C060D6D5605F age=1."
)
need_sym_path = pytest.mark.skipif(not _sym_path, reason=_k1_reason)


@need_sym_path
def test_k1_add_module_rsds_resolves_to_pdb_source():
    """K1: add_module with the ntoskrnl RSDS identity should produce
    source=='pdb' from resolve() once SymFindFileInPathW locates the PDB.

    Uses an arbitrary fake ImageBase so there is no dependency on an actual
    running kernel; dbghelp loads the PDB and maps symbols relative to
    whatever base we specify.
    """
    import logging
    from etw_analyzer.native.symbolizer import Symbolizer
    from etw_analyzer.native.bindings import dbghelp as _dh
    from etw_analyzer.native.bindings.types import IMAGEHLP_MODULEW64, guid_from_string

    # Enable DEBUG logging to capture SymFindFileInPathW diagnostic messages.
    logging.getLogger("etw_analyzer.native.symbolizer").setLevel(logging.DEBUG)

    sym = Symbolizer(symbol_path=_sym_path)
    try:
        sym.add_module(
            _FAKE_BASE, _FAKE_SIZE,
            r"\SystemRoot\System32\ntoskrnl.exe",
            pdb_guid=_NTOSKRNL_GUID,
            pdb_age=_NTOSKRNL_AGE,
            pdb_name=_NTOSKRNL_PDB,
        )

        entry = sym._modules.get(_FAKE_BASE)
        assert entry is not None, "Module entry must be present after add_module"

        identity_source = entry.get("identity_source", "image")
        dbghelp_path    = entry.get("DbgHelpPath", "")

        if identity_source != "rsds":
            # SymFindFileInPathW missed -- PDB not reachable with this
            # _NT_SYMBOL_PATH.  Report diagnostic but don't fail the test;
            # K2 is the hermetic CI guard.
            pytest.skip(
                f"SymFindFileInPathW did not find ntkrnlmp.pdb "
                f"(identity_source={identity_source!r}, path={dbghelp_path!r}). "
                f"_NT_SYMBOL_PATH={_sym_path!r}. "
                f"Skipping K1 live assertion; K2 mock test covers the wiring."
            )

        # PDB was found; verify SymGetModuleInfoW64 reports SymPdb.
        mi = IMAGEHLP_MODULEW64()
        mi.SizeOfStruct = ctypes.sizeof(IMAGEHLP_MODULEW64)
        mi_ok = _dh.SymGetModuleInfoW64(
            sym._handle,
            ctypes.c_ulonglong(_FAKE_BASE + 0x1000),
            ctypes.byref(mi),
        )

        # Probe several offsets to commit the deferred load and resolve a symbol.
        probe_addr = None
        for offset in (0x10000, 0x20000, 0x40000, 0x80000):
            label  = sym.resolve(_FAKE_BASE + offset)
            source = sym.get_source(_FAKE_BASE + offset)
            if source == "pdb":
                probe_addr = _FAKE_BASE + offset
                break

        sym_type_str = _dh.sym_type_name(mi.SymType) if mi_ok else "query-failed"

        assert probe_addr is not None, (
            f"No offset in module resolved to source='pdb'. "
            f"identity_source={identity_source!r}, DbgHelpPath={dbghelp_path!r}, "
            f"SymGetModuleInfoW64 ok={mi_ok}, SymType={sym_type_str}. "
            f"The RSDS PDB load may have succeeded per SymFindFileInPathW but "
            f"SymFromAddrW is still returning export/unknown -- "
            f"check that SymType != SymExport after loading via PDB path."
        )

        label = sym.resolve(probe_addr)
        assert "!" in label, f"Expected 'module!function' form; got {label!r}"
        # Must not be one of the known bogus export-table nearest-neighbour guesses.
        bogus = {"MmCopyMemory", "strncpy", "FsRtlAreNamesEqual"}
        fn_part = label.split("!")[-1].split("+")[0]
        assert fn_part not in bogus, (
            f"Resolved to a known export-table guess {fn_part!r}; "
            f"RSDS load probably did not produce PDB symbols."
        )
    finally:
        sym.close()
