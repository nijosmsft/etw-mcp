"""Tests for ``tools/symbol_diagnostics.py`` — the diagnose_symbol_load
and clean_stale_symbol_files MCP tools.

These tests focus on the pure-Python pieces (PE / RSDS parsing,
symbol path parsing, SymCache enumeration) because the dbghelp
SymGetModuleInfoW64 path requires a real loaded module. The PE
parsing tests synthesize tiny but valid PE images on disk to exercise
the parser; the cleanup test builds a fake SymCache subtree to prove
the dry-run / delete logic works correctly.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pandas as pd
import pytest

import etw_analyzer.native.config as native_config
import etw_analyzer.tools.trace_mgmt as trace_mgmt
from etw_analyzer.trace_state import clear_traces
from etw_analyzer.tools.symbol_diagnostics import (
    RsdsRecord,
    _guid_to_nodashes,
    _iter_candidates,
    _resolve_file_ptr,
    candidate_pdb_paths,
    clean_stale_symbol_files,
    diagnose_symbol_load,
    parse_symbol_path,
    read_pe_rsds,
)


# ---------------------------------------------------------------------------
# Minimal PE builder for RSDS parsing tests
# ---------------------------------------------------------------------------


def _make_pe_with_rsds(
    guid_bytes: bytes,
    age: int,
    pdb_path: str,
) -> bytes:
    """Build a minimal x64 PE32+ image with a single .debug section
    containing one CV_INFO_PDB70 record. The image is just-barely-valid
    for our parser - it isn't loadable.

    Layout:
        0x000  DOS header (only e_magic 'MZ' + e_lfanew at 0x3C)
        0x040  PE\\0\\0
        0x044  COFF header (Machine, NumSections=1, ..., SizeOfOptHdr)
        0x058  Optional header (PE32+ magic 0x20B + data directories,
               with entry 6 = debug pointing into .debug)
        0x158  Section table (one 40-byte entry: ".debug")
        0x180  Section raw data: IMAGE_DEBUG_DIRECTORY + RSDS record
    """
    assert len(guid_bytes) == 16

    # Section raw data: 1 IMAGE_DEBUG_DIRECTORY entry (28 bytes) then the
    # RSDS record (4 + 16 + 4 + len(path) + 1 bytes).
    pdb_bytes = pdb_path.encode("utf-8") + b"\x00"
    rsds = b"RSDS" + guid_bytes + struct.pack("<I", age) + pdb_bytes

    # IMAGE_DEBUG_DIRECTORY layout: Chars, TS, MajMin, Type=2,
    # SizeOfData, AddressOfRawData (RVA), PointerToRawData (file off).
    SECTION_RAW_OFF = 0x200
    DEBUG_DIR_FILE_OFF = SECTION_RAW_OFF
    RSDS_FILE_OFF = DEBUG_DIR_FILE_OFF + 28
    DEBUG_DIR_RVA = 0x2000   # arbitrary, matches section VA below
    RSDS_RVA = DEBUG_DIR_RVA + 28

    debug_entry = struct.pack(
        "<IIIIIII",
        0,                # Characteristics
        0,                # TimeDateStamp
        0,                # MajorVersion+MinorVersion
        2,                # Type = IMAGE_DEBUG_TYPE_CODEVIEW
        len(rsds),        # SizeOfData
        RSDS_RVA,         # AddressOfRawData (RVA)
        RSDS_FILE_OFF,    # PointerToRawData (file offset)
    )

    section_data = debug_entry + rsds
    section_data_padded = section_data + b"\x00" * (max(0, 0x200 - len(section_data)))

    # Section header (.debug)
    SECTION_VA = DEBUG_DIR_RVA
    SECTION_VSIZE = len(section_data)
    SECTION_RSIZE = len(section_data_padded)
    section = (
        b".debug\x00\x00"                            # Name (8 bytes)
        + struct.pack("<I", SECTION_VSIZE)           # VirtualSize
        + struct.pack("<I", SECTION_VA)              # VirtualAddress
        + struct.pack("<I", SECTION_RSIZE)           # SizeOfRawData
        + struct.pack("<I", SECTION_RAW_OFF)         # PointerToRawData
        + b"\x00" * 12                                # ptr to relocations, line nos
        + b"\x00" * 4                                 # NumberOfRelocations + LineNumbers
        + struct.pack("<I", 0x42000040)              # Characteristics: discardable + read
    )

    # Optional header (PE32+).
    # We need OptHdrSize = 112 (standard PE32+ fields up to data
    # directories start) + 16 directories * 8 bytes = 240 bytes.
    OPT_HDR_SIZE = 112 + 16 * 8

    opt_hdr = bytearray(OPT_HDR_SIZE)
    struct.pack_into("<H", opt_hdr, 0, 0x20B)   # magic = PE32+
    # Data directory 6 (debug) → RVA + Size. Each entry is 8 bytes
    # starting at offset 112.
    DEBUG_DD_OFF = 112 + 6 * 8
    struct.pack_into("<II", opt_hdr, DEBUG_DD_OFF, DEBUG_DIR_RVA, len(debug_entry))

    # COFF header (20 bytes): Machine, NumSections, TS, PtrToSymTab,
    # NumSym, OptHdrSize, Characteristics.
    coff = struct.pack(
        "<HHIIIHH",
        0x8664,         # IMAGE_FILE_MACHINE_AMD64
        1,              # NumberOfSections
        0,              # TimeDateStamp
        0,              # PointerToSymbolTable
        0,              # NumberOfSymbols
        OPT_HDR_SIZE,   # SizeOfOptionalHeader
        0x22,           # IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE
    )

    pe_hdr = b"PE\x00\x00" + coff + bytes(opt_hdr) + section

    # DOS header: just enough for the parser. e_lfanew at offset 0x3C
    # points at the PE signature.
    PE_OFF = 0x40
    dos = bytearray(PE_OFF)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, PE_OFF)

    file_so_far = bytes(dos) + pe_hdr
    pad = SECTION_RAW_OFF - len(file_so_far)
    if pad < 0:
        raise RuntimeError(
            f"Header overflow: header is {len(file_so_far)} bytes, but "
            f"raw section data starts at {SECTION_RAW_OFF}."
        )
    return file_so_far + b"\x00" * pad + section_data_padded


# ---------------------------------------------------------------------------
# read_pe_rsds
# ---------------------------------------------------------------------------


def test_read_pe_rsds_returns_none_for_non_pe(tmp_path: Path):
    f = tmp_path / "not_a_pe.exe"
    f.write_bytes(b"this is not a PE binary at all")
    assert read_pe_rsds(f) is None


def test_read_pe_rsds_returns_none_for_missing_file(tmp_path: Path):
    assert read_pe_rsds(tmp_path / "ghost.exe") is None


def test_read_pe_rsds_parses_synthetic_pe(tmp_path: Path):
    guid = bytes.fromhex("8FE6FCD66E8B4F8FBFB60FE6D87E81E5")
    pe = _make_pe_with_rsds(guid, age=12, pdb_path=r"C:\build\windnsref.pdb")
    f = tmp_path / "windnsref.exe"
    f.write_bytes(pe)

    rsds = read_pe_rsds(f)
    assert rsds is not None
    assert rsds.age == 12
    # SymCache folder key = GUID + uppercase hex age.
    assert rsds.symcache_folder_name.endswith("C")
    assert rsds.pdb_path == r"C:\build\windnsref.pdb"
    # GUID round-trip: the parser swaps endianness for Data1/2/3 then
    # joins as uppercase hex.
    assert len(rsds.guid_string) == 32
    assert rsds.guid_string == rsds.guid_string.upper()


def test_rsds_symcache_folder_format():
    rec = RsdsRecord(guid_string="ABCDEF0123456789" * 2, age=15, pdb_path="x.pdb")
    # Age formatted in uppercase hex.
    assert rec.symcache_folder_name.endswith("F")
    assert len(rec.symcache_folder_name) == 32 + 1


# ---------------------------------------------------------------------------
# parse_symbol_path
# ---------------------------------------------------------------------------


def test_parse_symbol_path_empty():
    assert parse_symbol_path("") == []
    assert parse_symbol_path(None) == []  # type: ignore[arg-type]


def test_parse_symbol_path_plain_directory():
    out = parse_symbol_path(r"C:\symbols\local")
    assert out == [("local", Path(r"C:\symbols\local"))]


def test_parse_symbol_path_srv_cache_extracted():
    out = parse_symbol_path(r"srv*C:\symbols*https://msdl.microsoft.com/download/symbols")
    assert out == [("server", Path(r"C:\symbols"))]


def test_parse_symbol_path_mixed_entries():
    out = parse_symbol_path(
        r"srv*C:\symbols*https://msdl.microsoft.com/download/symbols;C:\build\Release;cache*D:\cache"
    )
    kinds = [k for k, _ in out]
    assert kinds == ["server", "local", "symcache"]


def test_parse_symbol_path_strips_whitespace_and_empties():
    out = parse_symbol_path(r"  C:\symbols  ;; ; C:\other")
    paths = [str(p) for _, p in out]
    assert paths == [r"C:\symbols", r"C:\other"]


# ---------------------------------------------------------------------------
# candidate_pdb_paths
# ---------------------------------------------------------------------------


def test_candidate_pdb_paths_finds_flat_layout(tmp_path: Path):
    pdb = tmp_path / "windnsref.pdb"
    pdb.write_bytes(b"fake pdb")

    paths = candidate_pdb_paths(str(tmp_path), "windnsref.exe", "windnsref.pdb")
    assert pdb in paths


def test_candidate_pdb_paths_finds_symstore_layout(tmp_path: Path):
    # <tmp>/windnsref.pdb/<GUID+Age>/windnsref.pdb
    sym_root = tmp_path / "windnsref.pdb" / "ABCDEFC"
    sym_root.mkdir(parents=True)
    pdb = sym_root / "windnsref.pdb"
    pdb.write_bytes(b"fake pdb")

    paths = candidate_pdb_paths(str(tmp_path), "windnsref.exe", "windnsref.pdb")
    assert pdb in paths


def test_candidate_pdb_paths_empty_when_dir_missing(tmp_path: Path):
    ghost = tmp_path / "does_not_exist"
    assert candidate_pdb_paths(str(ghost), "x.exe", "x.pdb") == []


# ---------------------------------------------------------------------------
# clean_stale_symbol_files
# ---------------------------------------------------------------------------


# Bytes-on-disk Data1/2/3 are little-endian; the displayed/symstore
# GUID swaps each field. Source GUID below is laid out so the swapped
# form is D6FCE68F8B6E8F4FBFB60FE6D87E81E5, which matches what dbghelp
# would synthesize from the same RSDS record. We use the swapped form
# for SymCache folder names (that's what symstore actually writes).
_SWAPPED_GUID = "D6FCE68F8B6E8F4FBFB60FE6D87E81E5"


@pytest.fixture
def fake_symcache(tmp_path: Path):
    """Build a realistic SymCache subtree with one current + two stale
    GUID+Age subfolders for ``windnsref.pdb``."""
    cache = tmp_path / "SymCache"
    pdb_root = cache / "windnsref.pdb"
    for age_hex in ("2", "4", "C"):
        sub = pdb_root / f"{_SWAPPED_GUID}{age_hex}"
        sub.mkdir(parents=True)
        (sub / "windnsref.pdb").write_bytes(b"fake")
    return cache


def test_clean_stale_symbol_files_dry_run_lists_but_does_not_delete(
    tmp_path: Path,
    fake_symcache: Path,
):
    guid = bytes.fromhex("8FE6FCD66E8B4F8FBFB60FE6D87E81E5")
    exe = tmp_path / "windnsref.exe"
    exe.write_bytes(_make_pe_with_rsds(guid, age=12, pdb_path="windnsref.pdb"))

    out = clean_stale_symbol_files(
        "windnsref.exe",
        str(exe),
        dry_run=True,
        symcache_root=str(fake_symcache),
    )

    assert "STALE" in out
    assert "KEEP (current)" in out
    assert "Dry-run mode" in out
    # Nothing should have been deleted.
    pdb_root = fake_symcache / "windnsref.pdb"
    assert (pdb_root / f"{_SWAPPED_GUID}2").exists()
    assert (pdb_root / f"{_SWAPPED_GUID}4").exists()
    assert (pdb_root / f"{_SWAPPED_GUID}C").exists()


def test_clean_stale_symbol_files_deletes_when_dry_run_false(
    tmp_path: Path,
    fake_symcache: Path,
):
    guid = bytes.fromhex("8FE6FCD66E8B4F8FBFB60FE6D87E81E5")
    exe = tmp_path / "windnsref.exe"
    exe.write_bytes(_make_pe_with_rsds(guid, age=12, pdb_path="windnsref.pdb"))

    out = clean_stale_symbol_files(
        "windnsref.exe",
        str(exe),
        dry_run=False,
        symcache_root=str(fake_symcache),
    )

    assert "Deleted 2 folders" in out
    pdb_root = fake_symcache / "windnsref.pdb"
    # Stale folders are gone.
    assert not (pdb_root / f"{_SWAPPED_GUID}2").exists()
    assert not (pdb_root / f"{_SWAPPED_GUID}4").exists()
    # Current folder is preserved.
    assert (pdb_root / f"{_SWAPPED_GUID}C").exists()


def test_clean_stale_symbol_files_missing_exe_returns_error(tmp_path: Path):
    out = clean_stale_symbol_files(
        "ghost.exe",
        str(tmp_path / "ghost.exe"),
        dry_run=True,
    )
    assert "not found" in out.lower()


def test_clean_stale_symbol_files_no_rsds_returns_error(tmp_path: Path):
    exe = tmp_path / "junk.exe"
    exe.write_bytes(b"not really a PE")
    out = clean_stale_symbol_files("junk.exe", str(exe), dry_run=True)
    assert "No RSDS record" in out


def test_clean_stale_symbol_files_module_not_in_cache(
    tmp_path: Path,
    fake_symcache: Path,
):
    guid = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    exe = tmp_path / "other.exe"
    exe.write_bytes(_make_pe_with_rsds(guid, age=1, pdb_path="other.pdb"))

    out = clean_stale_symbol_files(
        "other.exe",
        str(exe),
        dry_run=True,
        symcache_root=str(fake_symcache),
    )
    assert "nothing to clean" in out


def test_clean_stale_symbol_files_all_current(tmp_path: Path):
    cache = tmp_path / "SymCache"
    guid = bytes.fromhex("8FE6FCD66E8B4F8FBFB60FE6D87E81E5")
    # Build a cache that has ONLY the current age-12 subfolder (using
    # the symstore convention: Data1/2/3 byte-swapped).
    sub = cache / "windnsref.pdb" / f"{_SWAPPED_GUID}C"
    sub.mkdir(parents=True)
    (sub / "windnsref.pdb").write_bytes(b"fake")

    exe = tmp_path / "windnsref.exe"
    exe.write_bytes(_make_pe_with_rsds(guid, age=12, pdb_path="windnsref.pdb"))

    out = clean_stale_symbol_files(
        "windnsref.exe",
        str(exe),
        dry_run=False,
        symcache_root=str(cache),
    )
    assert "No stale folders to delete" in out


# ---------------------------------------------------------------------------
# parse_symbol_path — upstream store entries (Bug B fix)
# ---------------------------------------------------------------------------


def test_parse_symbol_path_srv_returns_upstream_unc_store(tmp_path: Path):
    """srv*<cache>*<UNC> yields both the cache dir (server) and the
    upstream UNC path (store).  The "store" entry is new behaviour."""
    sym = r"srv*C:\symbols*\\10.57.200.80\e$\symbols\Indexes"
    out = parse_symbol_path(sym)
    kinds = [k for k, _ in out]
    paths = [p for _, p in out]
    assert "server" in kinds
    assert "store" in kinds
    assert Path(r"C:\symbols") in paths
    assert Path(r"\\10.57.200.80\e$\symbols\Indexes") in paths


def test_parse_symbol_path_drops_https_upstream():
    """An https:// upstream must NOT appear as a searchable dir entry."""
    sym = r"srv*C:\symbols*https://msdl.microsoft.com/download/symbols"
    out = parse_symbol_path(sym)
    kinds = [k for k, _ in out]
    assert "store" not in kinds
    assert kinds == ["server"]


def test_parse_symbol_path_drops_symweb_upstream():
    """symweb shorthand must NOT appear as a searchable dir entry."""
    sym = r"srv*C:\symbols*symweb"
    out = parse_symbol_path(sym)
    kinds = [k for k, _ in out]
    assert "store" not in kinds
    assert kinds == ["server"]


def test_parse_symbol_path_multiple_upstreams_mixed():
    """Multiple upstreams: filesystem ones kept, http/symweb dropped."""
    sym = (
        r"srv*C:\cache"
        r"*\\server1\share"
        r"*https://msdl.microsoft.com/download/symbols"
        r"*D:\local_store"
    )
    out = parse_symbol_path(sym)
    kinds = [k for k, _ in out]
    paths = [p for _, p in out]
    assert kinds.count("store") == 2
    assert Path(r"\\server1\share") in paths
    assert Path(r"D:\local_store") in paths
    # https upstream is absent
    assert not any("msdl" in str(p).lower() for p in paths)


def test_parse_symbol_path_srv_no_cache_only_upstream(tmp_path: Path):
    """srv**<upstream> (empty cache slot) — only the upstream store appears."""
    sym = r"srv**\\server\share"
    out = parse_symbol_path(sym)
    kinds = [k for k, _ in out]
    # Empty cache part (parts[1] == "") is skipped; upstream store is kept.
    assert "server" not in kinds
    assert "store" in kinds


# ---------------------------------------------------------------------------
# _resolve_file_ptr — all three content forms
# ---------------------------------------------------------------------------


def test_resolve_file_ptr_path_prefix_form(tmp_path: Path):
    """PATH:<absolute> form resolves to the absolute path."""
    real_pdb = tmp_path / "real" / "foo.pdb"
    real_pdb.parent.mkdir(parents=True)
    real_pdb.write_bytes(b"fake pdb")

    guid_dir = tmp_path / "store" / "foo.pdb" / "ABCD1"
    guid_dir.mkdir(parents=True)
    ptr = guid_dir / "file.ptr"
    ptr.write_text(f"PATH:{real_pdb}", encoding="utf-8")

    result = _resolve_file_ptr(ptr)
    assert result == real_pdb


def test_resolve_file_ptr_bare_absolute_form(tmp_path: Path):
    """Bare absolute path (no PATH: prefix) is used as-is."""
    real_pdb = tmp_path / "absolute" / "bar.pdb"
    real_pdb.parent.mkdir(parents=True)
    real_pdb.write_bytes(b"fake pdb")

    guid_dir = tmp_path / "store" / "bar.pdb" / "GUID1"
    guid_dir.mkdir(parents=True)
    ptr = guid_dir / "file.ptr"
    ptr.write_text(str(real_pdb), encoding="utf-8")

    result = _resolve_file_ptr(ptr)
    assert result == real_pdb


def test_resolve_file_ptr_relative_form(tmp_path: Path):
    """Bare relative path is resolved relative to the GUID+Age folder."""
    # Layout:
    #   tmp/ostesting/foo.pdb        <- the real PDB
    #   tmp/store/foo.pdb/GUID1/     <- GUID+Age folder (3 levels below tmp)
    #   tmp/store/foo.pdb/GUID1/file.ptr -> "../../../ostesting/foo.pdb"
    real_pdb = tmp_path / "ostesting" / "foo.pdb"
    real_pdb.parent.mkdir(parents=True)
    real_pdb.write_bytes(b"fake pdb")

    guid_dir = tmp_path / "store" / "foo.pdb" / "GUID1"
    guid_dir.mkdir(parents=True)
    # From guid_dir (3 levels below tmp_path) up to tmp_path then into ostesting.
    rel = Path("..") / ".." / ".." / "ostesting" / "foo.pdb"
    ptr = guid_dir / "file.ptr"
    ptr.write_text(str(rel), encoding="utf-8")

    result = _resolve_file_ptr(ptr)
    assert result is not None
    assert result.resolve() == real_pdb.resolve()


def test_resolve_file_ptr_missing_target_returns_none(tmp_path: Path):
    """A file.ptr pointing at a non-existent target returns None."""
    guid_dir = tmp_path / "store" / "foo.pdb" / "GUID1"
    guid_dir.mkdir(parents=True)
    ptr = guid_dir / "file.ptr"
    ptr.write_text(str(tmp_path / "ghost" / "foo.pdb"), encoding="utf-8")

    assert _resolve_file_ptr(ptr) is None


def test_resolve_file_ptr_empty_content_returns_none(tmp_path: Path):
    """An empty file.ptr returns None without raising."""
    guid_dir = tmp_path / "store" / "foo.pdb" / "GUID1"
    guid_dir.mkdir(parents=True)
    ptr = guid_dir / "file.ptr"
    ptr.write_bytes(b"   \n  ")

    assert _resolve_file_ptr(ptr) is None


def test_resolve_file_ptr_path_prefix_with_trailing_whitespace(tmp_path: Path):
    """PATH: form tolerates trailing whitespace / newlines."""
    real_pdb = tmp_path / "real" / "ws.pdb"
    real_pdb.parent.mkdir(parents=True)
    real_pdb.write_bytes(b"fake pdb")

    guid_dir = tmp_path / "store" / "ws.pdb" / "GUID1"
    guid_dir.mkdir(parents=True)
    ptr = guid_dir / "file.ptr"
    ptr.write_text(f"PATH:{real_pdb}  \r\n", encoding="utf-8")

    result = _resolve_file_ptr(ptr)
    assert result == real_pdb


# ---------------------------------------------------------------------------
# candidate_pdb_paths — file.ptr integration (Bug B fix)
# ---------------------------------------------------------------------------


def test_candidate_pdb_paths_follows_fileptr_relative(tmp_path: Path):
    """candidate_pdb_paths follows a relative file.ptr redirect."""
    real_pdb = tmp_path / "ostesting" / "exe" / "ntkrnlmp.pdb"
    real_pdb.parent.mkdir(parents=True)
    real_pdb.write_bytes(b"fake pdb")

    # Layout:
    #   store/ntkrnlmp.pdb/<GUID+Age>/file.ptr (3 levels below store root)
    # Relative from that folder back to ostesting/exe/ntkrnlmp.pdb:
    #   ../../../ostesting/exe/ntkrnlmp.pdb
    store = tmp_path / "store"
    guid_dir = store / "ntkrnlmp.pdb" / "ABCD1234E"
    guid_dir.mkdir(parents=True)
    rel = Path("..") / ".." / ".." / "ostesting" / "exe" / "ntkrnlmp.pdb"
    (guid_dir / "file.ptr").write_text(str(rel), encoding="utf-8")

    paths = candidate_pdb_paths(str(store), "ntkrnlmp.exe", "ntkrnlmp.pdb")
    assert real_pdb.resolve() in [p.resolve() for p in paths]


def test_candidate_pdb_paths_follows_fileptr_path_prefix(tmp_path: Path):
    """candidate_pdb_paths follows a PATH: prefix file.ptr redirect."""
    real_pdb = tmp_path / "real" / "foo.pdb"
    real_pdb.parent.mkdir(parents=True)
    real_pdb.write_bytes(b"fake pdb")

    guid_dir = tmp_path / "store" / "foo.pdb" / "GUID1A"
    guid_dir.mkdir(parents=True)
    (guid_dir / "file.ptr").write_text(f"PATH:{real_pdb}", encoding="utf-8")

    paths = candidate_pdb_paths(str(tmp_path / "store"), "foo.exe", "foo.pdb")
    assert real_pdb in paths


def test_candidate_pdb_paths_follows_fileptr_bare_absolute(tmp_path: Path):
    """candidate_pdb_paths follows a bare absolute path file.ptr redirect."""
    real_pdb = tmp_path / "abs" / "bar.pdb"
    real_pdb.parent.mkdir(parents=True)
    real_pdb.write_bytes(b"fake pdb")

    guid_dir = tmp_path / "store" / "bar.pdb" / "GUID2B"
    guid_dir.mkdir(parents=True)
    (guid_dir / "file.ptr").write_text(str(real_pdb), encoding="utf-8")

    paths = candidate_pdb_paths(str(tmp_path / "store"), "bar.exe", "bar.pdb")
    assert real_pdb in paths


def test_candidate_pdb_paths_literal_symstore_still_works(tmp_path: Path):
    """Backward compat: literal <pdb>/<GUID>/<pdb> is still found."""
    guid_dir = tmp_path / "windnsref.pdb" / "ABCDEFC"
    guid_dir.mkdir(parents=True)
    pdb = guid_dir / "windnsref.pdb"
    pdb.write_bytes(b"fake pdb")

    paths = candidate_pdb_paths(str(tmp_path), "windnsref.exe", "windnsref.pdb")
    assert pdb in paths


def test_candidate_pdb_paths_skips_malformed_fileptr(tmp_path: Path):
    """A file.ptr pointing at a non-existent path is silently skipped."""
    guid_dir = tmp_path / "ghost.pdb" / "GUID1"
    guid_dir.mkdir(parents=True)
    (guid_dir / "file.ptr").write_text(str(tmp_path / "no_such.pdb"), encoding="utf-8")

    # Should not raise; no real PDB -> empty result
    paths = candidate_pdb_paths(str(tmp_path), "ghost.exe", "ghost.pdb")
    assert paths == []


def test_candidate_pdb_paths_skips_unreadable_fileptr(tmp_path: Path):
    """An OSError reading file.ptr is silently skipped (no raise)."""
    # We simulate an unreadable file.ptr by passing a directory path
    # as the file.ptr "file" — not a true OSError, but _resolve_file_ptr
    # is tested separately for OSError; here we just verify the caller
    # doesn't propagate any error.
    guid_dir = tmp_path / "x.pdb" / "GUID1"
    guid_dir.mkdir(parents=True)
    # Create file.ptr as a directory (not a file) — is_file() returns False,
    # so _iter_candidates skips it without calling _resolve_file_ptr.
    (guid_dir / "file.ptr").mkdir()

    paths = candidate_pdb_paths(str(tmp_path), "x.exe", "x.pdb")
    assert paths == []


# ---------------------------------------------------------------------------
# _iter_candidates — redirect metadata is surfaced
# ---------------------------------------------------------------------------


def test_iter_candidates_redirect_description_set_for_fileptr(tmp_path: Path):
    """_iter_candidates carries a redirect description for file.ptr entries."""
    real_pdb = tmp_path / "real" / "foo.pdb"
    real_pdb.parent.mkdir(parents=True)
    real_pdb.write_bytes(b"fake pdb")

    guid_dir = tmp_path / "store" / "foo.pdb" / "GUID1A"
    guid_dir.mkdir(parents=True)
    ptr = guid_dir / "file.ptr"
    ptr.write_text(f"PATH:{real_pdb}", encoding="utf-8")

    entries = list(_iter_candidates(str(tmp_path / "store"), "foo.exe", "foo.pdb"))
    assert len(entries) == 1
    path, desc = entries[0]
    assert path == real_pdb
    assert desc is not None
    assert "file.ptr" in desc
    assert str(ptr) in desc
    assert str(real_pdb) in desc


def test_iter_candidates_no_redirect_for_literal_pdb(tmp_path: Path):
    """_iter_candidates has None redirect description for literal PDB files."""
    guid_dir = tmp_path / "foo.pdb" / "GUID1"
    guid_dir.mkdir(parents=True)
    pdb = guid_dir / "foo.pdb"
    pdb.write_bytes(b"fake pdb")

    entries = list(_iter_candidates(str(tmp_path), "foo.exe", "foo.pdb"))
    assert len(entries) == 1
    path, desc = entries[0]
    assert path == pdb
    assert desc is None


# ---------------------------------------------------------------------------
# parse_symbol_path — upstream store searched by candidate_pdb_paths
# ---------------------------------------------------------------------------


def test_candidate_pdb_paths_searches_upstream_store(tmp_path: Path):
    """When sym_path has srv*<cache>*<upstream>, the upstream store is
    also searched — previously it was silently dropped."""
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    upstream_dir = tmp_path / "upstream"

    # Put the PDB only in the upstream store, not in the cache.
    pdb_in_upstream = upstream_dir / "foo.pdb"
    upstream_dir.mkdir()
    pdb_in_upstream.write_bytes(b"fake pdb")

    sym_path = f"srv*{cache_dir}*{upstream_dir}"
    paths = candidate_pdb_paths(sym_path, "foo.exe", "foo.pdb")
    assert pdb_in_upstream in paths


# ===========================================================================
# M4: diagnose_symbol_load 3-way GUID reconciliation
# ===========================================================================


@pytest.fixture(autouse=True)
def _isolate_traces_for_m4():
    clear_traces()
    native_config.reset_auto_cache()
    yield
    clear_traces()
    native_config.reset_auto_cache()


def _register_trace_with_image(
    tmp_path: Path,
    image_rows: list[dict],
    *,
    trace_id: str = "trace_diag_m4",
) -> trace_mgmt.TraceData:
    """Register a minimal TraceData with the given image DF."""
    etl = tmp_path / f"{trace_id}.etl"
    etl.write_bytes(b"synthetic")
    t = trace_mgmt.TraceData(
        trace_id=trace_id,
        etl_path=etl,
        export_dir=tmp_path / f".export-{trace_id}",
        symbol_path=None,
    )
    if image_rows:
        t.raw_csv["image"] = pd.DataFrame(image_rows)
    trace_mgmt.register_trace(t)
    return t


# ---------------------------------------------------------------------------
# PE GUID bytes for the two test identities.
# Encoding: each 16-byte sequence produces a specific canonical GUID when
# parsed by read_pe_rsds (little-endian for Data1/2/3, big-endian for Data4).
#
# TRACE_GUID  = "AFB1E3B1-3754-8BA7-3B92-C060D6D5605F"
#   PE bytes  = B1 E3 B1 AF | 54 37 | A7 8B | 3B 92 C0 60 D6 D5 60 5F
# DISK_GUID   = "11D7FE79-CC24-5612-0555-03EE86BB0E3E"
#   PE bytes  = 79 FE D7 11 | 24 CC | 12 56 | 05 55 03 EE 86 BB 0E 3E
# ---------------------------------------------------------------------------

_TRACE_GUID_UUID = "AFB1E3B1-3754-8BA7-3B92-C060D6D5605F"
_TRACE_GUID_NORM = "AFB1E3B137548BA73B92C060D6D5605F"
_TRACE_PE_BYTES = bytes.fromhex("B1E3B1AF5437A78B3B92C060D6D5605F")

_DISK_GUID_NORM = "11D7FE79CC24561205" + "5503EE86BB0E3E"  # 32-char no-dashes
_DISK_PE_BYTES = bytes.fromhex("79FED71124CC1256055503EE86BB0E3E")


def test_guid_to_nodashes_normalizes_uuid_form():
    assert _guid_to_nodashes("AFB1E3B1-3754-8BA7-3B92-C060D6D5605F") == _TRACE_GUID_NORM
    assert _guid_to_nodashes(_TRACE_GUID_NORM) == _TRACE_GUID_NORM
    assert _guid_to_nodashes("") == ""
    assert _guid_to_nodashes(None) == ""


def test_diagnose_cross_machine_shows_both_guids_and_cross_machine_verdict(
    tmp_path: Path,
):
    """trace GUID != disk GUID: output shows both, verdict says cross-machine."""
    # Trace identity: ntoskrnl captured from a different build.
    trace = _register_trace_with_image(
        tmp_path,
        [
            {
                "FileName": r"\Windows\System32\ntoskrnl.exe",
                "ImageBase": 0xFFFFF8057E600000,
                "ImageSize": 0x900000,
                "PdbGuid": _TRACE_GUID_UUID,
                "PdbAge": 1,
                "PdbName": "ntkrnlmp.pdb",
                "TimeDateStamp": 0x6471A2C0,
            }
        ],
    )
    # Disk image: analyst box's local ntoskrnl -- different build.
    disk_exe = tmp_path / "ntoskrnl.exe"
    disk_exe.write_bytes(_make_pe_with_rsds(_DISK_PE_BYTES, age=1, pdb_path="ntoskrnl.pdb"))

    out = diagnose_symbol_load(trace.trace_id, "ntoskrnl.exe", exe_path=str(disk_exe))

    # Both GUIDs must appear in the output.
    assert _TRACE_GUID_UUID in out or _TRACE_GUID_NORM[:8] in out, f"trace GUID missing:\n{out}"
    assert _DISK_GUID_NORM[:8] in out, f"disk GUID missing:\n{out}"

    # The reconciliation verdict must explain this is expected.
    assert "cross-machine" in out.lower() or "expected" in out.lower(), (
        f"cross-machine verdict missing:\n{out}"
    )

    # The tool must frame it as NOT a failure.
    assert "EXPECTED" in out or "expected" in out, f"expected-case framing missing:\n{out}"

    # Trace identity section must be present.
    assert "Trace identity" in out

    # GUID reconciliation section must be present.
    assert "GUID reconciliation" in out


def test_diagnose_same_build_reports_guid_match(tmp_path: Path):
    """trace GUID == disk GUID: output says they match (same-build case)."""
    trace = _register_trace_with_image(
        tmp_path,
        [
            {
                "FileName": r"\Windows\System32\ntoskrnl.exe",
                "ImageBase": 0xFFFFF8057E600000,
                "ImageSize": 0x900000,
                "PdbGuid": _TRACE_GUID_UUID,
                "PdbAge": 1,
                "PdbName": "ntkrnlmp.pdb",
                "TimeDateStamp": 0x6471A2C0,
            }
        ],
    )
    # Disk image: same build, same GUID.
    disk_exe = tmp_path / "ntoskrnl.exe"
    disk_exe.write_bytes(_make_pe_with_rsds(_TRACE_PE_BYTES, age=1, pdb_path="ntkrnlmp.pdb"))

    out = diagnose_symbol_load(trace.trace_id, "ntoskrnl.exe", exe_path=str(disk_exe))

    assert "GUID reconciliation" in out
    assert "match" in out.lower()
    # Should NOT say cross-machine when they match.
    assert "cross-machine" not in out.lower()


def test_diagnose_no_trace_identity_says_not_available(tmp_path: Path):
    """Old trace cache (no image DF): trace identity section says 'Not available'."""
    trace = _register_trace_with_image(tmp_path, [])  # no image rows
    disk_exe = tmp_path / "foo.sys"
    disk_exe.write_bytes(_make_pe_with_rsds(_DISK_PE_BYTES, age=2, pdb_path="foo.pdb"))

    out = diagnose_symbol_load(trace.trace_id, "foo.sys", exe_path=str(disk_exe))

    assert "Trace identity" in out
    assert "Not available" in out or "not available" in out


def test_diagnose_trace_pdb_name_used_in_candidate_search(tmp_path: Path):
    """When trace PDB name differs from disk PDB name, both are searched."""
    trace = _register_trace_with_image(
        tmp_path,
        [
            {
                "FileName": r"\Windows\System32\ntoskrnl.exe",
                "ImageBase": 0xFFFFF8057E600000,
                "ImageSize": 0x900000,
                "PdbGuid": _TRACE_GUID_UUID,
                "PdbAge": 1,
                # Trace says ntkrnlmp.pdb; disk says ntoskrnl.pdb
                "PdbName": "ntkrnlmp.pdb",
                "TimeDateStamp": 0x6471A2C0,
            }
        ],
    )
    disk_exe = tmp_path / "ntoskrnl.exe"
    disk_exe.write_bytes(_make_pe_with_rsds(_DISK_PE_BYTES, age=1, pdb_path="ntoskrnl.pdb"))

    out = diagnose_symbol_load(trace.trace_id, "ntoskrnl.exe", exe_path=str(disk_exe))

    # The trace PDB name (ntkrnlmp.pdb) must appear in the candidate search section.
    assert "ntkrnlmp.pdb" in out
