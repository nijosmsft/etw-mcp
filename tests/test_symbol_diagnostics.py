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

import pytest

from etw_analyzer.tools.symbol_diagnostics import (
    RsdsRecord,
    candidate_pdb_paths,
    clean_stale_symbol_files,
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
