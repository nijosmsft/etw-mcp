"""Regression tests for the SYMBOLS-stream fixes.

Covers the GitHub issues fixed together in this PR:

- #3  check_symbols must NOT count a wrong-GUID PDB as From-PDB/OK; it gets a
      distinct ``MISMATCHED_PDB`` status. ``read_pdb_signature`` must read the
      PDB Info Stream (stream 1), not stream 0 (which yields a garbage GUID).
- #8  resolve_symbols must prefer the native in-process symbolizer and fail
      gracefully when the external xperf symcache builder crashes (0xC0000005).
- #15 / #19  check_symbols must NOT report MISSING/0% for dotnet pre-symbolized
      traces whose ``cpu_sampling`` rows already carry named functions.
- #21 stack rebuild from ``sampled_profile.parquet`` with a symbolizer that
      raises on ``bulk_resolve`` must surface a clear error, not silently
      produce an all-unknown frame.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pandas as pd
import pytest

import etw_analyzer.tools.trace_mgmt as trace_mgmt
import etw_analyzer.native.config as native_config
from etw_analyzer.trace_state import TraceData, clear_traces, register_trace
from etw_analyzer.tools import symbol_diagnostics
from etw_analyzer.native import symbolizer as symbolizer_mod


@pytest.fixture(autouse=True)
def _isolate_traces():
    clear_traces()
    native_config.reset_auto_cache()
    yield
    clear_traces()
    native_config.reset_auto_cache()


def _register_trace_with_cpu_df(
    tmp_path: Path,
    cpu_df: pd.DataFrame,
    *,
    trace_id: str = "trace_regression",
    symbolizer=None,
) -> TraceData:
    etl = tmp_path / f"{trace_id}.etl"
    etl.write_bytes(b"synthetic")
    trace = TraceData(
        trace_id=trace_id,
        etl_path=etl,
        export_dir=tmp_path / f".export-{trace_id}",
        symbol_path="srv*C:\\symbols*https://msdl.microsoft.com/download/symbols",
    )
    trace.raw_csv["cpu_sampling"] = cpu_df
    if symbolizer is not None:
        trace.symbolizer = symbolizer
    register_trace(trace)
    return trace


# ---------------------------------------------------------------------------
# #3 — wrong-GUID PDB must be MISMATCHED_PDB, never OK
# ---------------------------------------------------------------------------


def test_check_symbols_mismatched_pdb_is_not_ok(tmp_path: Path):
    """A module whose names came from a wrong-build PDB (SymbolSource
    'mismatched') must be flagged MISMATCHED_PDB and never reported as OK
    or From-PDB (#3)."""
    df = pd.DataFrame({
        "Process Name": ["System"] * 6,
        "PID": [4] * 6,
        "Weight": [100] * 6,
        "% Weight": [16.6] * 6,
        "Module": ["tcpip.sys"] * 6,
        "Function": [f"WrongBuildFn{i}" for i in range(6)],
        "SymbolSource": ["mismatched"] * 6,
    })
    trace = _register_trace_with_cpu_df(tmp_path, df)

    out = trace_mgmt.check_symbols(trace.trace_id)

    assert "tcpip.sys" in out
    assert "MISMATCHED_PDB" in out
    # The module's row must NOT be classified OK.
    row_line = [l for l in out.splitlines() if "tcpip.sys" in l and "|" in l]
    assert row_line, "expected a table row for tcpip.sys"
    assert "OK" not in row_line[0]
    # Must steer the user to the strict cross-check tool.
    assert "diagnose_symbol_load" in out


def test_check_symbols_mismatched_warning_names_trace_guid(tmp_path: Path):
    cpu_df = pd.DataFrame({
        "Process Name": ["System"] * 5,
        "PID": [4] * 5,
        "Weight": [200] * 5,
        "% Weight": [100.0] * 5,
        "Module": ["tcpip.sys"] * 5,
        "Function": [f"WrongFn{i}" for i in range(5)],
        "SymbolSource": ["mismatched"] * 5,
    })
    image_rows = [{
        "FileName": r"\Windows\System32\drivers\tcpip.sys",
        "ImageBase": 0xFFFFF80500000000,
        "ImageSize": 0x400000,
        "PdbGuid": "D195DCC3-DF4C-1234-5678-90ABCDEF0001",
        "PdbAge": 1,
        "PdbName": "tcpip.pdb",
    }]
    etl = tmp_path / "mismatch.etl"
    etl.write_bytes(b"synthetic")
    trace = TraceData(
        trace_id="trace_mismatch_guid",
        etl_path=etl,
        export_dir=tmp_path / ".export-mismatch",
        symbol_path="srv*C:\\symbols*https://msdl.microsoft.com/download/symbols",
    )
    trace.raw_csv["cpu_sampling"] = cpu_df
    trace.raw_csv["image"] = pd.DataFrame(image_rows)
    register_trace(trace)

    out = trace_mgmt.check_symbols(trace.trace_id)

    assert "MISMATCHED_PDB" in out
    # The trace's captured GUID should appear in the mismatch explanation.
    assert "D195DCC3" in out


# ---------------------------------------------------------------------------
# #15 / #19 — dotnet pre-symbolized rows must NOT be MISSING
# ---------------------------------------------------------------------------


def test_check_symbols_dotnet_preresolved_not_missing(tmp_path: Path):
    """dotnet sidecar pre-resolves names into cpu_sampling even though the
    in-process symbolizer reports SymbolSource='unknown'. check_symbols must
    NOT report MISSING/0% for such a module (#15, regression for #19)."""
    df = pd.DataFrame({
        "Process Name": ["dotnet.exe"] * 8,
        "PID": [9000] * 8,
        "Weight": [50] * 8,
        "% Weight": [12.5] * 8,
        "Module": ["tcpip.sys"] * 8,
        # Real, usable names already present from the extractor.
        "Function": [f"TcpSend{i}" for i in range(8)],
        # ...but the in-process symbolizer loaded no PDB for them.
        "SymbolSource": ["unknown"] * 8,
    })
    trace = _register_trace_with_cpu_df(tmp_path, df)

    out = trace_mgmt.check_symbols(trace.trace_id)

    assert "tcpip.sys" in out
    row_line = [l for l in out.splitlines() if "tcpip.sys" in l and "|" in l]
    assert row_line, "expected a table row for tcpip.sys"
    # The module must NOT be reported MISSING — names ARE resolved.
    assert "MISSING" not in row_line[0]
    assert "PRE_RESOLVED" in row_line[0]


def test_check_symbols_preresolved_summary_note(tmp_path: Path):
    df = pd.DataFrame({
        "Process Name": ["dotnet.exe"] * 10,
        "PID": [9000] * 10,
        "Weight": [10] * 10,
        "% Weight": [10.0] * 10,
        "Module": ["clrjit.dll"] * 10,
        "Function": [f"Jit_Method_{i}" for i in range(10)],
        "SymbolSource": ["unknown"] * 10,
    })
    trace = _register_trace_with_cpu_df(tmp_path, df)

    out = trace_mgmt.check_symbols(trace.trace_id)

    assert "PRE_RESOLVED" in out
    # A genuinely unnamed unknown row stays MISSING, so the two paths differ.
    assert "Pre-resolved" in out


def test_check_symbols_unknown_unnamed_still_missing(tmp_path: Path):
    """Guard: an unknown-source row whose Function is itself unknown must
    still be MISSING (the pre-resolved path keys off a *named* Function)."""
    df = pd.DataFrame({
        "Process Name": ["app.exe"] * 4,
        "PID": [100] * 4,
        "Weight": [25] * 4,
        "% Weight": [25.0] * 4,
        "Module": ["nopdb.sys"] * 4,
        "Function": ["unknown"] * 4,
        "SymbolSource": ["unknown"] * 4,
    })
    trace = _register_trace_with_cpu_df(tmp_path, df)

    out = trace_mgmt.check_symbols(trace.trace_id)

    row_line = [l for l in out.splitlines() if "nopdb.sys" in l and "|" in l]
    assert row_line
    assert "MISSING" in row_line[0]


# ---------------------------------------------------------------------------
# #3 — diagnose_symbol_load must agree with check_symbols on MSFZ matches
#      (symstore folder name is authoritative even when the PDB bytes are
#       MSFZ-compressed and unreadable by the pure-Python parser).
# ---------------------------------------------------------------------------


def test_symstore_folder_identity_parses_guid_and_age():
    fid = symbol_diagnostics._symstore_folder_identity
    # <32 hex GUID><uppercase hex age> with a dummy trailing file name.
    folder = Path(r"C:\symbols\ntkrnlmp.pdb\AFB1E3B137548BA73B92C060D6D5605F1\ntkrnlmp.pdb")
    assert fid(folder) == ("AFB1E3B137548BA73B92C060D6D5605F", 1)
    # Lowercase input is normalised to uppercase GUID.
    lower = Path(r"x\afb1e3b137548ba73b92c060d6d5605fa\foo.pdb")
    assert fid(lower) == ("AFB1E3B137548BA73B92C060D6D5605F", 10)


def test_symstore_folder_identity_rejects_non_symstore_folders():
    fid = symbol_diagnostics._symstore_folder_identity
    # A flat-layout PDB (parent is a plain dir name) is not a symstore folder.
    assert fid(Path(r"C:\symbols\windnsref.pdb")) is None
    # Too short to be GUID(32)+age(>=1).
    assert fid(Path(r"x\ABCDEF\foo.pdb")) is None
    # Non-hex characters.
    assert fid(Path(r"x\ZZB1E3B137548BA73B92C060D6D5605F1\foo.pdb")) is None


def _register_trace_with_image_and_symfolder(
    tmp_path: Path,
    *,
    module: str,
    pdb_name: str,
    trace_guid: str,
    trace_age: int,
    folder_guid_nodash: str,
    folder_age: int,
    trace_id: str,
) -> TraceData:
    """Register a trace whose image DF carries ``trace_guid``/``trace_age`` for
    ``module`` and whose symbol path contains a symstore folder named
    ``<folder_guid_nodash><folder_age:X>`` holding an MSFZ-style (non-MSF7,
    unreadable) PDB. The folder GUID/age may match or differ from the trace's.
    """
    symdir = tmp_path / f"sym-{trace_id}"
    folder = symdir / pdb_name / f"{folder_guid_nodash.upper()}{folder_age:X}"
    folder.mkdir(parents=True)
    # An MSFZ-ish PDB the pure-Python parser cannot decode (read_pdb_signature
    # returns None) -> the match must come from the folder name alone.
    (folder / pdb_name).write_bytes(b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00MSFZ-junk")

    etl = tmp_path / f"{trace_id}.etl"
    etl.write_bytes(b"synthetic")
    trace = TraceData(
        trace_id=trace_id,
        etl_path=etl,
        export_dir=tmp_path / f".export-{trace_id}",
        symbol_path=str(symdir),
    )
    trace.raw_csv["cpu_sampling"] = pd.DataFrame({
        "Process Name": ["System"] * 2,
        "PID": [4] * 2,
        "Weight": [100] * 2,
        "% Weight": [50.0] * 2,
        "Module": [module] * 2,
        "Function": ["Fn0", "Fn1"],
        "SymbolSource": ["pdb"] * 2,
    })
    trace.raw_csv["image"] = pd.DataFrame([{
        "FileName": rf"\Windows\System32\{module}",
        "ImageBase": 0xFFFFF80500000000,
        "ImageSize": 0x400000,
        "PdbGuid": trace_guid,
        "PdbAge": trace_age,
        "PdbName": pdb_name,
    }])
    register_trace(trace)
    return trace


def test_diagnose_msfz_folder_match_agrees_with_disk_verdict(tmp_path: Path):
    """A genuine MSFZ match (symstore folder GUID+Age == trace identity) must
    be recognised by BOTH diagnose_symbol_load and the check_symbols disk
    verdict, so the two tools never disagree (#3)."""
    guid = "AFB1E3B1-3754-8BA7-3B92-C060D6D5605F"
    trace = _register_trace_with_image_and_symfolder(
        tmp_path,
        module="ntoskrnl.exe",
        pdb_name="ntkrnlmp.pdb",
        trace_guid=guid,
        trace_age=1,
        folder_guid_nodash="AFB1E3B137548BA73B92C060D6D5605F",
        folder_age=1,
        trace_id="trace_msfz_match",
    )

    out = symbol_diagnostics.diagnose_symbol_load(trace.trace_id, module="ntoskrnl.exe")
    # diagnose recognises the match via the symstore folder name.
    assert "PDB exists on disk" in out
    assert "symstore folder" in out

    # check_symbols' disk cross-check must reach the SAME verdict.
    verdict = trace_mgmt._trace_pdb_disk_verdict(
        trace, "ntoskrnl.exe", trace.symbol_path
    )
    assert verdict == "match"


def test_diagnose_msfz_folder_mismatch_agrees_with_disk_verdict(tmp_path: Path):
    """When the only on-disk symstore folder is a DIFFERENT build than the
    trace identity, both diagnose_symbol_load and the check_symbols disk
    verdict must report a mismatch (#3)."""
    trace = _register_trace_with_image_and_symfolder(
        tmp_path,
        module="tcpip.sys",
        pdb_name="tcpip.pdb",
        trace_guid="D195DCC3-DF4C-5AA5-5734-4F154FE5AD1D",
        trace_age=1,
        # A wrong-build folder GUID for the same pdb name.
        folder_guid_nodash="7BB5F847000000000000000000000000",
        folder_age=2,
        trace_id="trace_msfz_mismatch",
    )

    out = symbol_diagnostics.diagnose_symbol_load(trace.trace_id, module="tcpip.sys")
    assert "No PDB matching trace GUID" in out

    verdict = trace_mgmt._trace_pdb_disk_verdict(
        trace, "tcpip.sys", trace.symbol_path
    )
    assert verdict == "mismatch"


# ---------------------------------------------------------------------------
# #3 secondary — read_pdb_signature reads the PDB Info Stream (stream 1)
# ---------------------------------------------------------------------------


def _build_synthetic_pdb(
    path: Path,
    *,
    guid_bytes: bytes,
    age: int,
    stream0_garbage: bytes,
) -> None:
    """Write a minimal but valid MSF 7.0 PDB whose Info Stream (stream 1)
    carries ``guid_bytes`` + ``age`` and whose stream 0 carries unrelated
    garbage (so a stream-0 reader would return the wrong GUID)."""
    page_size = 512
    magic = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"
    assert len(magic) == 32

    # Stream contents.
    stream0 = stream0_garbage.ljust(64, b"\x00")
    stream1 = struct.pack("<III", 20000404, 0x1234, age) + guid_bytes  # 28 bytes

    # Block layout: 0=superblock, 1=dir-root, 2=dir, 3=stream0, 4=stream1.
    dir_root_block = 1
    dir_block = 2
    stream0_block = 3
    stream1_block = 4
    num_blocks = 5

    # Directory: num_streams, sizes[], then concatenated block-index arrays.
    directory = struct.pack("<I", 2)                      # num_streams
    directory += struct.pack("<II", len(stream0), len(stream1))
    directory += struct.pack("<I", stream0_block)         # stream 0 blocks
    directory += struct.pack("<I", stream1_block)         # stream 1 blocks
    dir_size = len(directory)

    # Dir-root page holds the array of directory page indices.
    dir_root = struct.pack("<I", dir_block)

    superblock = bytearray(magic)
    superblock += struct.pack("<I", page_size)            # 32
    superblock += struct.pack("<I", 1)                    # 36 free page map
    superblock += struct.pack("<I", num_blocks)           # 40 num blocks
    superblock += struct.pack("<I", dir_size)             # 44 dir size
    superblock += struct.pack("<I", 0)                    # 48 reserved
    superblock += struct.pack("<I", dir_root_block)       # 52 dir root page

    buf = bytearray(b"\x00" * (page_size * num_blocks))

    def _put(block: int, data: bytes) -> None:
        buf[block * page_size: block * page_size + len(data)] = data

    _put(0, bytes(superblock))
    _put(dir_root_block, dir_root)
    _put(dir_block, directory)
    _put(stream0_block, stream0)
    _put(stream1_block, stream1)

    path.write_bytes(bytes(buf))


def test_read_pdb_signature_reads_info_stream_not_stream0(tmp_path: Path):
    # d1 little, d2 little, d3 little, d4 big — matches read_pdb_signature.
    d1, d2, d3 = 0x11223344, 0x5566, 0x7788
    d4 = bytes([0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00])
    guid_bytes = (
        d1.to_bytes(4, "little")
        + d2.to_bytes(2, "little")
        + d3.to_bytes(2, "little")
        + d4
    )
    expected_guid = "112233445566778899AABBCCDDEEFF00"
    age = 7

    pdb = tmp_path / "afd.pdb"
    _build_synthetic_pdb(
        pdb,
        guid_bytes=guid_bytes,
        age=age,
        # Stream 0 holds different bytes; a stream-0 reader would mis-parse.
        stream0_garbage=struct.pack("<III", 1, 2, 999) + b"\xDE\xAD\xBE\xEF" * 4,
    )

    result = symbol_diagnostics.read_pdb_signature(pdb)

    assert result is not None
    guid_str, got_age = result
    assert guid_str == expected_guid
    assert got_age == age


# ---------------------------------------------------------------------------
# #3 — GUID comparison + mismatch classification helpers
# ---------------------------------------------------------------------------


def test_guids_equal_normalizes_dashes_braces_case():
    eq = symbolizer_mod._guids_equal
    # Dashed form equals the same hex without dashes, case-insensitively.
    assert eq("D195DCC3-DF4C-1234-5678-90ABCDEF0001",
              "d195dcc3df4c1234567890abcdef0001") is True
    # Braces are ignored too.
    assert eq("D195DCC3-DF4C-1234-5678-90ABCDEF0001",
              "{d195dcc3df4c1234567890abcdef0001}") is True
    # A genuinely different GUID does not match.
    assert eq("D195DCC3-DF4C-1234-5678-90ABCDEF0001",
              "D195DCC3-DF4C-1234-5678-90ABCDEF0002") is False
    assert eq(None, "abc") is False
    assert eq("abc", "") is False


@pytest.mark.skipif(
    not symbolizer_mod.is_available(),
    reason="dbghelp not available on this platform",
)
def test_module_pdb_matches_flags_guid_mismatch(monkeypatch):
    try:
        sym = symbolizer_mod.Symbolizer()
    except Exception as exc:  # pragma: no cover - environment guard
        pytest.skip(f"could not construct Symbolizer: {exc}")

    sym_pdb = sym._dbghelp.SymPdb
    base = {
        "ImageBase": 0x1000,
        "identity_source": "image",  # non-RSDS: a non-strict local-image load
        "PdbGuid": "D195DCC3-DF4C-1234-5678-90ABCDEF0001",
        "PdbAge": 1,
    }

    # dbghelp reports a DIFFERENT loaded GUID -> mismatch.
    monkeypatch.setattr(
        sym, "_loaded_module_identity",
        lambda b: (sym_pdb, "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF", 1),
    )
    mismatch_mod = dict(base)
    assert sym._module_pdb_matches(mismatch_mod) is False

    # Loaded GUID matches the trace identity -> trustworthy.
    monkeypatch.setattr(
        sym, "_loaded_module_identity",
        lambda b: (sym_pdb, "D195DCC3-DF4C-1234-5678-90ABCDEF0001", 1),
    )
    match_mod = dict(base)
    assert sym._module_pdb_matches(match_mod) is True

    # Exact-GUID RSDS load is trusted without an info round-trip.
    rsds_mod = dict(base)
    rsds_mod["identity_source"] = "rsds"
    assert sym._module_pdb_matches(rsds_mod) is True

    # No captured identity -> never downgrade.
    no_id_mod = dict(base)
    no_id_mod["PdbGuid"] = None
    assert sym._module_pdb_matches(no_id_mod) is True

    sym.close()


# ---------------------------------------------------------------------------
# #8 — crash-exit detection + native-preferred resolve_symbols
# ---------------------------------------------------------------------------


def test_is_crash_exit_code_classifies_access_violation():
    # 0xC0000005 surfaces as the signed -1073741819 on Windows subprocess.
    assert trace_mgmt._is_crash_exit_code(-1073741819) is True
    assert trace_mgmt._is_crash_exit_code(0xC0000005) is True
    assert trace_mgmt._is_crash_exit_code(0xC000001D) is True  # illegal instr
    # Ordinary non-zero / success exits are not crashes.
    assert trace_mgmt._is_crash_exit_code(1) is False
    assert trace_mgmt._is_crash_exit_code(0) is False


def test_xperf_crash_exit_code_extracts_from_runtimeerror():
    crash = RuntimeError("xperf -a symcache failed (exit -1073741819):\nstderr: ")
    assert trace_mgmt._xperf_crash_exit_code(crash) == -1073741819
    benign = RuntimeError("xperf -a symcache failed (exit 1):\nstderr: oops")
    assert trace_mgmt._xperf_crash_exit_code(benign) is None
    nomatch = RuntimeError("some other failure")
    assert trace_mgmt._xperf_crash_exit_code(nomatch) is None


class _AvailableSymbolizer:
    """Minimal symbolizer stub that reports itself available."""

    def is_available(self):
        return True

    def bulk_resolve(self, addrs):
        return {int(a): "" for a in addrs}


def test_resolve_symbols_prefers_native_when_symbolizer_available(tmp_path: Path):
    """When a native symbolizer is attached, resolve_symbols must use it and
    skip the external xperf symcache path entirely (#8)."""
    df = pd.DataFrame({
        "Process Name": ["app.exe"] * 3,
        "PID": [100] * 3,
        "Weight": [100, 100, 100],
        "% Weight": [33.3, 33.3, 33.3],
        "Module": ["good.dll"] * 3,
        "Function": ["a", "b", "c"],
        "SymbolSource": ["pdb", "pdb", "pdb"],
    })
    trace = _register_trace_with_cpu_df(
        tmp_path, df, trace_id="trace_native_resolve",
        symbolizer=_AvailableSymbolizer(),
    )

    out = trace_mgmt.resolve_symbols(trace.trace_id)

    assert "native" in out.lower()
    assert "xperf not required" in out.lower()
    # The symbol-status report (check_symbols) should be embedded.
    assert "good.dll" in out


# ---------------------------------------------------------------------------
# #21 — stacks rebuild surfaces a clear error when the symbolizer throws
# ---------------------------------------------------------------------------


class _ThrowingSymbolizer:
    def is_available(self):
        return True

    def bulk_resolve(self, addrs):
        raise RuntimeError("simulated dbghelp fault during bulk_resolve")


def test_stacks_rebuild_throwing_symbolizer_reports_error(tmp_path: Path):
    """Degenerate 1-row stacks + a valid sampled_profile.parquet + a
    symbolizer that raises on bulk_resolve: the rebuild must be attempted and
    a clear error surfaced, NOT a silent all-unknown frame (#21)."""
    pytest.importorskip("pyarrow")
    import pyarrow as pa
    import pyarrow.parquet as pq

    from etw_analyzer.tools.stack_analysis import get_hot_stacks, _stack_warning_text

    export_dir = tmp_path / ".export-throwing"
    export_dir.mkdir()
    stacks = [[0x1000, 0x2000], [0x1000, 0x3000], [0x2000, 0x3000]]
    table = pa.table({
        "Stack": pa.array(stacks, type=pa.list_(pa.uint64())),
        "Weight": pa.array([1, 1, 1], type=pa.uint64()),
    })
    pq.write_table(table, export_dir / "sampled_profile.parquet")

    # 1-row placeholder stacks frame -> treated as unresolved/deferred.
    placeholder = pd.DataFrame({"Module": [""], "Function": [""]})
    trace = TraceData(
        trace_id="trace_throwing_rebuild",
        etl_path=tmp_path / "throw.etl",
        export_dir=export_dir,
        raw_csv={
            "stacks": placeholder,
            "cpu_sampling": pd.DataFrame({
                "Process Name": ["server.exe"],
                "PID": [1234],
                "Weight": [3],
                "% Weight": [100.0],
                "Module": ["driver.sys"],
                "Function": ["Leaf"],
            }),
        },
        duration_seconds=1.0,
        cpu_count=2,
    )
    trace.symbolizer = _ThrowingSymbolizer()
    register_trace(trace)

    # Must not raise.
    out = get_hot_stacks(trace.trace_id)
    assert isinstance(out, str)

    # The rebuild was attempted (not skipped silently).
    assert getattr(trace, "_stacks_raw_attempted", False) is True

    # A clear error must be recorded explaining symbolization failed.
    warning = _stack_warning_text(trace)
    assert "symboliz" in warning.lower()
    assert warning, "expected a non-empty stack symbolization warning"
