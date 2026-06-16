"""Symbol diagnostics: explain WHY a module resolved to export-table
guesses and offer to clean up stale SymCache entries.

When ``check_symbols`` reports a module as ``EXPORT_ONLY`` the user
needs to know:

1. Where is dbghelp actually looking for the PDB?
2. What identity (GUID + Age) does the EXE's debug directory point at?
3. Which PDB files on disk - in ``_NT_SYMBOL_PATH`` entries and the
   ``C:\\SymCache`` shadow tree - match or mismatch that identity?

The kernel-driver test workflow on this repo trips over the third one
constantly: a developer overwrites ``windnsref.exe`` with a new build
but doesn't clear ``C:\\SymCache\\windnsref.pdb\\<old-age>\\``, and
dbghelp grabs the stale PDB because the SymCache path comes earlier in
the search order. With the wrong PDB loaded the addresses no longer
align with real functions, so dbghelp falls back to the PE export
table (or just to ``Unknown``).

This module provides two MCP tools:

- ``diagnose_symbol_load(trace_id, module)`` - walks the EXE on disk
  for the RSDS (CV_INFO_PDB70) record, walks every entry of the
  effective ``_NT_SYMBOL_PATH``, lists each candidate PDB and whether
  its GUID+Age match. Also calls ``SymGetModuleInfoW64`` against the
  loaded ``Symbolizer`` to report what dbghelp ACTUALLY loaded.

- ``clean_stale_symbol_files(module, exe_path, dry_run=True)`` -
  walks the ``C:\\SymCache\\<module>.pdb\\`` subfolders, identifies
  GUID+Age subfolders that don't match the current EXE's RSDS record,
  and optionally deletes them.

Both tools are pure-Python: PE parsing reads the DOS header → NT
headers → debug data directory → RSDS record without depending on
external tools. dbghelp is only used for the loaded-state query.
"""

from __future__ import annotations

import ctypes
import os
import shutil
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

import pandas as pd

from etw_analyzer.app import mcp
from etw_analyzer.formatting.markdown import format_table
from etw_analyzer.trace_state import require_trace
from etw_analyzer.tools.trace_mgmt import _resolve_sym_path


# ---------------------------------------------------------------------------
# PE / RSDS parsing — pure Python, no dbghelp dependency.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RsdsRecord:
    """The CV_INFO_PDB70 record embedded in a PE's debug directory.

    ``guid_string`` is the canonical no-dashes uppercase form used by
    SymCache folder names (matches dbghelp's symstore convention).
    ``age`` is a small monotonic integer the linker bumps when a PDB
    is rebuilt without re-linking; SymCache embeds it as a hex suffix
    on the GUID folder name (e.g. ``8FE6FCD66E8B4F8FBFB60FE6D87E81E5C``
    where the trailing ``C`` is the age).
    """
    guid_string: str        # 32-char uppercase hex, no dashes
    age: int                # uint32
    pdb_path: str           # path as recorded in the PE (may be absolute)

    @property
    def symcache_folder_name(self) -> str:
        """The directory name SymCache uses: GUID + uppercase hex age."""
        return f"{self.guid_string}{self.age:X}"


def read_pe_rsds(exe_path: Path) -> Optional[RsdsRecord]:
    """Parse a PE file's debug directory and return its RSDS record.

    Returns ``None`` if the file isn't a valid PE, has no debug
    directory, or the debug directory contains no CV_INFO_PDB70 entry.
    Reads at most a few KB - safe to call on large EXEs.
    """
    try:
        with exe_path.open("rb") as f:
            data = f.read()
    except OSError:
        return None

    if len(data) < 0x40 or data[:2] != b"MZ":
        return None

    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_off + 24 > len(data) or data[pe_off:pe_off + 4] != b"PE\x00\x00":
        return None

    # COFF header is right after the "PE\0\0" signature.
    machine = struct.unpack_from("<H", data, pe_off + 4)[0]
    num_sections = struct.unpack_from("<H", data, pe_off + 6)[0]
    opt_hdr_size = struct.unpack_from("<H", data, pe_off + 20)[0]
    opt_off = pe_off + 24

    if opt_off + 2 > len(data):
        return None
    magic = struct.unpack_from("<H", data, opt_off)[0]

    # PE32 (0x10B): data directories start at opt_off + 96.
    # PE32+ (0x20B): data directories start at opt_off + 112.
    if magic == 0x10B:
        data_dir_off = opt_off + 96
    elif magic == 0x20B:
        data_dir_off = opt_off + 112
    else:
        return None

    # Debug data directory is entry index 6.
    debug_dir_entry_off = data_dir_off + 6 * 8
    if debug_dir_entry_off + 8 > len(data):
        return None
    debug_rva, debug_size = struct.unpack_from("<II", data, debug_dir_entry_off)
    if debug_rva == 0 or debug_size == 0:
        return None

    # Walk section headers to translate the debug RVA into a file offset.
    sections_off = opt_off + opt_hdr_size
    debug_file_off: Optional[int] = None
    for i in range(num_sections):
        sec_off = sections_off + i * 40
        if sec_off + 40 > len(data):
            return None
        virt_size, virt_addr, raw_size, raw_ptr = struct.unpack_from(
            "<IIII", data, sec_off + 8
        )
        if virt_addr <= debug_rva < virt_addr + max(virt_size, raw_size):
            debug_file_off = raw_ptr + (debug_rva - virt_addr)
            break

    if debug_file_off is None:
        return None

    # Walk IMAGE_DEBUG_DIRECTORY entries (28 bytes each) looking for
    # type 2 (IMAGE_DEBUG_TYPE_CODEVIEW).
    entry_size = 28
    for i in range(debug_size // entry_size):
        e_off = debug_file_off + i * entry_size
        if e_off + entry_size > len(data):
            break
        _chars, _ts, _maj_min, dtype, size_of_data, _addr_rva, ptr_to_raw = (
            struct.unpack_from("<IIIIIII", data, e_off)
        )
        if dtype != 2:
            continue
        if ptr_to_raw + 24 > len(data):
            continue
        rec = data[ptr_to_raw:ptr_to_raw + size_of_data]
        if len(rec) < 24 or rec[:4] != b"RSDS":
            continue
        # CV_INFO_PDB70 layout: 4B sig, 16B GUID, 4B age, N-byte
        # zero-terminated UTF-8 PDB path.
        guid_bytes = rec[4:20]
        age = struct.unpack_from("<I", rec, 20)[0]
        path_bytes = rec[24:].split(b"\x00", 1)[0]
        try:
            pdb_path = path_bytes.decode("utf-8", errors="replace")
        except Exception:
            pdb_path = ""
        # GUID on disk is little-endian for Data1/2/3, big-endian for Data4.
        d1 = int.from_bytes(guid_bytes[0:4], "little")
        d2 = int.from_bytes(guid_bytes[4:6], "little")
        d3 = int.from_bytes(guid_bytes[6:8], "little")
        d4 = guid_bytes[8:16]
        guid_str = (
            f"{d1:08X}{d2:04X}{d3:04X}"
            + "".join(f"{b:02X}" for b in d4)
        )
        return RsdsRecord(guid_string=guid_str, age=age, pdb_path=pdb_path)

    return None


def read_pdb_signature(pdb_path: Path) -> Optional[tuple[str, int]]:
    """Read the PDB 7.0 stream-0 signature: (GUID hex string, age).

    Returns ``None`` if the file isn't a valid PDB or the layout
    differs from the expected MSF/Stream-0 form. This is a lightweight
    parser - it walks the MSF page directory just far enough to locate
    stream 0, which is where the GUID+Age live.

    PDB layout (per Microsoft's microsoft-pdb repo):
    - Bytes 0..32  : "Microsoft C/C++ MSF 7.00\\r\\n\\x1a\\x44\\x53\\x00\\x00\\x00"
    - DWORD        : page size (usually 4096)
    - DWORD        : free page map page
    - DWORD        : pages in file
    - DWORD        : directory size in bytes
    - DWORD        : reserved
    - DWORDs       : array of page indices for the directory pages
    Stream 0 (PDB info stream) starts with:
    - DWORD        : version (20000404 etc)
    - DWORD        : signature (timestamp)
    - DWORD        : age
    - 16 bytes     : GUID
    """
    try:
        with pdb_path.open("rb") as f:
            head = f.read(56)
            if len(head) < 56 or not head.startswith(b"Microsoft C/C++ MSF 7.00"):
                return None
            page_size = struct.unpack_from("<I", head, 32)[0]
            dir_size = struct.unpack_from("<I", head, 44)[0]
            # The first directory-pages-pointer page index lives right
            # after the reserved DWORD (offset 52). We need only the
            # first DWORD entry to find stream 0's directory.
            dir_root_page_idx = struct.unpack_from("<I", head, 52)[0]

            # Read the directory: dir_size bytes spread across pages
            # whose indices are stored at dir_root_page (each is a
            # 32-bit page index).
            f.seek(dir_root_page_idx * page_size)
            dir_root = f.read(page_size)
            pages_in_dir = (dir_size + page_size - 1) // page_size
            dir_page_indices = struct.unpack_from(
                f"<{pages_in_dir}I", dir_root, 0
            )

            dir_buf = bytearray()
            for pidx in dir_page_indices:
                f.seek(pidx * page_size)
                dir_buf.extend(f.read(page_size))
            dir_buf = bytes(dir_buf[:dir_size])

            # Directory layout: NumStreams, then NumStreams x StreamSize,
            # then NumStreams x (array of page indices for that stream).
            num_streams = struct.unpack_from("<I", dir_buf, 0)[0]
            if num_streams < 1:
                return None
            stream_sizes = struct.unpack_from(
                f"<{num_streams}I", dir_buf, 4
            )
            stream0_size = stream_sizes[0]
            if stream0_size == 0xFFFFFFFF or stream0_size == 0:
                return None
            # Pages for each stream start after the sizes.
            page_idx_off = 4 + num_streams * 4
            stream0_pages_count = (stream0_size + page_size - 1) // page_size
            stream0_page_indices = struct.unpack_from(
                f"<{stream0_pages_count}I", dir_buf, page_idx_off
            )

            buf = bytearray()
            for pidx in stream0_page_indices:
                f.seek(pidx * page_size)
                buf.extend(f.read(page_size))
            buf = bytes(buf[:stream0_size])

            if len(buf) < 28:
                return None
            _ver, _sig, age = struct.unpack_from("<III", buf, 0)
            guid_bytes = buf[12:28]
            d1 = int.from_bytes(guid_bytes[0:4], "little")
            d2 = int.from_bytes(guid_bytes[4:6], "little")
            d3 = int.from_bytes(guid_bytes[6:8], "little")
            d4 = guid_bytes[8:16]
            guid_str = (
                f"{d1:08X}{d2:04X}{d3:04X}"
                + "".join(f"{b:02X}" for b in d4)
            )
            return (guid_str, age)
    except (OSError, struct.error):
        return None


# ---------------------------------------------------------------------------
# Symbol path parsing — walk a semicolon-joined search path into the
# concrete directories where dbghelp will look.
# ---------------------------------------------------------------------------


def parse_symbol_path(sym_path: str) -> list[tuple[str, Path]]:
    """Return [(kind, dir), ...] for each searchable directory.

    ``kind`` is one of:
    - ``"symcache"``  - a ``cache*<dir>`` or implicit symstore cache
    - ``"local"``     - a plain directory
    - ``"server"``    - the local cache dir of a ``srv*<cache>*...`` entry
    - ``"store"``     - an upstream filesystem store (UNC or drive-letter
                        path) from a ``srv*<cache>*<upstream>`` entry;
                        http(s):// and ``symweb`` upstreams are skipped
                        since they are not locally globbable.

    Unparseable entries are skipped silently — the caller should treat
    the absence of an entry as "this part of _NT_SYMBOL_PATH isn't
    contributing to local search".
    """
    out: list[tuple[str, Path]] = []
    if not sym_path:
        return out
    for raw in sym_path.split(";"):
        entry = raw.strip()
        if not entry:
            continue
        lower = entry.lower()
        if lower.startswith("srv*") or lower.startswith("symsrv*"):
            parts = entry.split("*")
            # srv*<cache>*<upstream1>*<upstream2>...
            # parts[1] is the local cache dir
            if len(parts) >= 2 and parts[1]:
                out.append(("server", Path(parts[1])))
            # parts[2:] are upstream stores — include filesystem paths
            # (UNC \\... or drive-letter); skip http(s):// and symweb.
            for upstream in parts[2:]:
                if not upstream:
                    continue
                up_lower = upstream.lower()
                if up_lower.startswith("http://") or up_lower.startswith("https://"):
                    continue
                if up_lower == "symweb" or up_lower.startswith("symweb/"):
                    continue
                out.append(("store", Path(upstream)))
            continue
        if lower.startswith("cache*"):
            parts = entry.split("*", 1)
            if len(parts) == 2 and parts[1]:
                out.append(("symcache", Path(parts[1])))
            continue
        # Plain directory.
        out.append(("local", Path(entry)))
    return out


def _resolve_file_ptr(ptr_file: Path) -> Path | None:
    """Read a symstore file.ptr and return the target PDB path, or None.

    Handles three content forms:
    - ``PATH:<path>``          : strip the ``PATH:`` prefix
    - bare relative path       : resolved relative to the GUID+Age folder
    - bare absolute / UNC path : used as-is

    Returns ``None`` if the file is unreadable, empty, or the resolved
    target does not exist on disk. Never raises.
    """
    try:
        content = ptr_file.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None
    if not content:
        return None
    if content.upper().startswith("PATH:"):
        target = Path(content[5:].strip())
    else:
        target = Path(content)
    if not target.is_absolute():
        # Resolve relative to the GUID+Age folder (ptr_file's parent).
        target = (ptr_file.parent / target).resolve()
    try:
        return target if target.is_file() else None
    except OSError:
        return None


def _iter_candidates(
    sym_path: str,
    module_name: str,
    pdb_name: str,
) -> Iterable[tuple[Path, str | None]]:
    """Yield (pdb_path, redirect_description_or_None) for each candidate PDB.

    ``redirect_description`` is set when the candidate was reached via a
    ``file.ptr`` redirect; it is ``None`` for direct (literal) matches.
    """
    for _kind, dir_path in parse_symbol_path(sym_path):
        if not dir_path.exists():
            continue
        # Flat layout
        flat = dir_path / pdb_name
        if flat.is_file():
            yield (flat, None)
        # Symstore layout: <dir>/<pdb_name>/<GUID+Age>/<pdb_name>
        sym_root = dir_path / pdb_name
        if sym_root.is_dir():
            try:
                for sub in sorted(sym_root.iterdir()):
                    if not sub.is_dir():
                        continue
                    # Literal PDB file in the GUID+Age subfolder.
                    candidate = sub / pdb_name
                    if candidate.is_file():
                        yield (candidate, None)
                    # file.ptr redirect (pointer-indexed symstore).
                    ptr = sub / "file.ptr"
                    if ptr.is_file():
                        target = _resolve_file_ptr(ptr)
                        if target is not None:
                            yield (
                                target,
                                f"via file.ptr redirect: {ptr} -> {target}",
                            )
            except OSError:
                continue


def candidate_pdb_paths(
    sym_path: str,
    module_name: str,
    pdb_name: str,
) -> list[Path]:
    """Enumerate every PDB path dbghelp would try for ``module_name``.

    For each directory ``D`` in ``_NT_SYMBOL_PATH`` dbghelp tries:
      - ``D\\<pdb_name>``  (flat layout)
      - ``D\\<pdb_name>\\<GUID+Age>\\<pdb_name>``  (symstore layout)

    We can't enumerate the GUID+Age subfolders without knowing them
    ahead of time, so we glob ``D\\<pdb_name>\\*\\<pdb_name>`` for each
    directory and return whatever exists.

    Also follows ``file.ptr`` redirects written by pointer-indexed
    symbol stores (``D\\<pdb_name>\\<GUID+Age>\\file.ptr`` whose
    content resolves to the real PDB path).
    """
    return [path for path, _ in _iter_candidates(sym_path, module_name, pdb_name)]


# ---------------------------------------------------------------------------
# diagnose_symbol_load
# ---------------------------------------------------------------------------


def _query_loaded_module(trace, module_name: str) -> Optional[dict]:
    """Ask the trace's Symbolizer what dbghelp loaded for ``module_name``.

    Returns ``None`` if the trace has no symbolizer or dbghelp has no
    module covering any sampled address from that module. The returned
    dict contains ``loaded_pdb``, ``sym_type``, ``pdb_guid``, ``pdb_age``,
    ``pdb_unmatched``.
    """
    symbolizer = getattr(trace, "symbolizer", None)
    if symbolizer is None:
        return None

    # Find a sampled address from this module so we can query
    # SymGetModuleInfoW64. We need any address that dbghelp considers
    # to live inside the module.
    cpu_df = None
    for key in ("cpu_sampling", "CpuSampling", "CPU Usage (Sampled)"):
        if key in trace.raw_csv:
            cpu_df = trace.raw_csv[key]
            break
    if cpu_df is None or "Module" not in cpu_df.columns:
        return None
    if "Address" not in cpu_df.columns and "address" not in cpu_df.columns:
        # The aggregated cpu_sampling frame doesn't carry raw addresses.
        # Try a module base from the symbolizer's loaded list instead.
        modules = getattr(symbolizer, "_modules", None)
        if not modules:
            return None
        target_lower = module_name.lower()
        for base, entry in modules.items():
            file_name = entry.get("FileName") or entry.get("DbgHelpPath") or ""
            if Path(file_name).name.lower() == target_lower:
                return _call_sym_get_module_info(symbolizer, base)
        return None
    addr_col = "Address" if "Address" in cpu_df.columns else "address"
    mod_lower = module_name.lower()
    matches = cpu_df[cpu_df["Module"].astype(str).str.lower() == mod_lower]
    if matches.empty:
        return None
    sample_addr = int(matches.iloc[0][addr_col])
    return _call_sym_get_module_info(symbolizer, sample_addr)


def _call_sym_get_module_info(symbolizer, address: int) -> Optional[dict]:
    """Wrap SymGetModuleInfoW64 with proper SizeOfStruct."""
    try:
        from etw_analyzer.native.bindings.dbghelp import (
            SymGetModuleInfoW64,
            sym_type_name,
        )
        from etw_analyzer.native.bindings.types import IMAGEHLP_MODULEW64, guid_string
    except OSError:
        return None

    info = IMAGEHLP_MODULEW64()
    info.SizeOfStruct = ctypes.sizeof(IMAGEHLP_MODULEW64)
    h_process = getattr(symbolizer, "_handle", None)
    if h_process is None:
        return None
    ok = SymGetModuleInfoW64(h_process, ctypes.c_ulonglong(address), ctypes.byref(info))
    if not ok:
        return None
    return {
        "loaded_pdb": info.LoadedPdbName or info.CVData or "(unset)",
        "sym_type": sym_type_name(int(info.SymType)),
        "pdb_guid": guid_string(info.PdbSig70).upper().replace("-", ""),
        "pdb_age": int(info.PdbAge),
        "pdb_unmatched": bool(info.PdbUnmatched),
        "image_name": info.ImageName,
    }


@mcp.tool()
def diagnose_symbol_load(
    trace_id: str,
    module: str,
    exe_path: str | None = None,
    extra_symbol_paths: list[str] | None = None,
) -> str:
    """Explain why a module resolved to PE export-table guesses (or
    not at all) and surface every candidate PDB on disk.

    The output walks three independent sources of truth and compares
    them so the user can see exactly where the mismatch is:

    1. **EXE on disk**: the RSDS (CV_INFO_PDB70) record embedded in
       the PE debug directory tells us what GUID+Age the linker
       stamped. This is the authoritative identity the PDB must match.
    2. **Symbol path entries**: every directory in ``_NT_SYMBOL_PATH``
       (plus ``extra_symbol_paths``) is walked. For each candidate
       PDB we report its GUID+Age and whether they match the EXE.
    3. **Loaded state**: ``SymGetModuleInfoW64`` reports what dbghelp
       actually opened and whether ``SymType == SymExport`` (the
       smoking gun for "PDB missing, dbghelp fell back to exports").

    Args:
        trace_id: ID returned by load_trace.
        module: Module name (e.g. ``mswsock.dll``, ``windnsref.exe``).
        exe_path: Optional explicit path to the EXE on disk. If not
            given, the module's loaded image path from the trace is
            used. Required when the module wasn't loaded by the
            traced process (so the EXE path isn't recoverable).
        extra_symbol_paths: Additional directories to inspect for
            candidate PDBs, on top of ``_NT_SYMBOL_PATH``.
    """
    trace = require_trace(trace_id)
    sym_path = _resolve_sym_path(
        trace.symbol_path or os.environ.get("_NT_SYMBOL_PATH", ""),
        extra_symbol_paths,
    ) or ""

    lines: list[str] = [f"**Symbol Load Diagnostics: `{module}`**", ""]
    lines.append(f"Trace: `{trace.etl_path.name}`")
    if sym_path:
        lines.append(f"Symbol path: `{sym_path}`")
    else:
        lines.append("Symbol path: **(unset)** - no candidate PDBs can be found")
    lines.append("")

    # Locate the EXE on disk.
    exe = Path(exe_path) if exe_path else _find_exe_for_module(trace, module)
    if exe is None or not exe.exists():
        lines.append("**EXE on disk:** not found")
        lines.append("")
        lines.append(
            "Pass ``exe_path=...`` pointing at the binary that was "
            "running when the trace was captured. Without the EXE we "
            "cannot read the RSDS record and cannot tell which PDB on "
            "disk is correct."
        )
        return "\n".join(lines)

    lines.append(f"**EXE on disk:** `{exe}`")
    rsds = read_pe_rsds(exe)
    if rsds is None:
        lines.append("- No RSDS record found - the binary may be stripped of debug info.")
        lines.append("")
        return "\n".join(lines)
    lines.append(f"- RSDS GUID: `{rsds.guid_string}`")
    lines.append(f"- RSDS Age:  `{rsds.age}` (0x{rsds.age:X})")
    lines.append(f"- PDB hint:  `{rsds.pdb_path}`")
    lines.append(f"- SymCache key: `{rsds.symcache_folder_name}`")
    lines.append("")

    # Walk candidate PDB paths.
    pdb_name = Path(rsds.pdb_path).name if rsds.pdb_path else f"{Path(module).stem}.pdb"
    candidate_entries = list(_iter_candidates(sym_path, module, pdb_name))
    lines.append(f"**Candidate PDBs on disk** (searching for `{pdb_name}`):")
    if not candidate_entries:
        lines.append("- None found in any symbol path entry.")
    else:
        has_redirects = any(rd is not None for _, rd in candidate_entries)
        rows = []
        for cand, redirect_desc in candidate_entries:
            sig = read_pdb_signature(cand)
            row: dict = {
                "Path": str(cand),
                "GUID": "(unreadable)" if sig is None else sig[0],
                "Age": "?" if sig is None else str(sig[1]),
                "Match": "NO" if sig is None else (
                    "YES" if (sig[0] == rsds.guid_string and sig[1] == rsds.age) else "NO"
                ),
            }
            if has_redirects:
                if redirect_desc:
                    # Show just the file.ptr file; the resolved path is in "Path".
                    ptr_path = redirect_desc.split(" -> ")[0].replace(
                        "via file.ptr redirect: ", ""
                    )
                    row["Redirect"] = f"file.ptr: {ptr_path}"
                else:
                    row["Redirect"] = ""
            rows.append(row)
        df = pd.DataFrame(rows)
        lines.append("")
        lines.append(format_table(df, max_rows=25))
    lines.append("")

    # Query dbghelp for the actually-loaded state.
    loaded = _query_loaded_module(trace, module)
    lines.append("**Loaded state (from dbghelp):**")
    if loaded is None:
        lines.append("- dbghelp has no module loaded for this image.")
    else:
        lines.append(f"- Loaded PDB:   `{loaded['loaded_pdb']}`")
        lines.append(f"- SymType:      `{loaded['sym_type']}`")
        lines.append(f"- PDB GUID:     `{loaded['pdb_guid']}`")
        lines.append(f"- PDB Age:      `{loaded['pdb_age']}`")
        lines.append(f"- PDB Unmatched flag: `{loaded['pdb_unmatched']}`")
        if loaded["sym_type"] == "SymExport":
            lines.append("")
            lines.append(
                "**Diagnosis:** dbghelp loaded only the PE export table - "
                "no matching PDB was found. Function names from this "
                "module are nearest-neighbour guesses and may be wrong "
                "by hundreds of bytes."
            )
        elif loaded["pdb_unmatched"]:
            lines.append("")
            lines.append(
                "**Diagnosis:** dbghelp loaded a PDB but flagged it as "
                "unmatched. The PDB GUID or Age does not match the EXE - "
                "function names will be wrong."
            )
    lines.append("")

    # Actionable next steps.
    lines.append("**Next steps:**")
    if rsds is not None and any(
        (read_pdb_signature(c) == (rsds.guid_string, rsds.age)) for c, _ in candidate_entries
    ):
        lines.append(
            "- A matching PDB exists on disk. If dbghelp still reports "
            "``SymExport``, an older stale PDB is shadowing it via the "
            "SymCache search order. Run "
            "``clean_stale_symbol_files('" + module + "', '" + str(exe) + "')`` "
            "to list (and optionally delete) the stale entries."
        )
    else:
        lines.append(
            f"- No PDB with GUID `{rsds.guid_string}` Age `{rsds.age}` "
            "was found in any symbol path entry. Build the PDB locally "
            "and either copy it into one of the search directories or "
            "pass ``extra_symbol_paths=['<dir>']`` to ``load_trace`` / "
            "``check_symbols``."
        )

    return "\n".join(lines)


def _find_exe_for_module(trace, module: str) -> Optional[Path]:
    """Best-effort: find the EXE on disk that matches ``module``.

    Looks at the symbolizer's loaded-modules table for an image whose
    filename matches. Returns ``None`` when no match is found - the
    caller should ask the user for ``exe_path``.
    """
    symbolizer = getattr(trace, "symbolizer", None)
    if symbolizer is None:
        return None
    modules = getattr(symbolizer, "_modules", None)
    if not modules:
        return None
    target = module.lower()
    for entry in modules.values():
        file_name = entry.get("FileName") or entry.get("DbgHelpPath") or ""
        try:
            if Path(file_name).name.lower() == target:
                p = Path(file_name)
                if p.exists():
                    return p
        except (OSError, ValueError):
            continue
    return None


# ---------------------------------------------------------------------------
# clean_stale_symbol_files
# ---------------------------------------------------------------------------


@mcp.tool()
def clean_stale_symbol_files(
    module: str,
    exe_path: str,
    dry_run: bool = True,
    symcache_root: str | None = None,
) -> str:
    """List (and optionally delete) SymCache subfolders that don't match
    the current EXE's RSDS GUID+Age.

    A typical kernel-driver dev loop overwrites the EXE but leaves the
    stale PDB subfolders in ``C:\\SymCache\\<module>.pdb\\``. dbghelp's
    search order can pick up the wrong one and silently degrade to
    export-table fallback. This tool finds those orphans and offers to
    delete them.

    By default ``dry_run=True`` - we print what would be deleted but
    don't touch the filesystem. Pass ``dry_run=False`` to actually
    delete.

    Args:
        module: Module filename (e.g. ``windnsref.exe``).
        exe_path: Path to the current EXE on disk. We read its RSDS
            record to determine which GUID+Age subfolder is the right
            one.
        dry_run: When True (default), only list candidates. When False,
            delete matching subfolders.
        symcache_root: Override the SymCache root. Default:
            ``C:\\SymCache``.
    """
    exe = Path(exe_path)
    if not exe.exists():
        return f"EXE not found: {exe_path}"

    rsds = read_pe_rsds(exe)
    if rsds is None:
        return f"No RSDS record in `{exe_path}`. Cannot determine which PDB is current."

    pdb_name = Path(rsds.pdb_path).name if rsds.pdb_path else f"{Path(module).stem}.pdb"
    sym_root = Path(symcache_root) if symcache_root else Path(r"C:\SymCache")
    module_root = sym_root / pdb_name

    lines: list[str] = [
        f"**Stale Symbol Cleanup: `{module}`**",
        "",
        f"EXE: `{exe}`",
        f"RSDS identity: `{rsds.guid_string}` Age `{rsds.age}` "
        f"(folder name `{rsds.symcache_folder_name}`)",
        f"SymCache root: `{sym_root}`",
        f"Module subtree: `{module_root}`",
        "",
    ]

    if not module_root.is_dir():
        lines.append(f"No subtree at `{module_root}` - nothing to clean.")
        return "\n".join(lines)

    keep_folder = rsds.symcache_folder_name.lower()
    rows = []
    deletable: list[Path] = []
    try:
        subfolders = sorted(p for p in module_root.iterdir() if p.is_dir())
    except OSError as e:
        return "\n".join(lines + [f"Cannot enumerate `{module_root}`: {e}"])

    for sub in subfolders:
        is_current = sub.name.lower() == keep_folder
        rows.append({
            "Folder": sub.name,
            "Status": "KEEP (current)" if is_current else "STALE",
        })
        if not is_current:
            deletable.append(sub)

    df = pd.DataFrame(rows)
    lines.append(format_table(df, max_rows=50))
    lines.append("")

    if not deletable:
        lines.append("No stale folders to delete.")
        return "\n".join(lines)

    lines.append(f"**Stale folders ({len(deletable)}):**")
    for sub in deletable:
        lines.append(f"- `{sub}`")
    lines.append("")

    if dry_run:
        lines.append(
            "Dry-run mode: nothing was deleted. Re-run with "
            "``dry_run=False`` to actually remove these folders."
        )
    else:
        deleted = []
        failed = []
        for sub in deletable:
            try:
                shutil.rmtree(sub)
                deleted.append(sub)
            except OSError as e:
                failed.append((sub, str(e)))
        lines.append(f"Deleted {len(deleted)} folders.")
        if failed:
            lines.append(f"Failed to delete {len(failed)}:")
            for sub, err in failed:
                lines.append(f"- `{sub}`: {err}")

    return "\n".join(lines)
