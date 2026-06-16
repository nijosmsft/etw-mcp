"""Bindings for ``dbghelp.dll`` — Windows debug-help symbol resolution.

This module wraps the subset of ``dbghelp`` needed by Phase N3's
``Symbolizer``: option flags, per-process initialization, module loading,
and address-to-symbol lookup. The struct definitions live in
:mod:`.types` (``SYMBOL_INFOW``).

Import side effects: loading this module calls ``WinDLL("dbghelp",
use_last_error=True)``. On non-Windows hosts that import raises
``OSError`` / ``FileNotFoundError``; ``native.symbolizer.is_available``
catches it so the rest of the codebase can probe safely.

The bindings deliberately mirror the SDK signatures and Phase-N1's
``advapi32.py`` style — no logic, just argtypes/restype declarations —
so any wrong-type call surfaces immediately as a ctypes error.
"""

from __future__ import annotations

import ctypes
from ctypes import POINTER, wintypes

from .types import SYMBOL_INFOW, IMAGEHLP_MODULEW64


# ---------------------------------------------------------------------------
# SymSetOptions flag constants (subset).
#
# Matching the feasibility prototype's exp5 setup. See ``DbgHelp.h`` for the
# authoritative table.
# ---------------------------------------------------------------------------
SYMOPT_CASE_INSENSITIVE     = 0x00000001
SYMOPT_UNDNAME              = 0x00000002  # undecorate C++ names
SYMOPT_DEFERRED_LOADS       = 0x00000004  # delay PDB I/O until first lookup
SYMOPT_LOAD_LINES           = 0x00000010  # capture line-number records
SYMOPT_FAIL_CRITICAL_ERRORS = 0x00000200  # suppress error dialogs
SYMOPT_AUTO_PUBLICS         = 0x00010000  # search publics by default
SYMOPT_DEBUG                = 0x80000000


# ---------------------------------------------------------------------------
# SYMBOL_INFOW.Flags bits we care about. See DbgHelp.h ``SYMFLAG_*``.
#
# When SymFromAddrW succeeds with no matching PDB symbol it still returns
# the nearest PE export-table entry and sets ``SYMFLAG_EXPORT`` on Flags.
# That is dbghelp telling us "this name came from the PE export table, not
# from a PDB" — the result is a heuristic, not a real symbol. We surface
# that bit so check_symbols / get_hot_functions can distinguish "PDB-quality
# function name" from "export-table nearest-neighbour guess".
# ---------------------------------------------------------------------------
SYMFLAG_EXPORT              = 0x00000200


# symsrv option flags for SymFindFileInPathW.
#
# SSRVOPT_GUIDPTR (0x00000008): the ``id`` argument points to a GUID struct;
# symsrv locates the PDB by GUID+Age in flat dirs, two-tier ``file.ptr``
# stores, and ``srv*...*http(s)`` servers.  Value confirmed as the canonical
# documented constant in the Windows SDK ``dbghelp.h`` / ``symsrv.h``.
#
# SSRVOPT_DWORDPTR (0x00000002): the ``id`` argument points to a DWORD
# (TimeDateStamp).  Retained here for completeness; the main M3 code path
# uses GUIDPTR.
SSRVOPT_GUIDPTR  = 0x00000008
SSRVOPT_DWORDPTR = 0x00000002


# Maximum symbol-name length we ever request from dbghelp. The SDK header
# uses MAX_SYM_NAME = 2000 as the conventional ceiling; SYMBOL_INFOW is
# typically allocated with this many WCHARs after the fixed prefix.
MAX_SYM_NAME = 2000


# Load dbghelp at import time. On non-Windows hosts this raises OSError;
# the higher-level ``Symbolizer.is_available`` wrapper turns that into a
# boolean so the rest of the codebase can probe safely.
#
# Prefer a newer dbghelp from a WinDbg/Debuggers installation when available,
# because the system dbghelp.dll (<=10.0.26100) cannot load MSFZ-format
# compressed PDBs (introduced in ~VS2024/Windows 11 build toolchain).
# The WinDbg "Debuggers" toolchain at 10.0.29507+ supports MSFZ.
# symsrv.dll must be loaded from the SAME directory as dbghelp so it
# satisfies dbghelp's import and handles the srv*cache*server path syntax.
def _load_dbghelp() -> ctypes.WinDLL:
    import os

    candidates = [
        # WinDbg external installation (common lab / dev setup).
        (r"C:\Debuggers\dbghelp.dll",      r"C:\Debuggers\symsrv.dll"),
        # WDK x64 Debuggers (usually older than the WinDbg build above).
        (r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\dbghelp.dll",
         r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symsrv.dll"),
        # System fallback — always present on Windows.
        ("dbghelp.dll", None),
    ]

    # Insert any WinDbg UWP / Store installs discovered at runtime.
    try:
        import glob
        uwp_hits = sorted(
            glob.glob(
                r"C:\Program Files\WindowsApps\Microsoft.WinDbg_*\x64\dbghelp.dll"
            ),
            reverse=True,  # highest version name first
        )
        for path in uwp_hits:
            symsrv = os.path.join(os.path.dirname(path), "symsrv.dll")
            candidates.insert(0, (path, symsrv))
    except Exception:
        pass

    for dbghelp_path, symsrv_path in candidates:
        if dbghelp_path != "dbghelp.dll" and not os.path.exists(dbghelp_path):
            continue
        # Load symsrv from the same directory first so dbghelp picks it up.
        if symsrv_path and os.path.exists(symsrv_path):
            try:
                ctypes.WinDLL(symsrv_path, use_last_error=True)
            except OSError:
                pass
        try:
            return ctypes.WinDLL(dbghelp_path, use_last_error=True)
        except OSError:
            continue

    raise OSError("Failed to load dbghelp.dll from any candidate path")


_dbghelp = _load_dbghelp()


# ---------------------------------------------------------------------------
# Function bindings.
# ---------------------------------------------------------------------------
SymInitializeW = _dbghelp.SymInitializeW
SymInitializeW.argtypes = [
    wintypes.HANDLE,    # hProcess (synthetic per design §6.2)
    wintypes.LPCWSTR,   # UserSearchPath (may be NULL)
    wintypes.BOOL,      # fInvadeProcess
]
SymInitializeW.restype = wintypes.BOOL


SymCleanup = _dbghelp.SymCleanup
SymCleanup.argtypes = [wintypes.HANDLE]
SymCleanup.restype = wintypes.BOOL


SymSetOptions = _dbghelp.SymSetOptions
SymSetOptions.argtypes = [wintypes.DWORD]
SymSetOptions.restype = wintypes.DWORD


SymGetOptions = _dbghelp.SymGetOptions
SymGetOptions.argtypes = []
SymGetOptions.restype = wintypes.DWORD


# ``SymLoadModuleExW(hProcess, hFile, ImageName, ModuleName, BaseOfDll,
#                    SizeOfDll, Data, Flags)`` → DWORD64 (loaded base or 0)
SymLoadModuleExW = _dbghelp.SymLoadModuleExW
SymLoadModuleExW.argtypes = [
    wintypes.HANDLE,           # hProcess
    wintypes.HANDLE,           # hFile (NULL — we never have a real handle)
    wintypes.LPCWSTR,          # ImageName
    wintypes.LPCWSTR,          # ModuleName (NULL — derive from ImageName)
    ctypes.c_ulonglong,        # BaseOfDll
    wintypes.DWORD,            # SizeOfDll
    ctypes.c_void_p,           # PMODLOAD_DATA Data (NULL)
    wintypes.DWORD,            # Flags
]
SymLoadModuleExW.restype = ctypes.c_ulonglong


SymUnloadModule64 = _dbghelp.SymUnloadModule64
SymUnloadModule64.argtypes = [wintypes.HANDLE, ctypes.c_ulonglong]
SymUnloadModule64.restype = wintypes.BOOL


# ``SymFromAddrW(hProcess, Address, Displacement, Symbol)`` → BOOL
#
# ``Symbol`` points at an over-allocated SYMBOL_INFOW buffer whose
# ``MaxNameLen`` field tells dbghelp how many WCHARs of name it can write
# into the trailing array. The struct definition in :mod:`.types` declares
# a single-WCHAR tail; ``Symbolizer._resolve_one`` allocates ``MaxNameLen``
# extra WCHARs immediately after.
SymFromAddrW = _dbghelp.SymFromAddrW
SymFromAddrW.argtypes = [
    wintypes.HANDLE,                # hProcess
    ctypes.c_ulonglong,             # Address
    POINTER(ctypes.c_ulonglong),    # Displacement
    POINTER(SYMBOL_INFOW),          # Symbol
]
SymFromAddrW.restype = wintypes.BOOL


# ``SymGetModuleInfoW64(hProcess, dwAddr, ModuleInfo)`` → BOOL
#
# Caller must populate ``ModuleInfo.SizeOfStruct = sizeof(IMAGEHLP_MODULEW64)``
# before the call. Returns FALSE if dbghelp has no module loaded that
# covers ``dwAddr``. ``ModuleInfo.SymType`` distinguishes a real PDB
# load (SymPdb / SymDeferred) from a PE export-table fallback (SymExport)
# - the central evidence ``diagnose_symbol_load`` reports to the user.
SymGetModuleInfoW64 = _dbghelp.SymGetModuleInfoW64
SymGetModuleInfoW64.argtypes = [
    wintypes.HANDLE,                  # hProcess
    ctypes.c_ulonglong,               # dwAddr
    POINTER(IMAGEHLP_MODULEW64),      # ModuleInfo
]
SymGetModuleInfoW64.restype = wintypes.BOOL


# ``SymFindFileInPathW(hProcess, SearchPath, FileName, id, two, three,
#                      flags, FoundFile, callback, context)`` → BOOL
#
# When ``flags == SSRVOPT_GUIDPTR``, ``id`` is a pointer to a GUID struct,
# ``two`` is the PDB Age (DWORD), and ``three`` is 0.  symsrv walks every
# element of the symbol search path — flat dirs, two-tier ``file.ptr``
# stores, and ``srv*...*https`` servers — and writes the resolved local PDB
# path into ``FoundFile`` (a caller-allocated MAX_PATH+1 WCHAR buffer).
# Returns TRUE on success.  On failure, GetLastError() typically returns
# ``ERROR_FILE_NOT_FOUND`` (2) or a WinHTTP error.
#
# Callers must pass a ``WCHAR[MAX_PATH+1]`` buffer for ``FoundFile``; on
# success it holds the full local path of the located PDB.  ``SearchPath``
# may be NULL to re-use the path from ``SymInitializeW``.  ``callback``
# and ``context`` may be NULL.
SymFindFileInPathW = _dbghelp.SymFindFileInPathW
SymFindFileInPathW.argtypes = [
    wintypes.HANDLE,    # hProcess
    wintypes.LPCWSTR,   # SearchPath (NULL -> symbol path from SymInitializeW)
    wintypes.LPCWSTR,   # FileName (PDB basename, e.g. "ntkrnlmp.pdb")
    ctypes.c_void_p,    # id (pointer to GUID when SSRVOPT_GUIDPTR)
    wintypes.DWORD,     # two (PDB Age)
    wintypes.DWORD,     # three (0)
    wintypes.DWORD,     # flags (SSRVOPT_GUIDPTR)
    wintypes.LPWSTR,    # FoundFile (caller-allocated output buffer, MAX_PATH+1)
    ctypes.c_void_p,    # callback (NULL)
    ctypes.c_void_p,    # context (NULL)
]
SymFindFileInPathW.restype = wintypes.BOOL


# SYM_TYPE enum values for IMAGEHLP_MODULEW64.SymType. See DbgHelp.h.
# ``SymExport`` is the smoking gun for "PDB missing - dbghelp fell back
# to PE exports". ``SymDeferred`` means SYMOPT_DEFERRED_LOADS was set
# and dbghelp hasn't actually loaded the PDB yet; force a SymFromAddr
# call into the module's address range to commit the load before
# inspecting the type. ``SymNone`` means no symbols at all.
SymNone     = 0
SymCoff     = 1
SymCv       = 2
SymPdb      = 3
SymExport   = 4
SymDeferred = 5
SymSym      = 6
SymDia      = 7
SymVirtual  = 8


# Helper for callers to render SymType as a readable string.
_SYM_TYPE_NAMES = {
    SymNone: "SymNone",
    SymCoff: "SymCoff",
    SymCv: "SymCv",
    SymPdb: "SymPdb",
    SymExport: "SymExport",
    SymDeferred: "SymDeferred",
    SymSym: "SymSym",
    SymDia: "SymDia",
    SymVirtual: "SymVirtual",
}


def sym_type_name(sym_type: int) -> str:
    """Return the SDK identifier name for a SYM_TYPE value."""
    return _SYM_TYPE_NAMES.get(int(sym_type), f"Unknown({sym_type})")


__all__ = [
    "SYMOPT_CASE_INSENSITIVE",
    "SYMOPT_UNDNAME",
    "SYMOPT_DEFERRED_LOADS",
    "SYMOPT_LOAD_LINES",
    "SYMOPT_FAIL_CRITICAL_ERRORS",
    "SYMOPT_AUTO_PUBLICS",
    "SYMOPT_DEBUG",
    "SYMFLAG_EXPORT",
    "SSRVOPT_GUIDPTR",
    "SSRVOPT_DWORDPTR",
    "MAX_SYM_NAME",
    "SymInitializeW",
    "SymCleanup",
    "SymSetOptions",
    "SymGetOptions",
    "SymLoadModuleExW",
    "SymUnloadModule64",
    "SymFromAddrW",
    "SymGetModuleInfoW64",
    "SymFindFileInPathW",
    "SymNone",
    "SymCoff",
    "SymCv",
    "SymPdb",
    "SymExport",
    "SymDeferred",
    "SymSym",
    "SymDia",
    "SymVirtual",
    "sym_type_name",
]
