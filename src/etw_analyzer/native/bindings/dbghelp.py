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

from .types import SYMBOL_INFOW


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


# Maximum symbol-name length we ever request from dbghelp. The SDK header
# uses MAX_SYM_NAME = 2000 as the conventional ceiling; SYMBOL_INFOW is
# typically allocated with this many WCHARs after the fixed prefix.
MAX_SYM_NAME = 2000


# Load dbghelp lazily at import time. On non-Windows hosts this raises
# OSError; the higher-level ``Symbolizer.is_available`` wrapper turns
# that into a boolean so the rest of the codebase can probe safely.
_dbghelp = ctypes.WinDLL("dbghelp.dll", use_last_error=True)


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


__all__ = [
    "SYMOPT_CASE_INSENSITIVE",
    "SYMOPT_UNDNAME",
    "SYMOPT_DEFERRED_LOADS",
    "SYMOPT_LOAD_LINES",
    "SYMOPT_FAIL_CRITICAL_ERRORS",
    "SYMOPT_AUTO_PUBLICS",
    "SYMOPT_DEBUG",
    "SYMFLAG_EXPORT",
    "MAX_SYM_NAME",
    "SymInitializeW",
    "SymCleanup",
    "SymSetOptions",
    "SymGetOptions",
    "SymLoadModuleExW",
    "SymUnloadModule64",
    "SymFromAddrW",
]
