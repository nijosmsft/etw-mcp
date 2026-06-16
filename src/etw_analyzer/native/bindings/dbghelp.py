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
import glob
import os
import re
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


# Identity of the dbghelp/symsrv pair selected at import time. Diagnostics use
# this to explain MSFZ PDB failures instead of leaving users to guess which
# Windows debugger toolchain was loaded.
LOADED_DBGHELP_PATH: str | None = None
LOADED_DBGHELP_VERSION: str | None = None
LOADED_SYMSRV_PATH: str | None = None


class _VS_FIXEDFILEINFO(ctypes.Structure):
    _fields_ = [
        ("dwSignature", wintypes.DWORD),
        ("dwStrucVersion", wintypes.DWORD),
        ("dwFileVersionMS", wintypes.DWORD),
        ("dwFileVersionLS", wintypes.DWORD),
        ("dwProductVersionMS", wintypes.DWORD),
        ("dwProductVersionLS", wintypes.DWORD),
        ("dwFileFlagsMask", wintypes.DWORD),
        ("dwFileFlags", wintypes.DWORD),
        ("dwFileOS", wintypes.DWORD),
        ("dwFileType", wintypes.DWORD),
        ("dwFileSubtype", wintypes.DWORD),
        ("dwFileDateMS", wintypes.DWORD),
        ("dwFileDateLS", wintypes.DWORD),
    ]


def _read_file_version(path: str | None) -> str | None:
    """Return a DLL FileVersion like ``10.0.29507.1001`` when available."""
    if not path:
        return None
    try:
        version = ctypes.WinDLL("version.dll", use_last_error=True)
        get_size = version.GetFileVersionInfoSizeW
        get_size.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
        get_size.restype = wintypes.DWORD
        get_info = version.GetFileVersionInfoW
        get_info.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
        ]
        get_info.restype = wintypes.BOOL
        query = version.VerQueryValueW
        query.argtypes = [
            ctypes.c_void_p,
            wintypes.LPCWSTR,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(wintypes.UINT),
        ]
        query.restype = wintypes.BOOL

        handle = wintypes.DWORD()
        size = get_size(path, ctypes.byref(handle))
        if not size:
            return None
        buf = ctypes.create_string_buffer(size)
        if not get_info(path, 0, size, buf):
            return None
        value_ptr = ctypes.c_void_p()
        value_len = wintypes.UINT()
        if not query(buf, "\\", ctypes.byref(value_ptr), ctypes.byref(value_len)):
            return None
        fixed = ctypes.cast(
            value_ptr, ctypes.POINTER(_VS_FIXEDFILEINFO)
        ).contents
        if fixed.dwSignature != 0xFEEF04BD:
            return None
        major = fixed.dwFileVersionMS >> 16
        minor = fixed.dwFileVersionMS & 0xFFFF
        build = fixed.dwFileVersionLS >> 16
        revision = fixed.dwFileVersionLS & 0xFFFF
        return f"{major}.{minor}.{build}.{revision}"
    except Exception:
        return None


def _module_path_from_handle(handle: int | None) -> str | None:
    """Resolve a loaded module handle to its full path, best-effort."""
    if not handle:
        return None
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        get_module_file_name = kernel32.GetModuleFileNameW
        get_module_file_name.argtypes = [
            wintypes.HMODULE,
            wintypes.LPWSTR,
            wintypes.DWORD,
        ]
        get_module_file_name.restype = wintypes.DWORD
        buf = ctypes.create_unicode_buffer(32768)
        n = get_module_file_name(wintypes.HMODULE(handle), buf, len(buf))
        if n:
            return buf.value
    except Exception:
        pass
    return None


def _fallback_system_dbghelp_path() -> str:
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    return os.path.join(system_root, "System32", "dbghelp.dll")


def _version_sort_key(path: str) -> tuple:
    """Best-effort numeric sort key for WinDbg package/version directories."""
    parts: list[tuple[int, int | str]] = []
    for token in re.findall(r"\d+|[A-Za-z]+", path):
        if token.isdigit():
            parts.append((1, int(token)))
        else:
            parts.append((0, token.lower()))
    return tuple(parts)


def _candidate_dbghelp_paths() -> list[tuple[str, str | None]]:
    """Return dbghelp candidates in priority order."""
    candidates: list[tuple[str, str | None]] = []

    env_dbghelp = os.environ.get("ETW_MCP_DBGHELP")
    if env_dbghelp:
        env_symsrv = os.environ.get("ETW_MCP_SYMSRV")
        if not env_symsrv:
            env_symsrv = os.path.join(os.path.dirname(env_dbghelp), "symsrv.dll")
        candidates.append((env_dbghelp, env_symsrv))

    candidates.append((r"C:\Debuggers\dbghelp.dll", r"C:\Debuggers\symsrv.dll"))

    local_appdata = os.environ.get("LOCALAPPDATA")
    if local_appdata:
        local_windbg_hits = sorted(
            glob.glob(
                os.path.join(
                    local_appdata,
                    "Microsoft",
                    "WinDbg",
                    "*",
                    "amd64",
                    "dbghelp.dll",
                )
            ),
            key=_version_sort_key,
            reverse=True,
        )
        for path in local_windbg_hits:
            candidates.append((path, os.path.join(os.path.dirname(path), "symsrv.dll")))

    uwp_hits = sorted(
        glob.glob(r"C:\Program Files\WindowsApps\Microsoft.WinDbg_*\x64\dbghelp.dll"),
        key=_version_sort_key,
        reverse=True,
    )
    for path in uwp_hits:
        candidates.append((path, os.path.join(os.path.dirname(path), "symsrv.dll")))

    candidates.extend([
        (r"C:\Program Files\Windows Kits\10\Debuggers\x64\dbghelp.dll",
         r"C:\Program Files\Windows Kits\10\Debuggers\x64\symsrv.dll"),
        (r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\dbghelp.dll",
         r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symsrv.dll"),
        ("dbghelp.dll", None),
    ])

    seen: set[str] = set()
    out: list[tuple[str, str | None]] = []
    for dbghelp_path, symsrv_path in candidates:
        key = dbghelp_path.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append((dbghelp_path, symsrv_path))
    return out


def dbghelp_version_supports_msfz(version: str | None) -> bool | None:
    """Heuristic: dbghelp 10.0 build >= 27000 is treated as MSFZ-capable.

    Microsoft has not published the exact first supporting build. Known-bad
    system builds are 10.0.26100.x; known-good WinDbg builds are 10.0.29507.x.
    """
    if not version:
        return None
    parts = version.split(".")
    if len(parts) < 3:
        return None
    try:
        major = int(parts[0])
        build = int(parts[2])
    except ValueError:
        return None
    if major != 10:
        return None
    return build >= 27000


def dbghelp_supports_msfz() -> bool | None:
    """Return whether the loaded dbghelp is expected to read MSFZ PDBs."""
    return dbghelp_version_supports_msfz(LOADED_DBGHELP_VERSION)


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
    global LOADED_DBGHELP_PATH, LOADED_DBGHELP_VERSION, LOADED_SYMSRV_PATH

    for dbghelp_path, symsrv_path in _candidate_dbghelp_paths():
        if dbghelp_path != "dbghelp.dll" and not os.path.exists(dbghelp_path):
            continue
        # Load symsrv from the same directory first so dbghelp picks it up.
        loaded_symsrv_path = None
        if symsrv_path and os.path.exists(symsrv_path):
            try:
                ctypes.WinDLL(symsrv_path, use_last_error=True)
                loaded_symsrv_path = symsrv_path
            except OSError:
                pass
        try:
            dll = ctypes.WinDLL(dbghelp_path, use_last_error=True)
            loaded_path = _module_path_from_handle(getattr(dll, "_handle", None))
            if not loaded_path:
                loaded_path = (
                    os.path.abspath(dbghelp_path)
                    if dbghelp_path != "dbghelp.dll"
                    else _fallback_system_dbghelp_path()
                )
            LOADED_DBGHELP_PATH = loaded_path
            LOADED_DBGHELP_VERSION = _read_file_version(loaded_path)
            LOADED_SYMSRV_PATH = loaded_symsrv_path
            return dll
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
    "LOADED_DBGHELP_PATH",
    "LOADED_DBGHELP_VERSION",
    "LOADED_SYMSRV_PATH",
    "dbghelp_version_supports_msfz",
    "dbghelp_supports_msfz",
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
