"""dbghelp-backed address-to-symbol resolver (Phase N3).

Replaces the ``xperf -a symcache -build`` step that Phase N1/N2 inherited
from the xperf pipeline. The flow is:

1. The native consumer extracts ``Image/Load`` / ``Image/DCStart`` events
   (`mof.imageload`) along with the raw return addresses on every
   ``SampledProfile`` stack (`mof.stackwalk`).
2. ``Symbolizer.add_module`` is fed each ImageLoad row. It records the
   module range and PDB identity from the trace without calling dbghelp's
   file/symbol-server APIs.
3. ``Symbolizer.resolve(addr)`` / ``bulk_resolve(addrs)`` lazily loads the
   PDB for the addressed module, then translates raw return addresses into
   ``"module!function+0x123"`` strings. The per-address cache means
   re-walking the same hot path costs nothing after the first hit.

Design references:
    * §6.1 Public API
    * §6.2 Synthetic handle model — every Symbolizer owns a unique
      ``HANDLE`` allocated from a monotonic counter so concurrent traces
      don't collide on dbghelp's per-handle module list.
    * §6.3 Deferred-load handling — feasibility experiment showed the
      first ``SymFromAddrW`` may miss because ``SymLoadModuleExW`` is
      lazy; force one re-probe and retry.
    * §6.5 Symbol path resolution — ctor arg → env var → public Microsoft
      symbol server. Matches the existing xperf-mode plumbing.

The module is Windows-only by virtue of its dbghelp dependency; on other
platforms ``is_available()`` returns ``False`` and the rest of the
codebase silently falls back to the existing xperf path.
"""

from __future__ import annotations

import ctypes
import itertools
import logging
import os
import threading
from ctypes import wintypes
from pathlib import Path
from typing import Iterable, Optional


logger = logging.getLogger(__name__)


_DEFAULT_SYMBOL_PATH = (
    r"srv*C:\symbols*https://msdl.microsoft.com/download/symbols"
)


# Synthetic-handle counter. dbghelp keys per-process state on whatever
# HANDLE the caller passed to ``SymInitializeW``; we hand out a unique one
# per Symbolizer so two concurrently-loaded traces never share a module
# table. Starting at 0x10000 keeps us well clear of any real OS pseudo
# handle (``GetCurrentProcess()`` returns -1 / 0xFFFFFFFFFFFFFFFF).
_handle_counter = itertools.count(0x10000)
_handle_lock = threading.Lock()


def _next_synthetic_handle() -> wintypes.HANDLE:
    """Return a fresh synthetic HANDLE value for ``SymInitializeW``."""

    with _handle_lock:
        value = next(_handle_counter)
    return wintypes.HANDLE(value)


def resolve_symbol_path(symbol_path: Optional[str]) -> str:
    """Pick the symbol path per design §6.5.

    Order: ctor arg → ``_NT_SYMBOL_PATH`` env var → public default.
    """

    if symbol_path:
        return symbol_path
    env = os.environ.get("_NT_SYMBOL_PATH")
    if env:
        return env
    return _DEFAULT_SYMBOL_PATH


def is_available() -> bool:
    """Return ``True`` when ``dbghelp.dll`` can be loaded on this host."""

    try:
        from .bindings import dbghelp  # noqa: F401 — side-effect import
    except (ImportError, OSError):
        return False
    return True


def _guids_equal(a: Optional[str], b: Optional[str]) -> bool:
    """Compare two GUID strings ignoring dashes, braces, and case.

    Accepts both the dashed UUID form (``D195DCC3-DF4C-...``) the trace
    rundown carries and the canonical ``GUID.__str__`` form. Returns
    ``False`` when either side is empty.
    """

    if not a or not b:
        return False
    na = a.replace("-", "").replace("{", "").replace("}", "").lower()
    nb = b.replace("-", "").replace("{", "").replace("}", "").lower()
    return na == nb


class SymbolizerError(RuntimeError):
    """Raised when dbghelp initialization fails."""


class Symbolizer:
    """Resolve raw ETW return addresses to ``module!function+offset`` strings.

    The class is intended to be used as a context manager, but
    ``close()`` is idempotent so direct ``__init__``/``close`` is fine
    too. Multiple instances can coexist — each owns a unique synthetic
    HANDLE and an isolated module table.

    Parameters
    ----------
    symbol_path:
        Override for the ``_NT_SYMBOL_PATH`` env var. If both are unset
        the public Microsoft symbol server is used.
    """

    def __init__(self, symbol_path: Optional[str] = None) -> None:
        from .bindings import dbghelp  # local import so non-Windows fails late
        from .bindings.types import SYMBOL_INFOW, IMAGEHLP_MODULEW64

        self._dbghelp = dbghelp
        self._SYMBOL_INFOW = SYMBOL_INFOW
        self._IMAGEHLP_MODULEW64 = IMAGEHLP_MODULEW64
        self._symbol_path = resolve_symbol_path(symbol_path)
        self._handle = _next_synthetic_handle()
        self._initialized = False
        self._closed = False

        # Module bookkeeping. ``_modules`` keeps the dict the consumer
        # registered so a later resolve can lazily locate/load the PDB
        # without re-parsing the ImageLoad event.
        self._modules: dict[int, dict] = {}
        # Sorted (base, size) tuples for O(log N) range lookup. Refreshed
        # whenever ``_modules`` mutates. Pairs with ``_module_bases`` for
        # the bisect dance in ``_find_module_for_address``.
        self._module_bases: list[int] = []
        self._module_ranges: list[tuple[int, int]] = []  # parallel (base, size)

        # Per-address resolved-string cache. Sized loosely — typical
        # traces have ~10–50K distinct return addresses across stacks,
        # and a string entry is well under 100B, so we don't bother
        # bounding the cache.
        self._cache: dict[int, str] = {}

        # Parallel per-address symbol-source cache: "pdb" | "export" |
        # "mismatched" | "unknown". Populated alongside ``_cache`` by
        # ``_resolve_one``. "pdb" means SymFromAddrW returned a result
        # without ``SYMFLAG_EXPORT`` set AND the loaded PDB's GUID+Age
        # matches the trace's captured RSDS identity -- i.e. dbghelp
        # matched the CORRECT PDB. "mismatched" means a PDB symbol was
        # returned but from a different-build PDB (GUID/Age disagree with
        # the trace identity); the name is from the wrong build and must
        # not be trusted (#3). "export" means SymFromAddrW returned a name
        # from the PE export table (nearest-neighbour heuristic, no PDB
        # hit). "unknown" covers misses where we fell back to
        # ``module+0xRVA`` or ``unknown+0xADDR``. Lets check_symbols and
        # the hot-function tools report resolution honesty (item 63).
        self._source_cache: dict[int, str] = {}

        # Lock guards _modules + _cache for thread-safe symbol calls.
        # dbghelp itself is *not* thread-safe across all APIs — see
        # https://learn.microsoft.com/en-us/windows/win32/debug/calling-the-dbghelp-library
        # so we serialize every ``SymLoadModuleExW`` / ``SymFromAddrW``.
        self._lock = threading.Lock()

    # -- context manager ------------------------------------------------
    def __enter__(self) -> "Symbolizer":
        self._ensure_init()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # -- internal helpers ----------------------------------------------
    def _ensure_init(self) -> None:
        """Lazily call ``SymInitializeW`` + ``SymSetOptions``.

        Splitting out from ``__init__`` keeps the constructor fast (no
        side effects) and gives tests a clean place to monkeypatch.
        """

        if self._initialized:
            return
        if self._closed:
            raise SymbolizerError("Symbolizer is closed")

        d = self._dbghelp
        # Per §6.3, the options we want: undecorate C++, defer the actual
        # PDB load until first lookup, no error dialogs, capture line
        # numbers, search publics on demand.
        d.SymSetOptions(
            d.SYMOPT_UNDNAME
            | d.SYMOPT_DEFERRED_LOADS
            | d.SYMOPT_LOAD_LINES
            | d.SYMOPT_FAIL_CRITICAL_ERRORS
            | d.SYMOPT_AUTO_PUBLICS
        )
        ok = d.SymInitializeW(self._handle, self._symbol_path, False)
        if not ok:
            err = ctypes.get_last_error()
            raise SymbolizerError(
                f"SymInitializeW failed: GetLastError={err}, "
                f"symbol_path={self._symbol_path!r}"
            )
        self._initialized = True

    def _rebuild_index(self) -> None:
        """Refresh the sorted module-range index after a mutation."""

        if not self._modules:
            self._module_bases = []
            self._module_ranges = []
            return
        sorted_bases = sorted(self._modules.keys())
        self._module_bases = sorted_bases
        self._module_ranges = [
            (base, self._modules[base].get("ImageSize", 0))
            for base in sorted_bases
        ]

    def _find_module_for_address(self, address: int) -> Optional[dict]:
        """Return the module entry whose [base, base+size) contains ``address``.

        Uses bisect over the sorted base array — O(log N) per lookup.
        Returns ``None`` if no module covers the address.
        """

        bases = self._module_bases
        if not bases:
            return None
        # bisect_right places the candidate after any equal entries, so
        # the module of interest is at index-1.
        import bisect
        idx = bisect.bisect_right(bases, address) - 1
        if idx < 0:
            return None
        base, size = self._module_ranges[idx]
        if size and address >= base + size:
            return None
        return self._modules.get(base)

    def _resolve_one(self, address: int) -> Optional[tuple[str, str]]:
        """Single ``SymFromAddrW`` call. Returns ``(label, source)`` on success
        or ``None`` on miss.

        ``source`` is ``"pdb"`` when the resolved name came from a PDB and
        ``"export"`` when dbghelp fell back to the PE export table
        (``SYMFLAG_EXPORT`` bit set on ``SYMBOL_INFOW.Flags``). The export
        case is a nearest-neighbour heuristic — the name + offset that come
        back may not correspond to the actual function the address belongs
        to. Callers should treat ``"export"`` rows as low-confidence.

        Caller already holds ``self._lock``.
        """

        self._ensure_init()
        d = self._dbghelp
        # Over-allocate the SYMBOL_INFOW so its trailing Name array has
        # room for ``MAX_SYM_NAME`` WCHARs.
        buf_size = ctypes.sizeof(self._SYMBOL_INFOW) + d.MAX_SYM_NAME * ctypes.sizeof(wintypes.WCHAR)
        buf = ctypes.create_string_buffer(buf_size)
        sym = ctypes.cast(buf, ctypes.POINTER(self._SYMBOL_INFOW)).contents
        sym.SizeOfStruct = ctypes.sizeof(self._SYMBOL_INFOW)
        sym.MaxNameLen = d.MAX_SYM_NAME

        displacement = ctypes.c_ulonglong(0)
        ok = d.SymFromAddrW(self._handle, address, ctypes.byref(displacement), sym)
        if not ok:
            return None

        # Decode the variable-length Name field. It lives at the address
        # of the ``Name`` field within the over-allocated buffer.
        name_addr = ctypes.addressof(buf) + self._SYMBOL_INFOW.Name.offset
        name_str = ctypes.wstring_at(name_addr, sym.NameLen)
        if not name_str:
            return None

        # ``ModBase`` lets us find the module — display the file stem,
        # not the full path, to match xperf's ``module!function`` shape.
        # Fall back to a range lookup against the looked-up address in
        # case dbghelp normalizes the base differently from what we
        # registered (the SDK doesn't guarantee identity).
        mod_base = int(sym.ModBase)
        module_entry = self._modules.get(mod_base)
        if module_entry is None:
            module_entry = self._find_module_for_address(address)
        module_label = _module_label(module_entry) if module_entry else "unknown"

        label = f"{module_label}!{name_str}+0x{displacement.value:x}"
        if int(sym.Flags) & d.SYMFLAG_EXPORT:
            source = "export"
        elif module_entry is not None and not self._module_pdb_matches(module_entry):
            # dbghelp resolved a PDB symbol, but the loaded PDB's GUID+Age
            # does NOT match the identity the trace captured for this module
            # (e.g. a different-build local image was loaded non-strictly).
            # The function name is from the WRONG build and must not be
            # counted as a trustworthy "From PDB" hit (#3).
            source = "mismatched"
        else:
            source = "pdb"
        return (label, source)

    def _loaded_module_identity(
        self, image_base: int
    ) -> Optional[tuple[int, Optional[str], int]]:
        """Return ``(sym_type, loaded_guid_str_or_None, loaded_age)`` for the
        PDB dbghelp currently has loaded at ``image_base``.

        Returns ``None`` when ``SymGetModuleInfoW64`` reports no module. The
        GUID is the canonical dashed string form (or ``None`` when the SDK
        reports an all-zero signature). Caller holds ``self._lock``.
        """

        d = self._dbghelp
        mi = self._IMAGEHLP_MODULEW64()
        mi.SizeOfStruct = ctypes.sizeof(self._IMAGEHLP_MODULEW64)
        try:
            ok = d.SymGetModuleInfoW64(
                self._handle, ctypes.c_ulonglong(image_base), ctypes.byref(mi)
            )
        except OSError:
            return None
        if not ok:
            return None
        guid_str = str(mi.PdbSig70)
        if guid_str.replace("-", "").strip("0") == "":
            guid_str = None
        return (int(mi.SymType), guid_str, int(mi.PdbAge))

    def _module_pdb_matches(self, module: dict) -> bool:
        """Whether the PDB dbghelp loaded for ``module`` matches the trace's
        captured RSDS identity (GUID+Age).

        Returns ``True`` when we cannot prove a mismatch -- i.e. the trace
        carried no identity, dbghelp loaded the file via the exact-GUID RSDS
        path, or ``SymGetModuleInfoW64`` is unavailable. Only an explicit
        GUID/Age disagreement between the loaded PDB and the trace identity
        yields ``False``. The verdict is memoized on the module entry so the
        ``SymGetModuleInfoW64`` round-trip happens at most once per module.
        Caller holds ``self._lock``.
        """

        cached = module.get("pdb_match")
        if cached is not None:
            return bool(cached)

        # Exact-GUID RSDS load already proved the identity matches.
        if module.get("identity_source") == "rsds":
            module["pdb_match"] = True
            return True

        trace_guid = module.get("PdbGuid")
        if not trace_guid:
            # No captured identity to compare against -- never downgrade.
            module["pdb_match"] = True
            return True

        info = self._loaded_module_identity(int(module["ImageBase"]))
        if info is None:
            module["pdb_match"] = True
            return True
        sym_type, loaded_guid, loaded_age = info
        if sym_type != self._dbghelp.SymPdb or not loaded_guid:
            # Not a real PDB load (export/deferred/none) -- the export-flag
            # check already governs those rows; don't flag as mismatched.
            module["pdb_match"] = True
            return True

        guid_ok = _guids_equal(str(trace_guid), loaded_guid)
        trace_age = module.get("PdbAge")
        age_ok = trace_age is None or int(trace_age) == int(loaded_age)
        match = bool(guid_ok and age_ok)
        module["pdb_match"] = match
        if not match:
            module["loaded_pdb_guid"] = loaded_guid
            module["loaded_pdb_age"] = int(loaded_age)
        return match

    # -- public API ----------------------------------------------------

    def _ensure_pdb_loaded(self, image_base: int) -> None:
        """Lazily bind a registered module to dbghelp.

        ``add_module`` is intentionally metadata-only so loading a large
        trace cannot block on one remote PDB lookup per image. The first
        symbol query for an address in a module calls this method while
        holding ``self._lock``. It performs the same exact-GUID RSDS lookup
        that the eager M3 path used, then falls back to the legacy local-image
        load when identity is absent or lookup misses. A module is attempted
        at most once per Symbolizer instance.
        """

        module = self._modules.get(image_base)
        if module is None or module.get("pdb_load_attempted"):
            return

        module["pdb_load_attempted"] = True
        self._ensure_init()
        d = self._dbghelp

        pdb_guid = module.get("PdbGuid")
        pdb_age = module.get("PdbAge")
        pdb_name = module.get("PdbName")
        image_size = int(module.get("ImageSize", 0) or 0)
        path_for_dbghelp = module.get("DbgHelpPath") or module.get("FileName")

        if pdb_guid and pdb_name and self._symbol_path:
            try:
                from .bindings.types import guid_from_string

                guid = guid_from_string(str(pdb_guid))
                found_buf = ctypes.create_unicode_buffer(1024)
                ok = d.SymFindFileInPathW(
                    self._handle,
                    None,           # use search path from SymInitializeW
                    str(pdb_name),
                    ctypes.cast(ctypes.pointer(guid), ctypes.c_void_p),
                    wintypes.DWORD(int(pdb_age or 0)),
                    wintypes.DWORD(0),
                    wintypes.DWORD(d.SSRVOPT_GUIDPTR),
                    found_buf,
                    None,
                    None,
                )
                if ok and found_buf.value:
                    found_pdb_path = found_buf.value
                    logger.debug(
                        "SymFindFileInPathW found %s -> %s",
                        pdb_name, found_pdb_path,
                    )
                    loaded = d.SymLoadModuleExW(
                        self._handle,
                        None,
                        found_pdb_path,
                        None,
                        ctypes.c_ulonglong(image_base),
                        wintypes.DWORD(image_size & 0xFFFFFFFF),
                        None,
                        wintypes.DWORD(0),
                    )
                    if loaded:
                        module["DbgHelpPath"] = found_pdb_path
                        module["identity_source"] = "rsds"
                        module["pdb_loaded"] = True
                    else:
                        err = ctypes.get_last_error()
                        if err != 0:
                            logger.debug(
                                "SymLoadModuleExW(rsds) failed for %s @ 0x%x: err=%d",
                                found_pdb_path, image_base, err,
                            )

                    mi = self._IMAGEHLP_MODULEW64()
                    mi.SizeOfStruct = ctypes.sizeof(self._IMAGEHLP_MODULEW64)
                    if d.SymGetModuleInfoW64(
                        self._handle,
                        ctypes.c_ulonglong(image_base),
                        ctypes.byref(mi),
                    ):
                        if mi.SymType == d.SymExport:
                            logger.warning(
                                "RSDS load did not yield PDB symbols for %s "
                                "@ 0x%x (SymType=SymExport after rsds load); "
                                "GUID=%s age=%s",
                                pdb_name, image_base, pdb_guid, pdb_age,
                            )
                    return

                err = ctypes.get_last_error()
                logger.debug(
                    "SymFindFileInPathW miss for %s GUID=%s age=%s err=%d; "
                    "falling back to local image",
                    pdb_name, pdb_guid, pdb_age, err,
                )
            except Exception as exc:
                logger.debug(
                    "RSDS identity load error for GUID=%s pdb=%s: %s; "
                    "falling back to local image",
                    pdb_guid, pdb_name, exc,
                )

        loaded = d.SymLoadModuleExW(
            self._handle,
            None,
            path_for_dbghelp,
            None,
            ctypes.c_ulonglong(image_base),
            wintypes.DWORD(image_size & 0xFFFFFFFF),
            None,
            wintypes.DWORD(0),
        )
        if loaded:
            module["identity_source"] = "image"
            module["pdb_loaded"] = True
        else:
            err = ctypes.get_last_error()
            if err != 0:
                logger.debug(
                    "SymLoadModuleExW failed for %s @ 0x%x: err=%d",
                    path_for_dbghelp, image_base, err,
                )

    def add_module(
        self,
        image_base: int,
        image_size: int,
        file_path: str,
        *,
        pdb_guid: Optional[str] = None,
        pdb_age: Optional[int] = None,
        pdb_name: Optional[str] = None,
        time_date_stamp: Optional[int] = None,
    ) -> None:
        """Register a loaded module from an ImageLoad event.

        The method records the module range and any RSDS PDB identity from
        the trace but does not call ``SymFindFileInPathW`` or
        ``SymLoadModuleExW``. Exact-GUID lookup and legacy local-image
        fallback happen lazily in ``_ensure_pdb_loaded`` on first resolve
        for an address inside this module.

        Idempotent: re-registering the same base updates the recorded size,
        path, and any newly discovered identity, but preserves the lazy-load
        attempt/result flags.
        """

        if not image_base:
            return
        path_for_dbghelp = _normalize_image_path(file_path)

        with self._lock:
            existing = self._modules.get(image_base)
            entry = {
                "ImageBase": image_base,
                "ImageSize": image_size,
                "FileName": file_path,
                "DbgHelpPath": path_for_dbghelp,
                "PdbGuid": str(pdb_guid) if pdb_guid else None,
                "PdbAge": pdb_age,
                "PdbName": str(pdb_name) if pdb_name else None,
                "TimeDateStamp": time_date_stamp,
                "identity_source": "deferred",
                "pdb_load_attempted": False,
                "pdb_loaded": False,
            }
            if existing is not None:
                entry["DbgHelpPath"] = existing.get("DbgHelpPath", path_for_dbghelp)
                entry["identity_source"] = existing.get("identity_source", "deferred")
                entry["pdb_load_attempted"] = existing.get("pdb_load_attempted", False)
                entry["pdb_loaded"] = existing.get("pdb_loaded", False)
                for key in ("PdbGuid", "PdbAge", "PdbName", "TimeDateStamp"):
                    if entry.get(key) is None:
                        entry[key] = existing.get(key)

            self._modules[image_base] = entry
            self._rebuild_index()

    def resolve(self, address: int) -> str:
        """Resolve a single address.

        Returns a ``"module!function+0x<offset>"`` string on success or
        a fallback ``"unknown+0x<address>"`` form on miss. Never raises.
        """

        if address == 0:
            return "unknown+0x0"

        cached = self._cache.get(address)
        if cached is not None:
            return cached

        with self._lock:
            cached = self._cache.get(address)
            if cached is not None:
                return cached

            result, source = self._resolve_one_with_source(address)

            self._cache[address] = result
            self._source_cache[address] = source
            return result

    def _resolve_one_with_source(self, address: int) -> tuple[str, str]:
        """Wrap ``_resolve_one`` with the deferred-load retry + module-RVA
        fallback. Returns ``(label, source)`` where ``source`` is one of
        ``"pdb"``, ``"export"``, or ``"unknown"``. Caller holds ``self._lock``.

        Split out from ``resolve()`` so both ``resolve()`` and
        ``get_source()``-style callers can populate the cache via the same
        code path.
        """

        module = self._find_module_for_address(address)
        if module is not None:
            self._ensure_pdb_loaded(int(module["ImageBase"]))

        # Fast path: ask dbghelp directly.
        result = self._resolve_one(address)

        # Deferred-load case (§6.3): dbghelp's SYMOPT_DEFERRED_LOADS
        # means the first lookup against a module triggers symsrv;
        # if SymFromAddrW returned a miss but the address is inside
        # a registered module range, force a probe and retry.
        if result is None:
            if module is not None:
                base = module["ImageBase"]
                # Probe near the image base to wake symsrv, then
                # retry the original address.
                _ = self._resolve_one(base + 0x1000)
                result = self._resolve_one(address)

        if result is None:
            module = self._find_module_for_address(address)
            if module is not None:
                label = _module_label(module)
                rva = address - module["ImageBase"]
                return (f"{label}+0x{rva:x}", "unknown")
            return (f"unknown+0x{address:x}", "unknown")

        return result

    def bulk_resolve(self, addresses: Iterable[int]) -> dict[int, str]:
        """Resolve a batch of addresses.

        Returns a dict mapping each input address to its resolved
        string. The internal cache means repeated bulk calls over the
        same hot path are cheap.
        """

        addrs = list(addresses)
        out: dict[int, str] = {}
        for addr in addrs:
            if addr in out:
                continue
            out[addr] = self.resolve(addr)
        return out

    def get_source(self, address: int) -> str:
        """Return the symbol source for ``address``: ``"pdb"`` | ``"export"``
        | ``"mismatched"`` | ``"unknown"``.

        Calls ``resolve()`` first if the address has not been seen, so the
        return is always one of the four documented strings. Used by item
        63 (honest ``check_symbols``) and the export-fallback annotators in
        ``get_hot_functions`` / ``get_hot_stacks``.
        """

        if address == 0:
            return "unknown"
        cached = self._source_cache.get(address)
        if cached is not None:
            return cached
        # Force a resolve to populate both caches; ignore the string.
        _ = self.resolve(address)
        return self._source_cache.get(address, "unknown")

    def bulk_resolve_with_source(
        self, addresses: Iterable[int]
    ) -> dict[int, tuple[str, str]]:
        """Resolve a batch and return ``addr -> (label, source)``.

        Companion to :meth:`bulk_resolve` for callers that need to surface
        whether each row came from a PDB or from the PE export-table
        fallback (item 63). Reuses the same underlying cache so mixing the
        two methods is free after the first hit.
        """

        addrs = list(addresses)
        out: dict[int, tuple[str, str]] = {}
        for addr in addrs:
            if addr in out:
                continue
            label = self.resolve(addr)
            source = self._source_cache.get(addr, "unknown")
            out[addr] = (label, source)
        return out

    def close(self) -> None:
        """Release dbghelp state. Safe to call more than once."""

        if self._closed:
            return
        self._closed = True
        if not self._initialized:
            return
        try:
            self._dbghelp.SymCleanup(self._handle)
        except OSError:
            # SymCleanup signals failure via return value; this except
            # is defensive against ctypes weirdness during interpreter
            # shutdown.
            pass
        finally:
            self._initialized = False

    # -- diagnostics ---------------------------------------------------
    def module_count(self) -> int:
        """Number of modules currently registered."""

        return len(self._modules)

    def cache_size(self) -> int:
        """Number of addresses currently in the resolved-symbol cache."""

        return len(self._cache)


# ---------------------------------------------------------------------------
# Helpers — outside the class so tests can exercise them without spinning
# up dbghelp.
# ---------------------------------------------------------------------------
def _module_label(module: dict) -> str:
    """Return the user-facing module name (basename, no extension stripped).

    ETW gives us paths like ``\\SystemRoot\\System32\\ntoskrnl.exe`` or
    ``C:\\Windows\\System32\\drivers\\tcpip.sys``; we match xperf's
    ``module!function`` convention which keeps the extension.
    """

    file_name = module.get("FileName") or ""
    # Same NUL/whitespace cleanup as _normalize_image_path so the
    # displayed module name is just the file basename.
    file_name = file_name.lstrip("\x00 \t")
    if not file_name:
        return "unknown"
    return Path(file_name).name


def _module_label_for_base(modules: dict[int, dict], base: int) -> str:
    """Look up a label by exact ModBase. Used when ``ModBase`` from
    ``SymFromAddrW`` doesn't match a key in ``self._modules`` (rare —
    dbghelp normalizes the base internally)."""

    if not modules:
        return "unknown"
    entry = modules.get(base)
    if entry is None:
        return "unknown"
    return _module_label(entry)


def _normalize_image_path(file_name: str) -> str:
    """Map ETW image paths to something ``SymLoadModuleExW`` can use.

    ETW emits NT-namespace paths:
        * ``\\SystemRoot\\System32\\…`` — rewrite to ``C:\\Windows\\…``
        * ``\\Device\\HarddiskVolume<N>\\Windows\\…`` — strip the volume
          prefix and rewrite to ``C:\\Windows\\…``

    dbghelp will fall back on the basename + ``_NT_SYMBOL_PATH`` even
    when the rewritten path doesn't exist locally, but giving it a
    plausible Windows-form path lets it stat the on-disk image and pull
    the matching PDB GUID/age from it before going to symsrv.
    """

    if not file_name:
        return file_name
    # Some kernel ImageLoad payloads have leading NUL pads from the MOF
    # decoder's variable-length tail. Strip them along with any other
    # whitespace before classifying the prefix.
    file_name = file_name.lstrip("\x00 \t")
    if not file_name:
        return file_name
    sysroot = os.environ.get("SystemRoot") or r"C:\Windows"
    lower = file_name.lower()
    # ``\SystemRoot\…`` → ``C:\Windows\…``
    if lower.startswith("\\systemroot\\"):
        return sysroot + file_name[len("\\SystemRoot"):]
    # ``\Device\HarddiskVolumeN\Windows\…`` → ``C:\Windows\…``. The
    # volume index is variable; locate the embedded ``\Windows\`` and
    # rewrite the prefix from there.
    if lower.startswith("\\device\\"):
        idx = lower.find("\\windows\\")
        if idx > 0:
            # Strip the trailing ``\\Windows`` from sysroot so the
            # resulting path doesn't double it.
            drive_part = sysroot
            if drive_part.lower().endswith("\\windows"):
                drive_part = drive_part[:-len("\\windows")]
            return drive_part + file_name[idx:]
    return file_name


__all__ = [
    "Symbolizer",
    "SymbolizerError",
    "is_available",
    "resolve_symbol_path",
]
