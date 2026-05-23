"""dbghelp-backed address-to-symbol resolver (Phase N3).

Replaces the ``xperf -a symcache -build`` step that Phase N1/N2 inherited
from the xperf pipeline. The flow is:

1. The native consumer extracts ``Image/Load`` / ``Image/DCStart`` events
   (`mof.imageload`) along with the raw return addresses on every
   ``SampledProfile`` stack (`mof.stackwalk`).
2. ``Symbolizer.add_module`` is fed each ImageLoad row — that calls
   ``SymLoadModuleExW`` so dbghelp knows the module's runtime base and
   can pull the matching PDB from symsrv on demand.
3. ``Symbolizer.resolve(addr)`` / ``bulk_resolve(addrs)`` translates raw
   return addresses into ``"module!function+0x123"`` strings. The
   per-address cache means re-walking the same hot path costs nothing
   after the first hit.

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
        from .bindings.types import SYMBOL_INFOW

        self._dbghelp = dbghelp
        self._SYMBOL_INFOW = SYMBOL_INFOW
        self._symbol_path = resolve_symbol_path(symbol_path)
        self._handle = _next_synthetic_handle()
        self._initialized = False
        self._closed = False

        # Module bookkeeping. ``_modules`` keeps the dict the consumer
        # registered so we can re-probe a deferred-load PDB without
        # re-parsing the ImageLoad event.
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

    def _resolve_one(self, address: int) -> Optional[str]:
        """Single ``SymFromAddrW`` call. Returns ``None`` on miss.

        Caller already holds ``self._lock``.
        """

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

        return f"{module_label}!{name_str}+0x{displacement.value:x}"

    # -- public API ----------------------------------------------------
    def add_module(
        self,
        image_base: int,
        image_size: int,
        file_path: str,
    ) -> None:
        """Register a loaded module from an ImageLoad event.

        Idempotent: re-registering the same base updates the recorded
        size / path but does not re-call ``SymLoadModuleExW`` (which
        would simply return the same loaded address). ImageLoad events
        emitted during a kernel rundown can show the same module at the
        same base multiple times — we tolerate that without rework.
        """

        if not image_base:
            return
        # File names from ETW often have NT-form prefixes
        # (``\SystemRoot\…`` / ``\Device\HarddiskVolume3\…``). dbghelp's
        # SymLoadModuleExW needs a path it can stat or at least extract a
        # name from; both forms produce a usable basename via
        # ``Path(..).name``, so we don't need to rewrite paths upfront.
        path_for_dbghelp = _normalize_image_path(file_path)

        with self._lock:
            self._ensure_init()

            existing = self._modules.get(image_base)
            self._modules[image_base] = {
                "ImageBase": image_base,
                "ImageSize": image_size,
                "FileName": file_path,
                "DbgHelpPath": path_for_dbghelp,
            }
            self._rebuild_index()

            if existing is not None:
                return

            d = self._dbghelp
            loaded = d.SymLoadModuleExW(
                self._handle,
                None,                 # hFile — we never have one
                path_for_dbghelp,     # ImageName
                None,                 # ModuleName — derived from ImageName
                ctypes.c_ulonglong(image_base),
                wintypes.DWORD(image_size & 0xFFFFFFFF),
                None,                 # PMODLOAD_DATA
                wintypes.DWORD(0),    # Flags
            )
            if not loaded:
                err = ctypes.get_last_error()
                # 0 with GetLastError==0 means "already loaded" per docs;
                # any other error is logged but not fatal — we'd rather
                # have an unresolved address than a load_trace failure.
                if err != 0:
                    logger.debug(
                        "SymLoadModuleExW failed for %s @ 0x%x: err=%d",
                        path_for_dbghelp, image_base, err,
                    )

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

            # Fast path: ask dbghelp directly.
            result = self._resolve_one(address)

            # Deferred-load case (§6.3): dbghelp's SYMOPT_DEFERRED_LOADS
            # means the first lookup against a module triggers symsrv;
            # if SymFromAddrW returned a miss but the address is inside
            # a registered module range, force a probe and retry.
            if result is None:
                module = self._find_module_for_address(address)
                if module is not None:
                    base = module["ImageBase"]
                    # Re-register to make sure dbghelp has it. This is a
                    # no-op if already loaded; if the first add_module
                    # silently failed (e.g. NT-form path) we get a
                    # second chance with whatever path normalization we
                    # could derive.
                    d = self._dbghelp
                    d.SymLoadModuleExW(
                        self._handle, None,
                        module.get("DbgHelpPath") or module.get("FileName"),
                        None,
                        ctypes.c_ulonglong(base),
                        wintypes.DWORD(module.get("ImageSize", 0) & 0xFFFFFFFF),
                        None, wintypes.DWORD(0),
                    )
                    # Probe near the image base to wake symsrv, then
                    # retry the original address.
                    _ = self._resolve_one(base + 0x1000)
                    result = self._resolve_one(address)

            if result is None:
                module = self._find_module_for_address(address)
                if module is not None:
                    label = _module_label(module)
                    rva = address - module["ImageBase"]
                    result = f"{label}+0x{rva:x}"
                else:
                    result = f"unknown+0x{address:x}"

            self._cache[address] = result
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
