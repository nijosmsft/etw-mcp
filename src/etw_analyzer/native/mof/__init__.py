"""Hand-coded MOF struct decoders for the ~15 kernel-logger GUIDs.

The Windows kernel logger emits its high-volume events (SampledProfile,
CSwitch, DPC, ISR, StackWalk, ImageLoad, Process, Thread, DiskIo, FileIo,
EventTrace metadata, SystemConfig rundowns) via legacy MOF schemas that
``TdhGetEventInformation`` cannot read — the feasibility report's central
finding (see ``udp-perf/docs/wpr-mcp-native-etw-feasibility.md`` §exp2 and
§exp3). Every byte of these payloads has to be peeled apart by hand.

This package is organised one module per provider, mirroring the table in
``udp-perf/docs/wpr-mcp-native-etw-design.md`` §4.1. Each provider module
exports:

* ``PROVIDER_GUID`` — lowercase string form.
* ``HANDLERS`` — ``dict[(opcode, version_or_None) -> (canonical_class, fn)]``.
  Version ``None`` is the wildcard fallback. Decoders take
  ``(payload_bytes, header_dict) -> dict | None``.

The :func:`register_kernel_handlers` helper merges every module's
``HANDLERS`` into a flat dispatch table keyed on ``(provider_guid_lower,
opcode, version_or_None)``. ``extract.py`` calls this once at startup.

SystemConfig is the one exception: per design §4.4 (and feasibility
``exp10b``) TDH *does* decode its events. We still register a passthrough
decoder here so the dispatch table covers every kernel-logger GUID we know
about — the TDH layer (Phase N1+) can override on a per-event basis.
"""

from __future__ import annotations

from typing import Optional

from . import diskio, eventtrace, fileio, imageload, perfinfo, process
from . import stackwalk, sysconfig, thread


# Type aliases for the dispatch table. Decoders take a payload-bytes blob
# and a header dict (the result of pulling ``EVENT_HEADER`` /
# ``BufferContext`` fields into a Python dict) and return either a row
# dict in the canonical-class schema or ``None`` to drop the row.
HandlerKey = tuple[str, int, Optional[int]]
HandlerFn = callable
HandlerEntry = tuple[str, HandlerFn]


# Modules registered, in priority order. The order matters only for
# debugging — every (provider_guid, opcode, version) key is unique.
_MODULES = (
    perfinfo,
    stackwalk,
    thread,
    process,
    imageload,
    diskio,
    fileio,
    eventtrace,
    sysconfig,
)


def register_kernel_handlers(
    dispatch_table: dict[HandlerKey, HandlerEntry],
) -> dict[HandlerKey, HandlerEntry]:
    """Populate ``dispatch_table`` with every kernel-MOF handler.

    Each module exposes a ``HANDLERS`` dict keyed on
    ``(opcode, version_or_None)``. We rewrite the keys to include the
    provider GUID so the consumer can look up
    ``(provider_guid, opcode, version)`` in O(1).

    Returns the dispatch table for chaining (``return register_kernel_handlers({})``).
    Existing entries in ``dispatch_table`` are *not* overwritten — caller
    can pre-register custom decoders if it wants.
    """
    for module in _MODULES:
        guid = module.PROVIDER_GUID.lower()
        for (opcode, version), entry in module.HANDLERS.items():
            key: HandlerKey = (guid, int(opcode), version)
            dispatch_table.setdefault(key, entry)
    return dispatch_table


def kernel_provider_guids() -> set[str]:
    """Return the set of provider GUIDs (lowercase) this package decodes.

    Used by the consumer to seed the TDH negative cache (per design §5.2):
    every GUID in this set is short-circuited to the MOF path before the
    TDH library is even consulted.
    """
    return {m.PROVIDER_GUID.lower() for m in _MODULES}


__all__ = [
    "register_kernel_handlers",
    "kernel_provider_guids",
    "HandlerKey",
    "HandlerFn",
    "HandlerEntry",
]
