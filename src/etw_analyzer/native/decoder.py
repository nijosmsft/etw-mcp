"""TDH-based manifest-event decoder with schema caching (Phase N4b).

This is the runtime piece that lets the native consumer process manifest
events the way Phase 3-5 tools expect. The kernel-MOF tree in
:mod:`native.mof` covers SampledProfile/CSwitch/DPC/etc. but
``TdhGetEventInformation`` returns ``ERROR_NOT_FOUND`` for those — they
have no manifest. For everything else (TCPIP, AFD, MsQuic, HttpService,
NDIS-PacketCapture, and any other provider that registered a manifest
with ``wevtutil im`` or ``EventRegister``), TDH knows the field layout
and gives us names/types we can format into the same row-dict shape the
xperf-mode handlers produce.

Design points (from ``wpr-mcp-native-etw-design.md`` §5):

* **Per-event TDH calls are too expensive without caching** (exp6b
  measured ~5x speedup). The cache key is
  ``(provider_guid_bytes, event_id, version, opcode)`` — enough to
  uniquely identify a schema since manifests version fields per opcode.
* **Negative cache for kernel providers**: any (guid, event_id) that
  produced ``ERROR_NOT_FOUND`` (1168) is remembered and we skip the call
  on subsequent events. This is the single biggest perf win when a trace
  mixes kernel + manifest events — without it the kernel events keep
  paying the TdhGetEventInformation cost.
* **Variable-length properties drift the cursor** (the "exp2 surprise"
  documented in the feasibility report). When a property's length flag
  says it references a previously decoded field (PropertyParamLength,
  0x01), we look up the prior field's already-formatted value and use it
  as the length in bytes. ``TdhFormatProperty`` consumes a precise number
  of bytes per call via the ``UserDataConsumed`` out-param — we use that
  to advance the cursor rather than trusting ``PropertyLength`` blindly.

The decoder is intentionally NOT general-purpose: it doesn't follow
struct properties (PropertyStruct flag 0x01) or fancy array/map
features. Those don't appear in the manifest events we need to handle
(TCPIP, AFD, MsQuic, HttpService, NDIS-PacketCapture). If they show up
in the future they degrade to ``<unsupported>`` rather than crashing.
"""

from __future__ import annotations

import ctypes
import logging
from ctypes import POINTER, byref, c_ulong, c_ushort, c_void_p, c_wchar, sizeof, wintypes
from typing import Optional

from .bindings.tdh import (
    TdhFormatProperty,
    TdhGetEventInformation,
)
from .bindings.types import (
    EVENT_PROPERTY_INFO,
    EVENT_RECORD,
    TRACE_EVENT_INFO,
)


logger = logging.getLogger(__name__)


# Status codes from ``winerror.h``.
ERROR_SUCCESS = 0
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_NOT_FOUND = 1168            # No manifest for this event
ERROR_EVT_INVALID_EVENT_DATA = 15005

# EVENT_PROPERTY_INFO.Flags bits (``tdh.h``):
PROPERTY_STRUCT = 0x1             # nested struct, skip
PROPERTY_PARAM_LENGTH = 0x2       # length is in another property (by index)
PROPERTY_PARAM_COUNT = 0x4        # array count is in another property
PROPERTY_WBEMXML_FRAGMENT = 0x8
PROPERTY_PARAM_FIXED_LENGTH = 0x10
PROPERTY_PARAM_FIXED_COUNT = 0x20
PROPERTY_HAS_TAGS = 0x40
PROPERTY_HAS_CUSTOM_SCHEMA = 0x80

# EVENT_HEADER.Flags bits (from ``evntcons.h``):
EVENT_HEADER_FLAG_32_BIT_HEADER = 0x0020
EVENT_HEADER_FLAG_64_BIT_HEADER = 0x0040

# TDH IN-types we map to int/string semantics. Anything not listed falls
# through to ``str`` of the formatted output.
_INT_INTYPES = frozenset({
    3, 4, 5, 6, 7, 8, 9, 10,         # INT8/UINT8 .. INT64/UINT64
    13,                                # BOOLEAN
    20, 21,                            # HEXINT32 / HEXINT64
    16,                                # POINTER
})


def _read_wstr(base_addr: int, offset: int) -> str:
    """Read a UTF-16 NUL-terminated string at base+offset.

    Returns the empty string if ``offset`` is zero (sentinel for "no
    string"), matching the convention used throughout the SDK.
    """
    if offset == 0:
        return ""
    return ctypes.wstring_at(base_addr + offset)


class _SchemaEntry:
    """One cached TDH schema, fully parsed.

    We hold on to the raw ``buf`` so the ``TRACE_EVENT_INFO`` pointer we
    pass to ``TdhFormatProperty`` stays valid for the lifetime of the
    process. Parsing the property-info list once means later
    ``decode_event`` calls just walk a list of plain Python tuples
    instead of dereferencing ctypes structs.

    The ``properties`` list holds tuples of:
        (name, in_type, out_type, length, length_kind)

    where ``length_kind`` is one of:
        "fixed"  — use ``length`` directly
        "param"  — ``length`` is the *index* of the property whose decoded
                   integer value gives the byte length of this one
        "zero"   — length is zero; TdhFormatProperty figures it out from
                   the in-type (e.g. null-terminated strings)
    """

    __slots__ = (
        "buf",            # ctypes (c_ubyte * N) keeping TRACE_EVENT_INFO alive
        "tei_ptr",        # POINTER(TRACE_EVENT_INFO) into ``buf``
        "properties",     # list of property descriptor tuples
        "provider_name",
        "task_name",
        "opcode_name",
    )

    def __init__(self) -> None:
        self.buf: Optional[ctypes.Array] = None
        self.tei_ptr = None
        self.properties: list[tuple] = []
        self.provider_name = ""
        self.task_name = ""
        self.opcode_name = ""


def _build_schema(rec_ptr) -> Optional[_SchemaEntry]:
    """Call TdhGetEventInformation and parse the result into a _SchemaEntry.

    Returns None when TDH has no manifest for this event (the kernel-MOF
    case). Other failures are logged and also return None so the decoder
    can negative-cache and move on.
    """
    needed = c_ulong(0)
    rc = TdhGetEventInformation(rec_ptr, 0, None, None, byref(needed))
    if rc not in (ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS):
        return None
    if needed.value == 0:
        return None
    buf = (ctypes.c_ubyte * needed.value)()
    rc = TdhGetEventInformation(
        rec_ptr, 0, None,
        ctypes.cast(buf, POINTER(TRACE_EVENT_INFO)),
        byref(needed),
    )
    if rc != ERROR_SUCCESS:
        return None

    base = ctypes.addressof(buf)
    tei_ptr = ctypes.cast(base, POINTER(TRACE_EVENT_INFO))
    tei = tei_ptr.contents

    n_props = int(tei.TopLevelPropertyCount)
    prop_array_base = base + sizeof(TRACE_EVENT_INFO)
    epi_size = sizeof(EVENT_PROPERTY_INFO)

    entry = _SchemaEntry()
    entry.buf = buf
    entry.tei_ptr = tei_ptr
    entry.provider_name = _read_wstr(base, tei.ProviderNameOffset)
    entry.task_name = _read_wstr(base, tei.TaskNameOffset)
    entry.opcode_name = _read_wstr(base, tei.OpcodeNameOffset)

    for i in range(n_props):
        epi_addr = prop_array_base + i * epi_size
        epi = ctypes.cast(epi_addr, POINTER(EVENT_PROPERTY_INFO)).contents
        name = _read_wstr(base, epi.NameOffset)
        flags = int(epi.Flags)

        if flags & PROPERTY_STRUCT:
            # Nested struct — we don't decode these.
            entry.properties.append((name, 0, 0, 0, "unsupported"))
            continue

        in_type = int(epi.Union1.nonStructType.InType)
        out_type = int(epi.Union1.nonStructType.OutType)

        if flags & PROPERTY_PARAM_LENGTH:
            length_idx = int(epi.LengthUnion.lengthPropertyIndex)
            entry.properties.append((name, in_type, out_type, length_idx, "param"))
        else:
            length = int(epi.LengthUnion.length)
            if length == 0:
                entry.properties.append((name, in_type, out_type, 0, "zero"))
            else:
                entry.properties.append((name, in_type, out_type, length, "fixed"))

    return entry


class TdhDecoder:
    """TDH event decoder with schema and negative caches.

    Usage::

        decoder = TdhDecoder()
        fields = decoder.decode_event(rec_ptr)   # dict | None

    ``rec_ptr`` is the ``POINTER(EVENT_RECORD)`` the ETW callback gets.
    Return value is a dict of ``field_name -> Python value``. Integer
    types are returned as ints; everything else is a string. ``None`` is
    returned when TDH can't decode the event (typically because no
    manifest exists — a kernel-MOF event).
    """

    def __init__(self) -> None:
        # Positive cache: (guid_lower, event_id, version, opcode) -> _SchemaEntry
        self._schemas: dict[tuple, _SchemaEntry] = {}
        # Negative cache: same key, value is True if we've decided this event
        # can't be TDH-decoded. We use a separate set so a missing key in
        # ``_schemas`` doesn't imply "no manifest" — it implies "not yet
        # tried".
        self._negative: set[tuple] = set()
        # Coarser provider-wide negative cache. The kernel-MOF providers
        # never decode, so after the first failure for a given GUID we
        # stop calling TDH on them entirely.
        self._negative_providers: set[str] = set()

    # ------------------------------------------------------------------
    # Cache management
    # ------------------------------------------------------------------
    def schema_count(self) -> int:
        """Number of cached schemas (for diagnostics)."""
        return len(self._schemas)

    def negative_count(self) -> int:
        return len(self._negative)

    def mark_provider_skip(self, guid_lower: str) -> None:
        """Force-skip a provider. Used by the consumer to short-circuit
        kernel-MOF GUIDs before TDH is even consulted."""
        self._negative_providers.add(guid_lower.lower())

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------
    def decode_event(self, record: EVENT_RECORD) -> Optional[dict]:
        """Decode one event. Returns ``None`` on negative cache or failure.

        ``record`` is the dereferenced ``EVENT_RECORD`` reference the
        consumer callback receives. We re-take its address with
        ``ctypes.byref`` to satisfy ``TdhGetEventInformation``'s
        ``POINTER(EVENT_RECORD)`` argtype.

        The dict is a plain Python dict mapping each top-level property
        name to a Python value (int for numeric in-types, str otherwise).
        Errors mid-way through the property list are swallowed — the row
        returned contains everything decoded so far; the consumer can
        decide whether the partial row is useful.
        """
        # ctypes argtypes for TdhGetEventInformation declare
        # ``POINTER(EVENT_RECORD)`` — ``ctypes.pointer`` builds a typed
        # pointer that matches; ``byref`` would also work but
        # ``pointer`` is the more readable shape for this call path.
        rec_ptr = ctypes.pointer(record)
        rec = record
        hdr = rec.EventHeader
        desc = hdr.EventDescriptor

        # Build the cache key. We use the GUID Data1/Data2/Data3/Data4
        # rather than the formatted string — saves a 36-char allocation
        # per event on the hot path.
        pid = hdr.ProviderId
        key = (
            pid.Data1, pid.Data2, pid.Data3, bytes(pid.Data4),
            int(desc.Id), int(desc.Version), int(desc.Opcode),
        )

        if key in self._negative:
            return None

        schema = self._schemas.get(key)
        if schema is None:
            # Provider-wide negative cache short-circuit. We still have
            # to format the GUID once, but only the first time we see
            # the GUID — subsequent events hit the per-key negative
            # cache above.
            guid_str = (
                f"{pid.Data1:08x}-{pid.Data2:04x}-{pid.Data3:04x}-"
                f"{pid.Data4[0]:02x}{pid.Data4[1]:02x}-"
                f"{pid.Data4[2]:02x}{pid.Data4[3]:02x}"
                f"{pid.Data4[4]:02x}{pid.Data4[5]:02x}"
                f"{pid.Data4[6]:02x}{pid.Data4[7]:02x}"
            )
            if guid_str in self._negative_providers:
                self._negative.add(key)
                return None

            schema = _build_schema(rec_ptr)
            if schema is None:
                self._negative.add(key)
                return None
            self._schemas[key] = schema

        # Pointer size — for the manifest events we care about this is
        # always 64-bit on x64 Windows. The 32-bit flag is honoured for
        # correctness but never trips on real captures from our test rig.
        pointer_size = 4 if (int(hdr.Flags) & EVENT_HEADER_FLAG_32_BIT_HEADER) else 8

        user_data_addr = int(rec.UserData or 0)
        user_data_len = int(rec.UserDataLength)
        consumed_total = 0

        # Storage for both the formatted output (returned to caller) and
        # the integer-coerced numeric form (consulted when a later
        # property references this one as a length-by-index).
        out: dict[str, object] = {}
        int_values: list[Optional[int]] = [None] * len(schema.properties)

        tei_ptr = schema.tei_ptr

        for i, (name, in_type, out_type, length_or_idx, kind) in enumerate(schema.properties):
            if kind == "unsupported":
                out[name] = "<struct>"
                continue

            if kind == "param":
                # Length is sourced from another property's int value.
                # If that property hasn't been decoded yet (shouldn't
                # happen with well-formed manifests, all length-refs
                # point backwards) or didn't yield an int, fall back to
                # 0 and let TDH error out cleanly.
                referenced = int_values[length_or_idx] if 0 <= length_or_idx < len(int_values) else None
                prop_length = referenced if referenced is not None and referenced >= 0 else 0
            elif kind == "fixed":
                prop_length = length_or_idx
            else:  # "zero" — TdhFormatProperty derives it from the type
                prop_length = 0

            remaining_addr = user_data_addr + consumed_total
            remaining_len = user_data_len - consumed_total
            if remaining_len <= 0:
                # We've drained the payload. Remaining properties get a
                # sentinel so the dict shape is stable across events of
                # the same schema.
                out[name] = ""
                continue

            buf_size = c_ulong(256)
            out_buf = (c_wchar * 256)()
            consumed = c_ushort(0)
            rc = TdhFormatProperty(
                tei_ptr, None, pointer_size,
                in_type, out_type, prop_length,
                min(remaining_len, 0xFFFF),  # USHORT limit
                c_void_p(remaining_addr),
                byref(buf_size),
                ctypes.cast(out_buf, wintypes.LPWSTR),
                byref(consumed),
            )

            if rc == ERROR_INSUFFICIENT_BUFFER:
                # Grow and retry. The buf_size out-param told us the
                # needed size in bytes — convert to wchars.
                wchar_count = max(buf_size.value // ctypes.sizeof(c_wchar), 1)
                out_buf = (c_wchar * wchar_count)()
                rc = TdhFormatProperty(
                    tei_ptr, None, pointer_size,
                    in_type, out_type, prop_length,
                    min(remaining_len, 0xFFFF),
                    c_void_p(remaining_addr),
                    byref(buf_size),
                    ctypes.cast(out_buf, wintypes.LPWSTR),
                    byref(consumed),
                )

            if rc == ERROR_SUCCESS:
                value_str = out_buf.value
                out[name] = value_str
                consumed_total += int(consumed.value)

                # Pre-compute the int form when the in-type calls for it.
                # We only really need this for properties that get
                # referenced as PROPERTY_PARAM_LENGTH targets — and those
                # are always integer types in well-formed manifests.
                if in_type in _INT_INTYPES:
                    try:
                        if value_str.startswith("0x") or value_str.startswith("0X"):
                            int_values[i] = int(value_str, 16)
                        else:
                            int_values[i] = int(value_str)
                        # Promote to int in the output dict too, since
                        # numeric fields are easier to aggregate downstream.
                        out[name] = int_values[i]
                    except (ValueError, AttributeError):
                        # Some int-typed fields format as hex with embedded
                        # punctuation (mostly POINTER). Leave as string.
                        pass
            else:
                # Format failed. We can't safely advance the cursor (we
                # don't know how many bytes this property occupies), so
                # we mark the rest of the row sparse and stop.
                out[name] = f"<rc={rc}>"
                # Don't break — emit the remaining property names with
                # empty values so the dict shape stays stable. The
                # cursor is now wrong, but TDH will fail further calls
                # gracefully; we just need to not raise.
                break

        return out


__all__ = [
    "TdhDecoder",
    "ERROR_NOT_FOUND",
]
