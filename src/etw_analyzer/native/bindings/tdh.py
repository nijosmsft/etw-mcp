"""Bindings for the Trace Data Helper (``tdh.dll``) APIs.

Phase N1 ships the bindings but does not yet wire them into the active
decoder — :mod:`native.extract` only consumes raw event records and
defers manifest-event decoding to Phase N2. Having the bindings landed
now means the schema-cache and ``TdhFormatProperty`` work in Phase N2 is
a pure logic addition on top of an already-validated function table.

Bound APIs:
    * ``TdhGetEventInformation`` — get the ``TRACE_EVENT_INFO`` blob for
      an event record. Returns ``ERROR_NOT_FOUND`` for kernel MOF events.
    * ``TdhGetPropertySize`` — required for variable-length property
      decoding (the bug documented in the feasibility ``exp2_tdh_decode``
      experiment: skipping this for BINARY properties drifts every
      subsequent field).
    * ``TdhGetProperty`` — fetch a single property's raw bytes.
    * ``TdhFormatProperty`` — format a single property into a Unicode
      string using the schema.

Import side effects identical to :mod:`.advapi32` — loading the module
calls ``WinDLL("tdh.dll", use_last_error=True)``.
"""

from __future__ import annotations

import ctypes
from ctypes import POINTER, wintypes

from .types import (
    EVENT_RECORD,
    PROPERTY_DATA_DESCRIPTOR,
    TRACE_EVENT_INFO,
)


_tdh = ctypes.WinDLL("tdh.dll", use_last_error=True)


TdhGetEventInformation = _tdh.TdhGetEventInformation
TdhGetEventInformation.argtypes = [
    POINTER(EVENT_RECORD),
    wintypes.ULONG,
    ctypes.c_void_p,             # TDH_CONTEXT *Context (optional)
    POINTER(TRACE_EVENT_INFO),
    POINTER(wintypes.ULONG),     # BufferSize (in/out)
]
TdhGetEventInformation.restype = wintypes.ULONG


TdhGetPropertySize = _tdh.TdhGetPropertySize
TdhGetPropertySize.argtypes = [
    POINTER(EVENT_RECORD),
    wintypes.ULONG,
    ctypes.c_void_p,                       # TDH_CONTEXT *Context (optional)
    wintypes.ULONG,                        # PropertyDataCount
    POINTER(PROPERTY_DATA_DESCRIPTOR),
    POINTER(wintypes.ULONG),               # PropertySize (out)
]
TdhGetPropertySize.restype = wintypes.ULONG


TdhGetProperty = _tdh.TdhGetProperty
TdhGetProperty.argtypes = [
    POINTER(EVENT_RECORD),
    wintypes.ULONG,
    ctypes.c_void_p,                       # TDH_CONTEXT *Context (optional)
    wintypes.ULONG,                        # PropertyDataCount
    POINTER(PROPERTY_DATA_DESCRIPTOR),
    wintypes.ULONG,                        # BufferSize
    ctypes.c_void_p,                       # Buffer (out)
]
TdhGetProperty.restype = wintypes.ULONG


TdhFormatProperty = _tdh.TdhFormatProperty
TdhFormatProperty.argtypes = [
    POINTER(TRACE_EVENT_INFO),
    ctypes.c_void_p,           # EVENT_MAP_INFO *MapInfo
    wintypes.ULONG,            # PointerSize
    wintypes.USHORT,           # PropertyInType
    wintypes.USHORT,           # PropertyOutType
    wintypes.USHORT,           # PropertyLength
    wintypes.USHORT,           # UserDataLength
    ctypes.c_void_p,           # UserData
    POINTER(wintypes.ULONG),   # BufferSize (in/out)
    wintypes.LPWSTR,           # Buffer
    POINTER(wintypes.USHORT),  # UserDataConsumed (out)
]
TdhFormatProperty.restype = wintypes.ULONG


# Mapping for TDH_IN_TYPE values (a subset; full table lives in the
# Phase N2 ``tdh_decode`` module and gets extended there).
TDH_INTYPE_NAMES = {
    0: "NULL", 1: "UNICODESTRING", 2: "ANSISTRING",
    3: "INT8", 4: "UINT8", 5: "INT16", 6: "UINT16",
    7: "INT32", 8: "UINT32", 9: "INT64", 10: "UINT64",
    11: "FLOAT", 12: "DOUBLE", 13: "BOOLEAN", 14: "BINARY",
    15: "GUID", 16: "POINTER", 17: "FILETIME", 18: "SYSTEMTIME",
    19: "SID", 20: "HEXINT32", 21: "HEXINT64",
    22: "MANIFEST_COUNTEDSTRING", 23: "MANIFEST_COUNTEDANSISTRING",
    24: "RESERVED24", 25: "MANIFEST_COUNTEDBINARY",
    300: "COUNTEDSTRING", 301: "COUNTEDANSISTRING",
    302: "REVERSEDCOUNTEDSTRING", 303: "REVERSEDCOUNTEDANSISTRING",
    304: "NONNULLTERMINATEDSTRING", 305: "NONNULLTERMINATEDANSISTRING",
    306: "UNICODECHAR", 307: "ANSICHAR", 308: "SIZET",
    309: "HEXDUMP", 310: "WBEMSID",
}


__all__ = [
    "TdhGetEventInformation",
    "TdhGetPropertySize",
    "TdhGetProperty",
    "TdhFormatProperty",
    "TDH_INTYPE_NAMES",
]
