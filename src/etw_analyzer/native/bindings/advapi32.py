"""Bindings for ``OpenTraceW`` / ``ProcessTrace`` / ``CloseTrace``.

These three functions form the entire ETW consumer-side surface: open a
log file (returns a 64-bit trace handle), spin ProcessTrace which calls
our event-record callback for every event, then close the handle. The
``EVENT_TRACE_LOGFILEW`` struct in :mod:`.types` is the in/out parameter
that ties them together.

Import side effects: loading this module calls ``WinDLL("advapi32",
use_last_error=True)``. On non-Windows platforms that import will raise
``OSError`` / ``FileNotFoundError``; callers should catch that — see
``native.consumer.is_available``.
"""

from __future__ import annotations

import ctypes
from ctypes import POINTER, wintypes

from .types import EVENT_TRACE_LOGFILEW, FILETIME


# Constants
INVALID_PROCESSTRACE_HANDLE = ctypes.c_uint64(0xFFFFFFFFFFFFFFFF).value
PROCESS_TRACE_MODE_REAL_TIME = 0x00000100
PROCESS_TRACE_MODE_RAW_TIMESTAMP = 0x00001000
PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000

# Common Win32 / TDH error codes
ERROR_SUCCESS = 0
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_NOT_FOUND = 1168
ERROR_EVT_INVALID_EVENT_DATA = 15005
ERROR_RESOURCE_TYPE_NOT_FOUND = 1813


# Load advapi32 lazily at import time. On non-Windows hosts this raises
# OSError; the higher-level ``is_available`` wrapper turns that into a
# boolean so the rest of the codebase can probe safely.
_advapi32 = ctypes.WinDLL("advapi32.dll", use_last_error=True)


OpenTraceW = _advapi32.OpenTraceW
OpenTraceW.argtypes = [POINTER(EVENT_TRACE_LOGFILEW)]
OpenTraceW.restype = ctypes.c_ulonglong  # TRACEHANDLE

ProcessTrace = _advapi32.ProcessTrace
ProcessTrace.argtypes = [
    POINTER(ctypes.c_ulonglong),  # HandleArray (PTRACEHANDLE)
    wintypes.ULONG,               # HandleCount
    POINTER(FILETIME),            # StartTime (optional)
    POINTER(FILETIME),            # EndTime (optional)
]
ProcessTrace.restype = wintypes.ULONG

CloseTrace = _advapi32.CloseTrace
CloseTrace.argtypes = [ctypes.c_ulonglong]
CloseTrace.restype = wintypes.ULONG


__all__ = [
    "INVALID_PROCESSTRACE_HANDLE",
    "PROCESS_TRACE_MODE_REAL_TIME",
    "PROCESS_TRACE_MODE_RAW_TIMESTAMP",
    "PROCESS_TRACE_MODE_EVENT_RECORD",
    "ERROR_SUCCESS",
    "ERROR_INSUFFICIENT_BUFFER",
    "ERROR_NOT_FOUND",
    "ERROR_EVT_INVALID_EVENT_DATA",
    "ERROR_RESOURCE_TYPE_NOT_FOUND",
    "OpenTraceW",
    "ProcessTrace",
    "CloseTrace",
]
