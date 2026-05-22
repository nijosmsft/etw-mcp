"""ctypes struct definitions for the Windows ETW consumer APIs.

Layouts mirror the SDK headers (``evntrace.h`` / ``evntcons.h`` / ``tdh.h``)
bit-for-bit so the field offsets line up on 64-bit Python builds. Lifted
from the Phase N1 feasibility prototypes (``etw_types.py`` /
``etw_defs.py`` under ``C:\\temp\\etw-feasibility``); the only structural
changes are docstrings, name normalisation, and splitting the bindings into
``advapi32`` / ``tdh`` submodules.

Every struct here is layout-only. No DLL calls live in this module; see
``advapi32.py`` and ``tdh.py`` for the bindings that consume these types.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes


# ---------------------------------------------------------------------------
# GUID
# ---------------------------------------------------------------------------
class GUID(ctypes.Structure):
    """16-byte GUID. Matches ``::_GUID`` in ``guiddef.h``."""

    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]

    def __str__(self) -> str:
        d4 = self.Data4
        return (
            f"{self.Data1:08x}-{self.Data2:04x}-{self.Data3:04x}-"
            f"{d4[0]:02x}{d4[1]:02x}-"
            f"{d4[2]:02x}{d4[3]:02x}{d4[4]:02x}"
            f"{d4[5]:02x}{d4[6]:02x}{d4[7]:02x}"
        )

    @classmethod
    def from_string(cls, s: str) -> "GUID":
        """Parse a ``'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'`` string."""
        s = s.strip("{}").lower().replace("-", "")
        if len(s) != 32:
            raise ValueError(f"invalid GUID string: {s!r}")
        g = cls()
        g.Data1 = int(s[0:8], 16)
        g.Data2 = int(s[8:12], 16)
        g.Data3 = int(s[12:16], 16)
        for i in range(8):
            g.Data4[i] = int(s[16 + i * 2 : 18 + i * 2], 16)
        return g


def guid_string(g: GUID) -> str:
    """Return the canonical lowercase string form of a GUID."""
    return str(g).lower()


# ---------------------------------------------------------------------------
# FILETIME / SYSTEMTIME / TIME_ZONE_INFORMATION
# ---------------------------------------------------------------------------
class FILETIME(ctypes.Structure):
    _fields_ = [
        ("dwLowDateTime", wintypes.DWORD),
        ("dwHighDateTime", wintypes.DWORD),
    ]


class SYSTEMTIME(ctypes.Structure):
    _fields_ = [
        ("wYear", wintypes.WORD),
        ("wMonth", wintypes.WORD),
        ("wDayOfWeek", wintypes.WORD),
        ("wDay", wintypes.WORD),
        ("wHour", wintypes.WORD),
        ("wMinute", wintypes.WORD),
        ("wSecond", wintypes.WORD),
        ("wMilliseconds", wintypes.WORD),
    ]


class TIME_ZONE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Bias", wintypes.LONG),
        ("StandardName", wintypes.WCHAR * 32),
        ("StandardDate", SYSTEMTIME),
        ("StandardBias", wintypes.LONG),
        ("DaylightName", wintypes.WCHAR * 32),
        ("DaylightDate", SYSTEMTIME),
        ("DaylightBias", wintypes.LONG),
    ]


# ---------------------------------------------------------------------------
# EVENT_TRACE_HEADER — the union-with-substruct layout from the SDK
# ---------------------------------------------------------------------------
class _EventTraceHeaderClass(ctypes.Structure):
    _fields_ = [
        ("Type", ctypes.c_ubyte),
        ("Level", ctypes.c_ubyte),
        ("Version", wintypes.USHORT),
    ]


class _EventTraceHeaderU2(ctypes.Union):
    _fields_ = [
        ("Version", wintypes.ULONG),
        ("Class", _EventTraceHeaderClass),
    ]


class _EventTraceHeaderFieldType(ctypes.Structure):
    _fields_ = [
        ("HeaderType", ctypes.c_ubyte),
        ("MarkerFlags", ctypes.c_ubyte),
    ]


class _EventTraceHeaderU1(ctypes.Union):
    _fields_ = [
        ("FieldTypeFlags", wintypes.USHORT),
        ("FT", _EventTraceHeaderFieldType),
    ]


class _EventTraceHeaderU4(ctypes.Union):
    _fields_ = [
        ("KernelUser", ctypes.c_ulonglong),
        ("ProcessorTime", ctypes.c_ulonglong),
    ]


class EVENT_TRACE_HEADER(ctypes.Structure):
    _anonymous_ = ("U1", "U2", "U4")
    _fields_ = [
        ("Size", wintypes.USHORT),
        ("U1", _EventTraceHeaderU1),
        ("U2", _EventTraceHeaderU2),
        ("ThreadId", wintypes.ULONG),
        ("ProcessId", wintypes.ULONG),
        ("TimeStamp", wintypes.LARGE_INTEGER),
        ("Guid", GUID),
        ("U4", _EventTraceHeaderU4),
    ]


# ---------------------------------------------------------------------------
# ETW_BUFFER_CONTEXT
# ---------------------------------------------------------------------------
class _EtwBufferContextStruct(ctypes.Structure):
    _fields_ = [
        ("ProcessorNumber", ctypes.c_ubyte),
        ("Alignment", ctypes.c_ubyte),
    ]


class _EtwBufferContextU(ctypes.Union):
    _fields_ = [
        ("ProcessorIndex", wintypes.USHORT),
        ("BC", _EtwBufferContextStruct),
    ]


class ETW_BUFFER_CONTEXT(ctypes.Structure):
    _anonymous_ = ("U",)
    _fields_ = [
        ("U", _EtwBufferContextU),
        ("LoggerId", wintypes.USHORT),
    ]


# ---------------------------------------------------------------------------
# EVENT_TRACE (legacy callback form)
# ---------------------------------------------------------------------------
class _EventTraceU(ctypes.Union):
    _fields_ = [
        ("ClientContext", wintypes.ULONG),
        ("BufferContext", ETW_BUFFER_CONTEXT),
    ]


class EVENT_TRACE(ctypes.Structure):
    _anonymous_ = ("U",)
    _fields_ = [
        ("Header", EVENT_TRACE_HEADER),
        ("InstanceId", wintypes.ULONG),
        ("ParentInstanceId", wintypes.ULONG),
        ("ParentGuid", GUID),
        ("MofData", ctypes.c_void_p),
        ("MofLength", wintypes.ULONG),
        ("U", _EventTraceU),
    ]


# ---------------------------------------------------------------------------
# TRACE_LOGFILE_HEADER (64-bit layout)
# ---------------------------------------------------------------------------
class _TLH_VersionDetail(ctypes.Structure):
    _fields_ = [
        ("VersionMajor", ctypes.c_ubyte),
        ("VersionMinor", ctypes.c_ubyte),
        ("VersionSub", ctypes.c_ubyte),
        ("VersionSubMinor", ctypes.c_ubyte),
    ]


class _TLH_VersionU(ctypes.Union):
    _fields_ = [
        ("Version", wintypes.ULONG),
        ("Vd", _TLH_VersionDetail),
    ]


class TRACE_LOGFILE_HEADER(ctypes.Structure):
    _anonymous_ = ("VU",)
    _fields_ = [
        ("BufferSize", wintypes.ULONG),
        ("VU", _TLH_VersionU),
        ("ProviderVersion", wintypes.ULONG),
        ("NumberOfProcessors", wintypes.ULONG),
        ("EndTime", wintypes.LARGE_INTEGER),
        ("TimerResolution", wintypes.ULONG),
        ("MaximumFileSize", wintypes.ULONG),
        ("LogFileMode", wintypes.ULONG),
        ("BuffersWritten", wintypes.ULONG),
        ("StartBuffers", wintypes.ULONG),
        ("PointerSize", wintypes.ULONG),
        ("EventsLost", wintypes.ULONG),
        ("CpuSpeedInMHz", wintypes.ULONG),
        ("LoggerName", wintypes.LPWSTR),
        ("LogFileName", wintypes.LPWSTR),
        ("TimeZone", TIME_ZONE_INFORMATION),
        ("BootTime", wintypes.LARGE_INTEGER),
        ("PerfFreq", wintypes.LARGE_INTEGER),
        ("StartTime", wintypes.LARGE_INTEGER),
        ("ReservedFlags", wintypes.ULONG),
        ("BuffersLost", wintypes.ULONG),
    ]


# ---------------------------------------------------------------------------
# EVENT_RECORD (manifest path; ``evntcons.h``)
# ---------------------------------------------------------------------------
class EVENT_DESCRIPTOR(ctypes.Structure):
    _fields_ = [
        ("Id", wintypes.USHORT),
        ("Version", ctypes.c_ubyte),
        ("Channel", ctypes.c_ubyte),
        ("Level", ctypes.c_ubyte),
        ("Opcode", ctypes.c_ubyte),
        ("Task", wintypes.USHORT),
        ("Keyword", ctypes.c_ulonglong),
    ]


class _EventHeader_TimeU_Proc(ctypes.Structure):
    _fields_ = [
        ("KernelTime", wintypes.ULONG),
        ("UserTime", wintypes.ULONG),
    ]


class _EventHeader_TimeU(ctypes.Union):
    _fields_ = [
        ("ProcessorTime", ctypes.c_ulonglong),
        ("Proc", _EventHeader_TimeU_Proc),
    ]


class EVENT_HEADER(ctypes.Structure):
    _anonymous_ = ("U",)
    _fields_ = [
        ("Size", wintypes.USHORT),
        ("HeaderType", wintypes.USHORT),
        ("Flags", wintypes.USHORT),
        ("EventProperty", wintypes.USHORT),
        ("ThreadId", wintypes.ULONG),
        ("ProcessId", wintypes.ULONG),
        ("TimeStamp", wintypes.LARGE_INTEGER),
        ("ProviderId", GUID),
        ("EventDescriptor", EVENT_DESCRIPTOR),
        ("U", _EventHeader_TimeU),
        ("ActivityId", GUID),
    ]


class EVENT_HEADER_EXTENDED_DATA_ITEM(ctypes.Structure):
    _fields_ = [
        ("Reserved1", wintypes.USHORT),
        ("ExtType", wintypes.USHORT),
        ("LinkageFlags", wintypes.USHORT),
        ("DataSize", wintypes.USHORT),
        ("DataPtr", ctypes.c_ulonglong),
    ]


class EVENT_RECORD(ctypes.Structure):
    _fields_ = [
        ("EventHeader", EVENT_HEADER),
        ("BufferContext", ETW_BUFFER_CONTEXT),
        ("ExtendedDataCount", wintypes.USHORT),
        ("UserDataLength", wintypes.USHORT),
        ("ExtendedData", ctypes.POINTER(EVENT_HEADER_EXTENDED_DATA_ITEM)),
        ("UserData", ctypes.c_void_p),
        ("UserContext", ctypes.c_void_p),
    ]


# ---------------------------------------------------------------------------
# Callback function types
# ---------------------------------------------------------------------------
EVENT_TRACE_BUFFER_CALLBACK = ctypes.WINFUNCTYPE(wintypes.ULONG, ctypes.c_void_p)
EVENT_CALLBACK = ctypes.WINFUNCTYPE(None, ctypes.POINTER(EVENT_TRACE))
EVENT_RECORD_CALLBACK = ctypes.WINFUNCTYPE(None, ctypes.POINTER(EVENT_RECORD))


# ---------------------------------------------------------------------------
# EVENT_TRACE_LOGFILEW
#
# The callback union is declared as ``c_void_p`` so we can assign a
# ``WINFUNCTYPE`` value via ``ctypes.cast`` at runtime without ctypes
# complaining about an unsized union member.
# ---------------------------------------------------------------------------
class EVENT_TRACE_LOGFILEW(ctypes.Structure):
    _fields_ = [
        ("LogFileName", wintypes.LPWSTR),
        ("LoggerName", wintypes.LPWSTR),
        ("CurrentTime", wintypes.LARGE_INTEGER),
        ("BuffersRead", wintypes.ULONG),
        ("ProcessTraceMode", wintypes.ULONG),
        ("CurrentEvent", EVENT_TRACE),
        ("LogfileHeader", TRACE_LOGFILE_HEADER),
        ("BufferCallback", EVENT_TRACE_BUFFER_CALLBACK),
        ("BufferSize", wintypes.ULONG),
        ("Filled", wintypes.ULONG),
        ("EventsLost", wintypes.ULONG),
        ("EventCallback", ctypes.c_void_p),
        ("IsKernelTrace", wintypes.ULONG),
        ("Context", ctypes.c_void_p),
    ]


# ---------------------------------------------------------------------------
# TDH support structs (used by ``bindings/tdh.py`` and the future
# tdh_decode.py work). EVENT_PROPERTY_INFO is variable-tailed so it's
# typically used as a pointer; we still declare the fixed leading fields.
# ---------------------------------------------------------------------------
class _EPI_NAME(ctypes.Structure):
    _fields_ = [
        ("InType", wintypes.USHORT),
        ("OutType", wintypes.USHORT),
        ("MapNameOffset", wintypes.ULONG),
    ]


class _EPI_STRUCT(ctypes.Structure):
    _fields_ = [
        ("StructStartIndex", wintypes.USHORT),
        ("NumOfStructMembers", wintypes.USHORT),
        ("padding", wintypes.ULONG),
    ]


class _EPI_CUSTOM(ctypes.Structure):
    _fields_ = [
        ("InType", wintypes.USHORT),
        ("OutType", wintypes.USHORT),
        ("CustomSchemaOffset", wintypes.ULONG),
    ]


class _EPI_UNION(ctypes.Union):
    _fields_ = [
        ("nonStructType", _EPI_NAME),
        ("structType", _EPI_STRUCT),
        ("customSchemaType", _EPI_CUSTOM),
    ]


class _EPI_COUNT(ctypes.Union):
    _fields_ = [
        ("count", wintypes.USHORT),
        ("countPropertyIndex", wintypes.USHORT),
    ]


class _EPI_LENGTH(ctypes.Union):
    _fields_ = [
        ("length", wintypes.USHORT),
        ("lengthPropertyIndex", wintypes.USHORT),
    ]


class _EPI_RESERVED(ctypes.Union):
    _fields_ = [
        ("Reserved", wintypes.ULONG),
        ("Tags_padding", wintypes.ULONG),
    ]


class EVENT_PROPERTY_INFO(ctypes.Structure):
    _fields_ = [
        ("Flags", wintypes.ULONG),
        ("NameOffset", wintypes.ULONG),
        ("Union1", _EPI_UNION),
        ("CountUnion", _EPI_COUNT),
        ("LengthUnion", _EPI_LENGTH),
        ("ResUnion", _EPI_RESERVED),
    ]


class TRACE_EVENT_INFO(ctypes.Structure):
    """Fixed-prefix of ``TRACE_EVENT_INFO``. The real struct has a trailing
    ``EVENT_PROPERTY_INFO EventPropertyInfoArray[ANYSIZE_ARRAY]`` which is
    walked via the ``PropertyCount`` field rather than as a typed array.
    """

    _fields_ = [
        ("ProviderGuid", GUID),
        ("EventGuid", GUID),
        ("EventDescriptor", EVENT_DESCRIPTOR),
        ("DecodingSource", wintypes.UINT),
        ("ProviderNameOffset", wintypes.ULONG),
        ("LevelNameOffset", wintypes.ULONG),
        ("ChannelNameOffset", wintypes.ULONG),
        ("KeywordsNameOffset", wintypes.ULONG),
        ("TaskNameOffset", wintypes.ULONG),
        ("OpcodeNameOffset", wintypes.ULONG),
        ("EventMessageOffset", wintypes.ULONG),
        ("ProviderMessageOffset", wintypes.ULONG),
        ("BinaryXMLOffset", wintypes.ULONG),
        ("BinaryXMLSize", wintypes.ULONG),
        ("EventNameOffset", wintypes.ULONG),
        ("EventAttributesOffset", wintypes.ULONG),
        ("PropertyCount", wintypes.ULONG),
        ("TopLevelPropertyCount", wintypes.ULONG),
        ("Tags_or_Flags", wintypes.ULONG),
    ]


class PROPERTY_DATA_DESCRIPTOR(ctypes.Structure):
    _fields_ = [
        ("PropertyName", ctypes.c_ulonglong),
        ("ArrayIndex", wintypes.ULONG),
        ("Reserved", wintypes.ULONG),
    ]


__all__ = [
    "GUID",
    "guid_string",
    "FILETIME",
    "SYSTEMTIME",
    "TIME_ZONE_INFORMATION",
    "EVENT_TRACE_HEADER",
    "ETW_BUFFER_CONTEXT",
    "EVENT_TRACE",
    "TRACE_LOGFILE_HEADER",
    "EVENT_DESCRIPTOR",
    "EVENT_HEADER",
    "EVENT_HEADER_EXTENDED_DATA_ITEM",
    "EVENT_RECORD",
    "EVENT_TRACE_LOGFILEW",
    "EVENT_TRACE_BUFFER_CALLBACK",
    "EVENT_CALLBACK",
    "EVENT_RECORD_CALLBACK",
    "EVENT_PROPERTY_INFO",
    "TRACE_EVENT_INFO",
    "PROPERTY_DATA_DESCRIPTOR",
]
