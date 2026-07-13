"""Canonical schemas for chunked native event-store datasets."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

import pyarrow as pa


EVENT_SCHEMA_VERSION = 5  # ReadyThread readying/readied identity + cswitch wait-state columns


@dataclass(frozen=True)
class EventSchema:
    """Fixed physical schema for one native event class."""

    name: str
    version: int
    schema: pa.Schema
    qpc_column: str = "TimeStampQpc"


_UINT64_MAX = (1 << 64) - 1


def _schema(name: str, fields: Iterable[pa.Field]) -> EventSchema:
    # NOTE: The parquet metadata keys intentionally retain the
    # "wpr_mcp_" prefix even after the v0.4 etw-mcp rename. The
    # native loader keys schema/version detection off these byte
    # strings; renaming them would silently invalidate every user's
    # on-disk extracted-parquet cache and force a fresh extraction.
    metadata = {
        b"wpr_mcp_event_class": name.encode("utf-8"),
        b"wpr_mcp_schema_version": str(EVENT_SCHEMA_VERSION).encode("ascii"),
    }
    return EventSchema(
        name=name,
        version=EVENT_SCHEMA_VERSION,
        schema=pa.schema(list(fields), metadata=metadata),
    )


_STACK_TYPE = pa.list_(pa.uint64())


def _base_event_fields() -> list[pa.Field]:
    return [
        pa.field("EventSequence", pa.uint64()),
        pa.field("TimeStampQpc", pa.int64()),
        pa.field("CPU", pa.int32()),
    ]


def _kernel_thread_fields() -> list[pa.Field]:
    return [
        * _base_event_fields(),
        pa.field("ProcessId", pa.int64()),
        pa.field("ThreadId", pa.int64()),
    ]


def _xperf_header_fields() -> list[pa.Field]:
    return [
        * _base_event_fields(),
        pa.field("Process Name", pa.string()),
        pa.field("PID", pa.int64()),
        pa.field("ThreadID", pa.int64()),
    ]


def _endpoint_fields() -> list[pa.Field]:
    return [
        pa.field("LocalAddr", pa.string()),
        pa.field("LocalPort", pa.int64()),
        pa.field("RemoteAddr", pa.string()),
        pa.field("RemotePort", pa.int64()),
    ]


def _tcp_data_fields(*, retransmit: bool = False) -> list[pa.Field]:
    fields = [
        * _xperf_header_fields(),
        * _endpoint_fields(),
        pa.field("Size", pa.int64()),
        pa.field("SeqNo", pa.uint64()),
        pa.field("ConnId", pa.uint64()),
    ]
    if retransmit:
        fields.append(pa.field("RetransmitCount", pa.int64()))
    return fields


def _tcp_connect_fields() -> list[pa.Field]:
    return [
        * _xperf_header_fields(),
        * _endpoint_fields(),
        pa.field("Size", pa.int64()),
        pa.field("MSS", pa.int64()),
        pa.field("RcvWin", pa.int64()),
        pa.field("SeqNo", pa.uint64()),
        pa.field("ConnId", pa.uint64()),
    ]


def _udp_fields() -> list[pa.Field]:
    return [
        * _xperf_header_fields(),
        * _endpoint_fields(),
        pa.field("Size", pa.int64()),
    ]


def _afd_io_fields() -> list[pa.Field]:
    return [
        * _xperf_header_fields(),
        pa.field("SocketHandle", pa.uint64()),
        pa.field("Size", pa.int64()),
        pa.field("CompletionStatus", pa.int64()),
    ]


def _afd_endpoint_fields() -> list[pa.Field]:
    return [
        * _xperf_header_fields(),
        pa.field("SocketHandle", pa.uint64()),
        * _endpoint_fields(),
    ]


def _single_handle_fields(name: str) -> list[pa.Field]:
    return [
        * _xperf_header_fields(),
        pa.field(name, pa.uint64()),
    ]


EVENT_SCHEMAS: dict[str, EventSchema] = {
    "sampled_profile": _schema(
        "sampled_profile",
        [
            pa.field("EventSequence", pa.uint64()),
            pa.field("TimeStampQpc", pa.int64()),
            pa.field("CPU", pa.int32()),
            pa.field("ProcessId", pa.int64()),
            pa.field("ThreadId", pa.int64()),
            pa.field("PayloadThreadId", pa.int64()),
            pa.field("InstructionPointer", pa.uint64()),
            pa.field("Weight", pa.int64()),
            pa.field("ProfileWeight", pa.int64()),
            pa.field("Stack", _STACK_TYPE),
        ],
    ),
    "cswitch": _schema(
        "cswitch",
        [
            pa.field("EventSequence", pa.uint64()),
            pa.field("TimeStampQpc", pa.int64()),
            pa.field("CPU", pa.int32()),
            pa.field("NewTID", pa.int64()),
            pa.field("OldTID", pa.int64()),
            pa.field("NewPID", pa.int64()),
            pa.field("OldPID", pa.int64()),
            pa.field("WaitReason", pa.string()),
            # v5: scheduler wait-state detail the precise CPU tool needs to
            # separate Waiting off-CPU intervals from other off-CPU (e.g.
            # preempted) intervals and to report priorities.
            pa.field("WaitMode", pa.string()),
            pa.field("OldThreadState", pa.string()),
            pa.field("NewPriority", pa.int32()),
            pa.field("OldPriority", pa.int32()),
            pa.field("Stack", _STACK_TYPE),
        ],
    ),
    "dpc": _schema(
        "dpc",
        [
            pa.field("EventSequence", pa.uint64()),
            pa.field("TimeStampQpc", pa.int64()),
            pa.field("InitialTimeQpc", pa.int64()),
            pa.field("CPU", pa.int32()),
            pa.field("Routine", pa.uint64()),
            pa.field("Type", pa.string()),
            pa.field("DurationQpc", pa.int64()),
            pa.field("DurationUs", pa.float64()),
            pa.field("Stack", _STACK_TYPE),
        ],
    ),
    "isr": _schema(
        "isr",
        [
            pa.field("EventSequence", pa.uint64()),
            pa.field("TimeStampQpc", pa.int64()),
            pa.field("InitialTimeQpc", pa.int64()),
            pa.field("CPU", pa.int32()),
            pa.field("Routine", pa.uint64()),
            pa.field("Type", pa.string()),
            pa.field("DurationQpc", pa.int64()),
            pa.field("DurationUs", pa.float64()),
            pa.field("Stack", _STACK_TYPE),
        ],
    ),
    "process": _schema(
        "process",
        [
            pa.field("EventSequence", pa.uint64()),
            pa.field("TimeStampQpc", pa.int64()),
            pa.field("CPU", pa.int32()),
            pa.field("ProcessId", pa.int64()),
            pa.field("ParentId", pa.int64()),
            pa.field("SessionId", pa.int64()),
            pa.field("ImageFileName", pa.string()),
            pa.field("CommandLine", pa.string()),
            pa.field("Type", pa.string()),
        ],
    ),
    "thread": _schema(
        "thread",
        [
            pa.field("EventSequence", pa.uint64()),
            pa.field("TimeStampQpc", pa.int64()),
            pa.field("CPU", pa.int32()),
            pa.field("ProcessId", pa.int64()),
            pa.field("ThreadId", pa.int64()),
            pa.field("ThreadName", pa.string()),
            pa.field("Type", pa.string()),
        ],
    ),
    "image": _schema(
        "image",
        [
            pa.field("EventSequence", pa.uint64()),
            pa.field("TimeStampQpc", pa.int64()),
            pa.field("CPU", pa.int32()),
            pa.field("ProcessId", pa.int64()),
            pa.field("ImageBase", pa.uint64()),
            pa.field("ImageSize", pa.uint64()),
            pa.field("FileName", pa.string()),
            pa.field("Type", pa.string()),
            # M2: PDB identity columns threaded from sidecar RSDS events.
            # Populated by the .NET sidecar (M1) and carried through Python
            # schema to every add_module call site (M3 wires them to dbghelp).
            # Rows with no matching RSDS event leave these null.
            pa.field("TimeDateStamp", pa.int64()),
            pa.field("PdbGuid", pa.string()),
            pa.field("PdbAge", pa.int64()),
            pa.field("PdbName", pa.string()),
        ],
    ),
    # M5: ImageID/DbgID_RSDS records carry PDB signature data (GUID, Age,
    # PdbName).  These are stored in a separate dataset so they can survive in
    # the event store independently of the "image" load/unload rows and be
    # joined back at symbolizer-build time.  PdbFullPath is the raw field
    # (potentially a full build path); PdbName is the basename.
    "imageid_rsds": _schema(
        "imageid_rsds",
        [
            pa.field("EventSequence", pa.uint64()),
            pa.field("TimeStampQpc", pa.int64()),
            pa.field("CPU", pa.int32()),
            pa.field("ProcessId", pa.int64()),
            pa.field("ImageBase", pa.uint64()),
            pa.field("PdbGuid", pa.string()),
            pa.field("PdbAge", pa.int64()),
            pa.field("PdbName", pa.string()),
            pa.field("PdbFullPath", pa.string()),
        ],
    ),
    "readythread": _schema(
        "readythread",
        [
            * _kernel_thread_fields(),
            # v5: split the two thread identities. ``ThreadId`` (from
            # _kernel_thread_fields) and ``ReadiedThreadId`` are the readied
            # (target) thread; ``ReadyingThreadId`` / ``ReadyingProcessId``
            # are the readying (source) thread/process lifted from the ETW
            # event header. The precise CPU tool uses these for wake
            # attribution.
            pa.field("ReadiedThreadId", pa.int64()),
            pa.field("ReadyingThreadId", pa.int64()),
            pa.field("ReadyingProcessId", pa.int64()),
            pa.field("AdjustReason", pa.int32()),
            pa.field("AdjustIncrement", pa.int32()),
            pa.field("Flag", pa.int32()),
            pa.field("Stack", _STACK_TYPE),
        ],
    ),
    "tcpip_recv": _schema("tcpip_recv", _tcp_data_fields()),
    "tcpip_send": _schema("tcpip_send", _tcp_data_fields()),
    "tcpip_retransmit": _schema(
        "tcpip_retransmit",
        _tcp_data_fields(retransmit=True),
    ),
    "tcpip_connect": _schema("tcpip_connect", _tcp_connect_fields()),
    "tcpip_accept": _schema("tcpip_accept", _tcp_connect_fields()),
    "udp_recv": _schema("udp_recv", _udp_fields()),
    "udp_send": _schema("udp_send", _udp_fields()),
    "afd_recv": _schema("afd_recv", _afd_io_fields()),
    "afd_send": _schema("afd_send", _afd_io_fields()),
    "afd_connect": _schema("afd_connect", _afd_endpoint_fields()),
    "afd_accept": _schema("afd_accept", _afd_endpoint_fields()),
    "afd_close": _schema("afd_close", _single_handle_fields("SocketHandle")),
    "ndis_drops": _schema(
        "ndis_drops",
        [
            * _xperf_header_fields(),
            pa.field("MiniportName", pa.string()),
            pa.field("Reason", pa.string()),
            pa.field("Size", pa.int64()),
        ],
    ),
    "packet_capture": _schema(
        "packet_capture",
        [
            * _xperf_header_fields(),
            pa.field("Direction", pa.string()),
            pa.field("MiniportName", pa.string()),
            pa.field("PacketBytes", pa.string()),
            pa.field("Size", pa.int64()),
        ],
    ),
    "http_recv": _schema(
        "http_recv",
        [
            * _xperf_header_fields(),
            pa.field("RequestId", pa.uint64()),
            pa.field("ConnectionId", pa.uint64()),
            pa.field("Verb", pa.string()),
            pa.field("Url", pa.string()),
        ],
    ),
    "http_deliver": _schema(
        "http_deliver",
        [
            * _xperf_header_fields(),
            pa.field("RequestId", pa.uint64()),
            pa.field("UrlGroupId", pa.uint64()),
        ],
    ),
    "http_send": _schema(
        "http_send",
        [
            * _xperf_header_fields(),
            pa.field("RequestId", pa.uint64()),
            pa.field("StatusCode", pa.int64()),
            pa.field("ContentLength", pa.int64()),
        ],
    ),
    "http_close": _schema("http_close", _single_handle_fields("RequestId")),
    "quic_conn_created": _schema(
        "quic_conn_created",
        [
            * _xperf_header_fields(),
            pa.field("ConnectionId", pa.uint64()),
            pa.field("CID", pa.string()),
            pa.field("LocalAddr", pa.string()),
            pa.field("RemoteAddr", pa.string()),
        ],
    ),
    "quic_conn_closed": _schema(
        "quic_conn_closed",
        _single_handle_fields("ConnectionId"),
    ),
    "quic_packet_recv": _schema(
        "quic_packet_recv",
        [
            * _xperf_header_fields(),
            pa.field("ConnectionId", pa.uint64()),
            pa.field("PacketNumber", pa.uint64()),
            pa.field("Size", pa.int64()),
        ],
    ),
    "quic_packet_send": _schema(
        "quic_packet_send",
        [
            * _xperf_header_fields(),
            pa.field("ConnectionId", pa.uint64()),
            pa.field("PacketNumber", pa.uint64()),
            pa.field("Size", pa.int64()),
        ],
    ),
    "quic_ack_recv": _schema(
        "quic_ack_recv",
        [
            * _xperf_header_fields(),
            pa.field("ConnectionId", pa.uint64()),
            pa.field("AckDelay", pa.int64()),
            pa.field("LargestAcknowledged", pa.uint64()),
        ],
    ),
}


_EVENT_CLASS_ALIAS_SETS: dict[str, tuple[str, ...]] = {
    "sampled_profile": (
        "SampledProfile", "sampledprofile", "sampled_profile", "dumper_df",
    ),
    "cswitch": ("CSwitch", "cswitch", "cswitch_events", "cswitch_events_df"),
    "dpc": ("PerfInfo/DPC", "PerfInfo/ThreadedDPC", "PerfInfo/TimerDPC", "dpc"),
    "isr": ("PerfInfo/ISR", "isr"),
    "process": (
        "Process/Start", "Process/End", "Process/DCStart",
        "Process/DCEnd", "Process/Defunct", "process",
    ),
    "thread": (
        "Thread/Start", "Thread/End", "Thread/DCStart",
        "Thread/DCEnd", "Thread/SetName", "thread",
    ),
    "image": (
        "Image/Load", "Image/Unload", "Image/DCStart", "Image/DCEnd", "image",
    ),
    "imageid_rsds": (
        "ImageID/DbgID_RSDS", "ImageID_DbgID_RSDS",
        "ImageID/DbgIDRSDS", "imageid_rsds",
    ),
    "readythread": (
        "ReadyThread", "Thread/ReadyThread", "Thread/Ready",
        "readythread", "ready_thread",
    ),
    "tcpip_recv": ("TcpIp/Recv", "TcpIp_Recv", "TcpIpRecv", "tcpip_recv", "tcpip_recv_df"),
    "tcpip_send": ("TcpIp/Send", "TcpIp_Send", "TcpIpSend", "tcpip_send", "tcpip_send_df"),
    "tcpip_retransmit": (
        "TcpIp/Retransmit", "TcpIp_Retransmit", "TcpIpRetransmit",
        "tcpip_retransmit", "tcpip_retransmit_df",
    ),
    "tcpip_connect": (
        "TcpIp/Connect", "TcpIp_Connect", "TcpIpConnect",
        "tcpip_connect", "tcpip_connect_df",
    ),
    "tcpip_accept": (
        "TcpIp/Accept", "TcpIp_Accept", "TcpIpAccept",
        "tcpip_accept", "tcpip_accept_df",
    ),
    "udp_recv": ("UdpIp/Recv", "UdpIp_Recv", "UdpIpRecv", "udp_recv", "udp_recv_df"),
    "udp_send": ("UdpIp/Send", "UdpIp_Send", "UdpIpSend", "udp_send", "udp_send_df"),
    "afd_recv": ("AFD/Recv", "Afd/Recv", "AFD_Recv", "AFDRecv", "afd_recv", "afd_recv_df"),
    "afd_send": ("AFD/Send", "Afd/Send", "AFD_Send", "AFDSend", "afd_send", "afd_send_df"),
    "afd_connect": (
        "AFD/Connect", "Afd/Connect", "AFD_Connect", "AFDConnect",
        "afd_connect", "afd_connect_df",
    ),
    "afd_accept": (
        "AFD/Accept", "Afd/Accept", "AFD_Accept", "AFDAccept",
        "afd_accept", "afd_accept_df",
    ),
    "afd_close": ("AFD/Close", "Afd/Close", "AFD_Close", "AFDClose", "afd_close", "afd_close_df"),
    "ndis_drops": (
        "NdisDrop", "NDIS/Drop", "Ndis/Drop", "NDIS_Drop",
        "PacketDrop", "ndis_drops", "ndis_drops_df", "ndis_drop",
    ),
    "packet_capture": (
        "NdisPacketCapture", "NdisPacketCapture/Recv", "NdisPacketCapture/Send",
        "Ndis/PacketCapture/Recv", "Ndis/PacketCapture/Send",
        "NDIS-PacketCapture/Recv", "NDIS-PacketCapture/Send",
        "PacketCapture/Recv", "PacketCapture/Send", "packet_capture",
        "packet_capture_df",
    ),
    "http_recv": (
        "HttpService/Recv", "HttpService_Recv", "HttpServiceRecv",
        "HttpService/RecvRequest", "HTTPRequestTraceTask/RecvReq",
        "Http/RecvRequest", "http_recv", "http_recv_df",
    ),
    "http_deliver": (
        "HttpService/Deliver", "HttpService_Deliver", "HttpServiceDeliver",
        "HttpService/DeliverRequest", "HTTPRequestTraceTask/Deliver",
        "Http/Deliver", "http_deliver", "http_deliver_df",
    ),
    "http_send": (
        "HttpService/Send", "HttpService_Send", "HttpServiceSend",
        "HttpService/SendResponse", "HttpService/FastResponse",
        "HTTPRequestTraceTask/SendResponse", "HTTPRequestTraceTask/FastSend",
        "Http/SendResponse", "http_send", "http_send_df",
    ),
    "http_close": (
        "HttpService/Close", "HttpService_Close", "HttpServiceClose",
        "HttpService/CloseRequest", "HTTPRequestTraceTask/SrvdReq",
        "Http/Close", "http_close", "http_close_df",
    ),
    "quic_conn_created": (
        "Quic/ConnectionCreated", "Quic_ConnectionCreated",
        "QuicConnectionCreated", "MsQuic/ConnectionCreated",
        "Quic/ConnCreated", "Quic/Connection", "quic_conn_created",
        "quic_connection_created", "quic_conn_created_df",
    ),
    "quic_conn_closed": (
        "Quic/ConnectionClosed", "Quic_ConnectionClosed",
        "QuicConnectionClosed", "MsQuic/ConnectionClosed",
        "Quic/ConnClosed", "Quic/ConnectionDestroyed",
        "quic_conn_closed", "quic_connection_closed", "quic_conn_closed_df",
    ),
    "quic_packet_recv": (
        "Quic/PacketRecv", "Quic_PacketRecv", "QuicPacketRecv",
        "MsQuic/PacketRecv", "Quic/PacketReceived",
        "Quic/ConnPacketRecv", "quic_packet_recv", "quic_packet_recv_df",
    ),
    "quic_packet_send": (
        "Quic/PacketSend", "Quic_PacketSend", "QuicPacketSend",
        "MsQuic/PacketSend", "Quic/PacketSent",
        "Quic/ConnPacketSent", "quic_packet_send", "quic_packet_send_df",
    ),
    "quic_ack_recv": (
        "Quic/AckReceived", "Quic_AckReceived", "QuicAckReceived",
        "MsQuic/AckReceived", "Quic/AckRecv", "Quic/AckProcessed",
        "quic_ack_recv", "quic_ack_recv_df",
    ),
}


EVENT_CLASS_ALIASES: dict[str, str] = {
    alias: canonical
    for canonical, aliases in _EVENT_CLASS_ALIAS_SETS.items()
    for alias in aliases
}
EVENT_CLASS_ALIASES.update({
    canonical: canonical
    for canonical in EVENT_SCHEMAS
})
EVENT_CLASS_ALIASES.update({
    alias.lower(): canonical
    for alias, canonical in list(EVENT_CLASS_ALIASES.items())
})


_FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "TimeStampQpc": ("TimeStampQpc", "TimeStamp"),
    "InitialTimeQpc": ("InitialTimeQpc", "InitialTime"),
    "DurationUs": ("DurationUs", "Duration_us", "Duration (us)", "DPC_us", "ISR_us"),
    "ProcessId": ("ProcessId", "PID"),
    "ThreadId": ("ThreadId", "ThreadID", "TID"),
    "PID": ("PID", "ProcessId"),
    "ThreadID": ("ThreadID", "ThreadId", "TID"),
    "Process Name": ("Process Name", "ProcessName"),
    "Weight": ("Weight", "Count"),
    "Size": ("Size", "NumBytes", "BytesSent", "BytesRecv", "FragmentSize"),
    "SeqNo": ("SeqNo", "SeqNum", "SequenceNumber"),
    "ConnId": ("ConnId", "Tcb", "TCB"),
    "SocketHandle": ("SocketHandle", "Endpoint"),
    "RequestId": ("RequestId", "RequestObj"),
    "ConnectionId": ("ConnectionId", "ConnectionObj", "Connection", "CorrelationId"),
    "UrlGroupId": ("UrlGroupId", "UrlGroup"),
    "PacketBytes": ("PacketBytes", "Fragment"),
    "MiniportName": ("MiniportName", "FriendlyName"),
    "LocalAddr": ("LocalAddr", "LocalAddress"),
    "RemoteAddr": ("RemoteAddr", "RemoteAddress"),
}


def canonical_event_class(event_class: str) -> str:
    """Return the event-store class name for a native/xperf event class."""

    raw = str(event_class).strip()
    name = EVENT_CLASS_ALIASES.get(raw)
    if name is None:
        name = EVENT_CLASS_ALIASES.get(raw.lower(), raw)
    if name not in EVENT_SCHEMAS:
        raise KeyError(f"unsupported native event-store class: {event_class!r}")
    return name


def schema_for_event_class(event_class: str) -> EventSchema:
    """Return the fixed schema descriptor for ``event_class``."""

    return EVENT_SCHEMAS[canonical_event_class(event_class)]


def empty_table(event_class: str) -> pa.Table:
    """Return an empty Arrow table with the class's canonical schema."""

    return pa.Table.from_pylist([], schema=schema_for_event_class(event_class).schema)


def rows_to_table(event_class: str, rows: Iterable[dict[str, Any]]) -> pa.Table:
    """Convert row dictionaries to an Arrow table, ignoring unknown columns."""

    event_schema = schema_for_event_class(event_class)
    normalized = [
        _normalize_row(row, event_schema.schema)
        for row in rows
    ]
    return pa.Table.from_pylist(normalized, schema=event_schema.schema)


def _normalize_row(row: dict[str, Any], schema: pa.Schema) -> dict[str, Any]:
    return {
        field.name: _coerce_value(_lookup_value(row, field.name), field.type)
        for field in schema
    }


def _lookup_value(row: dict[str, Any], field_name: str) -> Any:
    for key in _FIELD_ALIASES.get(field_name, (field_name,)):
        if key in row:
            return row[key]
    return None


def _coerce_value(value: Any, typ: pa.DataType) -> Any:
    if value is None:
        return None
    if pa.types.is_list(typ):
        if value is None:
            return None
        if isinstance(value, (bytes, str)):
            return None
        try:
            return [_coerce_uint64(item) for item in value]
        except TypeError:
            return None
    if pa.types.is_uint64(typ):
        return _coerce_uint64(value)
    if pa.types.is_integer(typ):
        return int(value)
    if pa.types.is_floating(typ):
        return float(value)
    if pa.types.is_string(typ):
        return str(value)
    return value


def _coerce_uint64(value: Any) -> int:
    integer = int(value)
    if integer < 0:
        integer = (integer + (1 << 64)) & _UINT64_MAX
    if integer > _UINT64_MAX:
        raise OverflowError(f"value does not fit uint64: {value!r}")
    return integer


__all__ = [
    "EVENT_SCHEMA_VERSION",
    "EVENT_SCHEMAS",
    "EVENT_CLASS_ALIASES",
    "EventSchema",
    "canonical_event_class",
    "schema_for_event_class",
    "empty_table",
    "rows_to_table",
]
