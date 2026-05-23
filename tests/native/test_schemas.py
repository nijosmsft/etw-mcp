from __future__ import annotations

import pyarrow as pa
import pytest

from etw_analyzer.native.schemas import (
    canonical_event_class,
    empty_table,
    rows_to_table,
    schema_for_event_class,
)


_NEW_CLASS_ALIASES = {
    "readythread": ["ReadyThread", "Thread/ReadyThread", "readythread"],
    "tcpip_recv": ["TcpIp/Recv", "TcpIp_Recv", "tcpip_recv", "tcpip_recv_df"],
    "tcpip_send": ["TcpIp/Send", "TcpIp_Send", "tcpip_send"],
    "tcpip_retransmit": ["TcpIp/Retransmit", "TcpIpRetransmit", "tcpip_retransmit"],
    "tcpip_connect": ["TcpIp/Connect", "TcpIpConnect", "tcpip_connect"],
    "tcpip_accept": ["TcpIp/Accept", "TcpIpAccept", "tcpip_accept"],
    "udp_recv": ["UdpIp/Recv", "UdpIpRecv", "udp_recv"],
    "udp_send": ["UdpIp/Send", "UdpIpSend", "udp_send"],
    "afd_recv": ["AFD/Recv", "Afd/Recv", "afd_recv"],
    "afd_send": ["AFD/Send", "Afd/Send", "afd_send"],
    "afd_connect": ["AFD/Connect", "Afd/Connect", "afd_connect"],
    "afd_accept": ["AFD/Accept", "Afd/Accept", "afd_accept"],
    "afd_close": ["AFD/Close", "Afd/Close", "afd_close"],
    "ndis_drops": ["NdisDrop", "NDIS/Drop", "ndis_drops"],
    "packet_capture": ["NdisPacketCapture", "NdisPacketCapture/Recv", "packet_capture"],
    "http_recv": ["HttpService/Recv", "HttpServiceRecv", "http_recv"],
    "http_deliver": ["HttpService/Deliver", "HttpServiceDeliver", "http_deliver"],
    "http_send": ["HttpService/Send", "HttpServiceSend", "http_send"],
    "http_close": ["HttpService/Close", "HttpServiceClose", "http_close"],
    "quic_conn_created": ["Quic/ConnectionCreated", "QuicConnectionCreated", "quic_conn_created"],
    "quic_conn_closed": ["Quic/ConnectionClosed", "QuicConnectionClosed", "quic_conn_closed"],
    "quic_packet_recv": ["Quic/PacketRecv", "QuicPacketRecv", "quic_packet_recv"],
    "quic_packet_send": ["Quic/PacketSend", "QuicPacketSend", "quic_packet_send"],
    "quic_ack_recv": ["Quic/AckReceived", "QuicAckReceived", "quic_ack_recv"],
}


@pytest.mark.parametrize(
    ("canonical", "aliases"),
    sorted(_NEW_CLASS_ALIASES.items()),
)
def test_new_schema_aliases_resolve(canonical: str, aliases: list[str]) -> None:
    for alias in aliases:
        assert canonical_event_class(alias) == canonical
        assert schema_for_event_class(alias).name == canonical


@pytest.mark.parametrize(
    "event_class",
    [
        "NdisPacketCapture",
        "HttpService/Recv",
        "Quic/PacketRecv",
        "TcpIp/Recv",
        "AFD/Recv",
    ],
)
def test_empty_table_has_canonical_schema(event_class: str) -> None:
    table = empty_table(event_class)
    assert table.num_rows == 0
    assert table.schema == schema_for_event_class(event_class).schema


def test_packet_capture_rows_to_table_round_trips() -> None:
    table = rows_to_table(
        "NdisPacketCapture",
        [{
            "TimeStamp": 100,
            "CPU": 2,
            "ProcessName": "pktmon.exe",
            "ProcessId": 10,
            "ThreadId": 11,
            "Direction": "Recv",
            "MiniportName": "mlx5",
            "PacketBytes": "aabbccddeeff",
            "Size": 6,
            "Ignored": "not stored",
        }],
    )

    assert table.schema == schema_for_event_class("packet_capture").schema
    assert table.column("TimeStampQpc").to_pylist() == [100]
    assert table.column("PID").to_pylist() == [10]
    assert table.column("ThreadID").to_pylist() == [11]
    assert table.column("PacketBytes").to_pylist() == ["aabbccddeeff"]
    assert "Ignored" not in table.column_names


def test_http_quic_and_network_rows_to_table_round_trip() -> None:
    tcp_conn_id = 0xFFFF_F806_B093_83AC
    tcp = rows_to_table(
        "TcpIp/Recv",
        [{
            "TimeStamp": 200,
            "CPU": 3,
            "PID": 20,
            "ThreadID": 21,
            "LocalAddr": "10.0.0.1",
            "LocalPort": 443,
            "RemoteAddr": "10.0.0.2",
            "RemotePort": 50000,
            "NumBytes": 1200,
            "SeqNum": 7,
            "Tcb": tcp_conn_id,
        }],
    )
    assert tcp.column("Size").to_pylist() == [1200]
    assert tcp.column("SeqNo").to_pylist() == [7]
    assert tcp.column("ConnId").to_pylist() == [tcp_conn_id]
    assert pa.types.is_uint64(tcp.schema.field("ConnId").type)

    http = rows_to_table(
        "HttpService/Recv",
        [{
            "TimeStamp": 300,
            "PID": 30,
            "ThreadID": 31,
            "RequestObj": 0xABC,
            "ConnectionObj": 0x111,
            "Verb": "GET",
            "Url": "/health",
        }],
    )
    assert http.column("RequestId").to_pylist() == [0xABC]
    assert http.column("ConnectionId").to_pylist() == [0x111]
    assert http.column("Url").to_pylist() == ["/health"]

    quic = rows_to_table(
        "Quic/AckReceived",
        [{
            "TimeStamp": 400,
            "PID": 40,
            "ThreadID": 41,
            "Connection": 0x2000,
            "AckDelay": 500,
            "LargestAcknowledged": 9,
        }],
    )
    assert quic.column("ConnectionId").to_pylist() == [0x2000]
    assert quic.column("AckDelay").to_pylist() == [500]
    assert quic.column("LargestAcknowledged").to_pylist() == [9]
