from __future__ import annotations

from pathlib import Path

import pandas as pd

from etw_analyzer.native.aggregators.network import enrich_network_events
from etw_analyzer.trace_state import TraceData


def _trace(**kwargs) -> TraceData:
    return TraceData(
        trace_id="trace_net",
        etl_path=Path(r"C:\traces\net.etl"),
        export_dir=Path(r"C:\traces\.etw-export-net"),
        mode="native",
        **kwargs,
    )


def test_tcp_send_recv_get_five_tuple_from_connid_map():
    process = pd.DataFrame([
        {"ProcessId": 1234, "ImageFileName": "server.exe", "TimeStamp": 1},
    ])
    recv = pd.DataFrame([{
        "ConnId": 0xABC,
        "PID": 1234,
        "Process Name": "<unknown>",
        "LocalAddr": "",
        "LocalPort": 0,
        "RemoteAddr": "",
        "RemotePort": 0,
        "Size": 100,
    }])
    connect = pd.DataFrame([{
        "ConnId": 0xABC,
        "PID": 1234,
        "Process Name": "<unknown>",
        "LocalAddr": "192.168.1.10",
        "LocalPort": 443,
        "RemoteAddr": "10.0.0.2",
        "RemotePort": 50000,
    }])
    trace = _trace(
        raw_csv={"Process/DCStart": process},
        tcpip_recv_df=recv,
        tcpip_connect_df=connect,
    )

    mutated = enrich_network_events(trace)

    assert "TcpIp/Recv" in mutated
    row = trace.tcpip_recv_df.iloc[0]
    assert row["LocalAddr"] == "192.168.1.10"
    assert row["LocalPort"] == 443
    assert row["RemoteAddr"] == "10.0.0.2"
    assert row["RemotePort"] == 50000
    assert row["Process Name"] == "server.exe"


def test_missing_tcp_mapping_gets_explicit_unknowns():
    send = pd.DataFrame([{
        "ConnId": 99,
        "PID": 0,
        "Process Name": "",
        "LocalAddr": "",
        "LocalPort": 0,
        "RemoteAddr": "",
        "RemotePort": 0,
        "Size": 100,
    }])
    trace = _trace(tcpip_send_df=send)

    mutated = enrich_network_events(trace)

    assert "TcpIp/Send" in mutated
    row = trace.tcpip_send_df.iloc[0]
    assert row["LocalAddr"] == "<unknown>"
    assert row["RemoteAddr"] == "<unknown>"
    assert row["Process Name"] == "unknown"


def test_afd_send_gets_endpoint_details_from_socket_map():
    afd_send = pd.DataFrame([{
        "SocketHandle": 123,
        "PID": 4321,
        "Process Name": "",
        "Size": 512,
    }])
    afd_connect = pd.DataFrame([{
        "SocketHandle": 123,
        "PID": 4321,
        "Process Name": "client.exe",
        "LocalAddr": "",
        "LocalPort": 0,
        "RemoteAddr": "10.0.0.8",
        "RemotePort": 443,
    }])
    trace = _trace(afd_send_df=afd_send, afd_connect_df=afd_connect)

    mutated = enrich_network_events(trace)

    assert "AFD/Send" in mutated
    row = trace.afd_send_df.iloc[0]
    assert row["RemoteAddr"] == "10.0.0.8"
    assert row["RemotePort"] == 443
    assert row["Process Name"] == "client.exe"
