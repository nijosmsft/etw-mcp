from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import etw_analyzer.native.extract as extract


HIGH_ADDRESS = 0xFFFFF806B09383AC


def _record(
    opcode: int,
    qpc: int,
    *,
    cpu: int = 0,
    pid: int = 1000,
    tid: int = 2000,
):
    descriptor = SimpleNamespace(Opcode=opcode, Version=0, Id=opcode)
    header = SimpleNamespace(
        ProviderId=object(),
        TimeStamp=qpc,
        ProcessId=pid,
        ThreadId=tid,
        EventDescriptor=descriptor,
    )
    buffer_context = SimpleNamespace(
        U=SimpleNamespace(BC=SimpleNamespace(ProcessorNumber=cpu))
    )
    return SimpleNamespace(
        EventHeader=header,
        BufferContext=buffer_context,
        UserDataLength=0,
        UserData=None,
    )


def _sample_decoder(payload, hdr):
    return {
        "TimeStamp": int(hdr["TimeStamp"]),
        "CPU": int(hdr["ProcessorNumber"]),
        "PID": int(hdr["ProcessId"]),
        "PayloadThreadId": int(hdr["ThreadId"]),
        "InstructionPointer": HIGH_ADDRESS,
        "Weight": 1,
        "ProfileWeight": 1,
    }


def _stack_decoder(payload, hdr):
    return {
        "EventTimeStamp": 100,
        "ProcessId": int(hdr["ProcessId"]),
        "ThreadId": 2000,
        "Stack": (HIGH_ADDRESS, 0x1234),
        "CPU": int(hdr["ProcessorNumber"]),
        "StackTimeStamp": int(hdr["TimeStamp"]),
    }


def _readythread_decoder(payload, hdr):
    return {
        "TimeStamp": int(hdr["TimeStamp"]),
        "CPU": int(hdr["ProcessorNumber"]),
        "ThreadId": int(hdr["ThreadId"]),
        "ProcessId": int(hdr["ProcessId"]),
        "AdjustReason": 1,
        "AdjustIncrement": 0,
        "Flag": 0,
    }


def _install_fake_consumer(monkeypatch, events):
    class FakeConsumer:
        def __init__(self, paths, callback):
            self._callback = callback

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return None

        def run(self):
            for event in events:
                self._callback(event)
            return SimpleNamespace(
                event_count=len(events),
                bytes_processed=1234,
                elapsed_seconds=0.01,
                events_lost=0,
                logfile_metadata=[SimpleNamespace(perf_freq=1_000_000)],
            )

    decoders = {
        1: ("SampledProfile", _sample_decoder),
        2: ("StackWalk", _stack_decoder),
    }
    monkeypatch.setattr(extract, "EtwConsumer", FakeConsumer)
    monkeypatch.setattr(extract, "guid_string", lambda provider: "provider")
    monkeypatch.setattr(
        extract,
        "_lookup_handler",
        lambda guid, opcode, version: decoders.get(opcode),
    )


def test_streaming_extraction_chunks_and_does_not_materialize_dataframes(
    monkeypatch,
    tmp_path: Path,
):
    etl = tmp_path / "sample.etl"
    etl.write_bytes(b"synthetic")
    export_dir = tmp_path / ".etw-export-sample"
    events = [
        _record(1, 100, tid=2000),
        _record(2, 101, tid=2000),
        _record(1, 200, tid=2001),
        _record(1, 300, tid=2002),
        _record(1, 400, tid=2003),
    ]
    _install_fake_consumer(monkeypatch, events)

    stats_sink = []
    with monkeypatch.context() as no_dataframe:
        no_dataframe.setattr(
            extract.pd,
            "DataFrame",
            lambda *args, **kwargs: pytest.fail(
                "streaming extraction must not materialize DataFrames"
            ),
        )
        store = extract.extract_events_to_store(
            etl,
            export_dir,
            event_classes={"SampledProfile", "CSwitch", "Process/Start"},
            stats_sink=stats_sink,
            max_rows_per_part=2,
        )

    sampled = store.manifest.datasets["sampled_profile"]
    assert sampled.row_count == 4
    assert [part.row_count for part in sampled.parts] == [2, 2]
    assert store.manifest.datasets["cswitch"].row_count == 0
    assert store.manifest.datasets["process"].row_count == 0
    assert sampled.min_qpc == 100
    assert sampled.max_qpc == 400

    rows = store.scan("sampled_profile", include_time=False)
    assert rows["TimeStampQpc"].tolist() == [100, 200, 300, 400]
    assert rows.iloc[0]["Stack"] == [HIGH_ADDRESS, 0x1234]

    assert len(stats_sink) == 1
    stats = stats_sink[0]
    assert stats.decoded_counts["SampledProfile"] == 4
    assert stats.stacks_paired == 1
    assert stats.stacks_orphan == 0


def test_streaming_extraction_skips_unrequested_classes_before_decode(
    monkeypatch,
    tmp_path: Path,
):
    etl = tmp_path / "sample.etl"
    etl.write_bytes(b"synthetic")
    export_dir = tmp_path / ".etw-export-sample"
    events = [
        _record(3, 100, tid=2000),
        _record(1, 200, tid=2001),
        _record(2, 201, tid=2001),
    ]

    def fail_cswitch_decoder(payload, hdr):
        pytest.fail("unrequested CSwitch should be skipped before decode")

    _install_fake_consumer(monkeypatch, events)
    monkeypatch.setattr(
        extract,
        "_lookup_handler",
        lambda guid, opcode, version: {
            1: ("SampledProfile", _sample_decoder),
            2: ("StackWalk", _stack_decoder),
            3: ("CSwitch", fail_cswitch_decoder),
        }.get(opcode),
    )

    store = extract.extract_events_to_store(
        etl,
        export_dir,
        event_classes={"SampledProfile"},
        capture_stacks=False,
        max_rows_per_part=2,
    )

    assert "cswitch" not in store.manifest.datasets
    sampled = store.manifest.datasets["sampled_profile"]
    assert sampled.row_count == 1
    rows = store.scan("sampled_profile", include_time=False)
    assert rows.iloc[0]["Stack"] is None


def test_streaming_extraction_stores_requested_app_layer_classes(
    monkeypatch,
    tmp_path: Path,
):
    etl = tmp_path / "sample.etl"
    etl.write_bytes(b"synthetic")
    export_dir = tmp_path / ".etw-export-sample"
    events = [
        _record(4, 1_000, tid=2000),
        _record(5, 1_500, tid=2000),
    ]

    def http_recv_decoder(payload, hdr):
        return {
            "TimeStamp": int(hdr["TimeStamp"]),
            "CPU": int(hdr["ProcessorNumber"]),
            "PID": int(hdr["ProcessId"]),
            "ThreadID": int(hdr["ThreadId"]),
            "RequestId": 10,
            "ConnectionId": 20,
            "Verb": "GET",
            "Url": "/stream",
        }

    def quic_ack_decoder(payload, hdr):
        return {
            "TimeStamp": int(hdr["TimeStamp"]),
            "CPU": int(hdr["ProcessorNumber"]),
            "PID": int(hdr["ProcessId"]),
            "ThreadID": int(hdr["ThreadId"]),
            "ConnectionId": 77,
            "AckDelay": 500,
            "LargestAcknowledged": 9,
        }

    _install_fake_consumer(monkeypatch, events)
    monkeypatch.setattr(
        extract,
        "_lookup_handler",
        lambda guid, opcode, version: {
            4: ("HttpService/Recv", http_recv_decoder),
            5: ("Quic/AckReceived", quic_ack_decoder),
        }.get(opcode),
    )

    store = extract.extract_events_to_store(
        etl,
        export_dir,
        event_classes={"HttpService/Recv", "Quic/AckReceived"},
        capture_stacks=False,
        max_rows_per_part=2,
    )

    assert store.manifest.datasets["http_recv"].row_count == 1
    assert store.manifest.datasets["quic_ack_recv"].row_count == 1
    assert store.scan("http_recv")["Url"].tolist() == ["/stream"]
    assert store.scan("quic_ack_recv")["AckDelay"].tolist() == [500]


def test_streaming_extraction_writes_requested_scheduler_detail_classes(
    monkeypatch,
    tmp_path: Path,
):
    etl = tmp_path / "sample.etl"
    etl.write_bytes(b"synthetic")
    export_dir = tmp_path / ".etw-export-sample"
    events = [
        _record(4, 100, tid=2000),
        _record(3, 150, tid=2000),
    ]
    _install_fake_consumer(monkeypatch, events)
    monkeypatch.setattr(
        extract,
        "_lookup_handler",
        lambda guid, opcode, version: {
            3: ("CSwitch", lambda payload, hdr: {
                "TimeStamp": int(hdr["TimeStamp"]),
                "CPU": int(hdr["ProcessorNumber"]),
                "NewTID": int(hdr["ThreadId"]),
                "OldTID": 100,
                "NewPID": int(hdr["ProcessId"]),
                "OldPID": 4,
                "WaitReason": "WrQueue",
            }),
            4: ("ReadyThread", _readythread_decoder),
        }.get(opcode),
    )

    store = extract.extract_events_to_store(
        etl,
        export_dir,
        event_classes={"CSwitch", "ReadyThread"},
        capture_stacks=True,
    )

    assert store.manifest.datasets["readythread"].row_count == 1
    assert store.manifest.datasets["cswitch"].row_count == 1
    ready = store.scan("readythread", include_time=False)
    assert ready.iloc[0]["ThreadId"] == 2000
