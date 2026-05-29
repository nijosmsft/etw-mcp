from __future__ import annotations

import re
from pathlib import Path

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from etw_analyzer.native import cache as native_cache
from etw_analyzer.native.event_store import (
    EventFilters,
    EventStoreTimebase,
    NativeEventStore,
    NativeEventStoreError,
    NativeEventStoreWriter,
)
import etw_analyzer.native.config as native_config
import etw_analyzer.tools.trace_mgmt as trace_mgmt
from etw_analyzer.trace_state import clear_traces, get_trace


HIGH_ADDRESS = 0xFFFFF806B09383AC


@pytest.fixture(autouse=True)
def isolate_traces():
    clear_traces()
    native_config.reset_auto_cache()
    yield
    clear_traces()
    native_config.reset_auto_cache()


def _make_etl(tmp_path: Path) -> Path:
    etl = tmp_path / "sample.etl"
    etl.write_bytes(b"synthetic etl")
    return etl


def _trace_id(result: str) -> str:
    match = re.search(r"Trace ID:\*\* `([^`]+)`", result)
    assert match, result
    return match.group(1)


def _sample(index: int, qpc: int, cpu: int = 0) -> dict:
    return {
        "EventSequence": index,
        "TimeStampQpc": qpc,
        "CPU": cpu,
        "ProcessId": 1000,
        "ThreadId": 2000,
        "PayloadThreadId": 2000,
        "InstructionPointer": HIGH_ADDRESS,
        "Weight": 1,
        "ProfileWeight": 1,
        "Stack": [HIGH_ADDRESS, 0x1234],
    }


def test_tiny_flush_threshold_creates_multiple_parts(tmp_path: Path):
    export_dir = tmp_path / ".etw-export-sample"
    writer = NativeEventStoreWriter(
        export_dir,
        run_id="run-a",
        staging=False,
        max_rows_per_part=2,
    )
    for index in range(5):
        writer.append("sampled_profile", _sample(index, 1_000 + index))

    store = writer.commit()

    dataset = store.manifest.datasets["sampled_profile"]
    assert dataset.row_count == 5
    assert [part.row_count for part in dataset.parts] == [2, 2, 1]
    assert len(list((store.generation_dir / "events" / "sampled_profile").glob("part-*.parquet"))) == 3


def test_stack_uint64_round_trips(tmp_path: Path):
    export_dir = tmp_path / ".etw-export-sample"
    writer = NativeEventStoreWriter(export_dir, run_id="run-stack", staging=False)
    writer.append("sampled_profile", _sample(1, 1_000))
    store = writer.commit()

    part_path = store.generation_dir / store.manifest.datasets["sampled_profile"].parts[0].path
    schema = pq.read_schema(part_path)
    stack_type = schema.field("Stack").type
    assert pa.types.is_list(stack_type)
    assert pa.types.is_uint64(stack_type.value_type)

    rows = store.scan("sampled_profile")
    assert int(rows.iloc[0]["InstructionPointer"]) == HIGH_ADDRESS
    assert rows.iloc[0]["Stack"] == [HIGH_ADDRESS, 0x1234]


def test_empty_dataset_manifest_and_scan(tmp_path: Path):
    export_dir = tmp_path / ".etw-export-sample"
    writer = NativeEventStoreWriter(
        export_dir,
        run_id="run-empty",
        event_classes=["cswitch"],
        staging=False,
    )
    store = writer.commit()

    dataset = store.manifest.datasets["cswitch"]
    assert dataset.row_count == 0
    assert dataset.parts == []
    assert store.scan("cswitch").empty


def test_scan_exposes_relative_microseconds(tmp_path: Path):
    export_dir = tmp_path / ".etw-export-sample"
    writer = NativeEventStoreWriter(
        export_dir,
        run_id="run-time",
        timebase=EventStoreTimebase(qpc_origin=1_000, perf_freq=1_000_000),
        staging=False,
    )
    for index, qpc in enumerate([1_000, 1_001, 2_000]):
        writer.append("sampled_profile", _sample(index, qpc))
    store = writer.commit()

    rows = store.scan("sampled_profile")

    assert rows["TimeStampQpc"].tolist() == [1_000, 1_001, 2_000]
    assert rows["TimeStamp"].tolist() == [0, 1, 1_000]


def test_scan_time_filter_uses_seconds_as_qpc_pushdown(tmp_path: Path):
    export_dir = tmp_path / ".etw-export-sample"
    writer = NativeEventStoreWriter(
        export_dir,
        run_id="run-filter",
        timebase=EventStoreTimebase(qpc_origin=1_000, perf_freq=1_000),
        staging=False,
        max_rows_per_part=1,
    )
    for index, qpc in enumerate([1_000, 1_500, 2_000, 2_500]):
        writer.append("sampled_profile", _sample(index, qpc, cpu=index % 2))
    store = writer.commit()

    rows = store.scan(
        "sampled_profile",
        filters=EventFilters(start_time=0.5, end_time=1.0),
    )

    assert rows["TimeStampQpc"].tolist() == [1_500, 2_000]
    assert rows["TimeStamp"].tolist() == [500_000, 1_000_000]


def test_scan_projected_columns_still_honor_cpu_and_time_filters(tmp_path: Path):
    export_dir = tmp_path / ".etw-export-sample"
    writer = NativeEventStoreWriter(
        export_dir,
        run_id="run-projected-filter",
        timebase=EventStoreTimebase(qpc_origin=1_000, perf_freq=1_000),
        staging=False,
        max_rows_per_part=1,
    )
    for index, (qpc, cpu) in enumerate([(1_000, 0), (1_500, 1), (2_000, 1), (2_500, 0)]):
        writer.append("sampled_profile", _sample(index, qpc, cpu=cpu))
    store = writer.commit()

    rows = store.scan(
        "sampled_profile",
        filters=EventFilters(cpu_filter="1", start_time=0.25, end_time=1.0),
        columns=["InstructionPointer"],
    )

    assert rows.columns.tolist() == ["InstructionPointer", "TimeStamp"]
    assert rows["InstructionPointer"].tolist() == [HIGH_ADDRESS, HIGH_ADDRESS]
    assert rows["TimeStamp"].tolist() == [500_000, 1_000_000]


def test_iter_batches_projected_columns_still_honor_cpu_and_time_filters(tmp_path: Path):
    export_dir = tmp_path / ".etw-export-sample"
    writer = NativeEventStoreWriter(
        export_dir,
        run_id="run-projected-filter-batches",
        timebase=EventStoreTimebase(qpc_origin=10_000, perf_freq=1_000),
        staging=False,
        max_rows_per_part=1,
    )
    for index, (qpc, cpu) in enumerate([(10_000, 0), (10_500, 1), (11_000, 1), (11_500, 0)]):
        writer.append("sampled_profile", _sample(index, qpc, cpu=cpu))
    store = writer.commit()

    batches = list(
        store.iter_batches(
            "sampled_profile",
            filters=EventFilters(cpu_filter="1", start_time=0.25, end_time=1.0),
            columns=["InstructionPointer"],
            batch_size=1,
        )
    )

    assert len(batches) == 2
    assert [batch.columns.tolist() for batch in batches] == [
        ["InstructionPointer", "TimeStamp"],
        ["InstructionPointer", "TimeStamp"],
    ]
    assert [int(batch.iloc[0]["TimeStamp"]) for batch in batches] == [500_000, 1_000_000]


def test_missing_part_file_rejected(tmp_path: Path):
    export_dir = tmp_path / ".etw-export-sample"
    writer = NativeEventStoreWriter(export_dir, run_id="run-missing", staging=False)
    writer.append("sampled_profile", _sample(1, 1_000))
    store = writer.commit()
    part_path = store.generation_dir / store.manifest.datasets["sampled_profile"].parts[0].path
    part_path.unlink()

    with pytest.raises(NativeEventStoreError):
        NativeEventStore.open(store.generation_dir, export_dir=export_dir)


def test_partial_part_file_rejected(tmp_path: Path):
    export_dir = tmp_path / ".etw-export-sample"
    writer = NativeEventStoreWriter(export_dir, run_id="run-partial", staging=False)
    writer.append("sampled_profile", _sample(1, 1_000))
    store = writer.commit()
    part_path = store.generation_dir / store.manifest.datasets["sampled_profile"].parts[0].path
    part_path.write_bytes(b"not a complete parquet file")

    with pytest.raises(NativeEventStoreError):
        NativeEventStore.open(store.generation_dir, export_dir=export_dir)


def test_native_reload_opens_event_store_without_materializing_events(
    monkeypatch,
    tmp_path: Path,
):
    etl = _make_etl(tmp_path)
    export_dir = etl.parent / f".etw-export-{etl.stem}"
    export_dir.mkdir()

    cpu_sampling = pd.DataFrame({
        "Process Name": ["proc.exe"],
        "PID": [1234],
        "Weight": [7],
        "% Weight": [100.0],
        "Module": ["mod.dll"],
        "Function": ["func"],
    })
    cpu_sampling.to_parquet(export_dir / "cpu_sampling.parquet", index=False)

    datasets = [
        native_cache.CacheDataset(
            name="cpu_sampling",
            kind="parquet",
            path="cpu_sampling.parquet",
            row_count=len(cpu_sampling),
            materialize_on_load=True,
        )
    ]
    for _, stem in trace_mgmt._DUMPER_EVENT_CLASSES.values():
        pd.DataFrame().to_parquet(export_dir / f"{stem}.parquet", index=False)
        datasets.append(
            native_cache.CacheDataset(
                name=stem,
                kind="dumper-parquet",
                path=f"{stem}.parquet",
                row_count=0,
                materialize_on_load=False,
            )
        )

    writer = NativeEventStoreWriter(export_dir, run_id="run-cache", staging=False)
    writer.append("sampled_profile", _sample(1, 1_000))
    store = writer.commit()
    datasets.append(store.cache_dataset())

    native_cache.write_manifest(
        export_dir,
        native_cache.CacheManifest.materialized_small(etl, datasets),
    )

    cached = trace_mgmt._load_from_cache(export_dir, etl, mode="native")
    assert cached is not None
    assert "cpu_sampling" in cached
    assert "sampled_profile" not in cached

    monkeypatch.setattr(native_config, "resolve_mode", lambda mode, etl_path=None: "native")
    monkeypatch.setattr(native_config, "_etl_size_mb", lambda etl_path: 0.1)
    monkeypatch.setattr(trace_mgmt, "find_xperf", lambda: None)

    result = trace_mgmt.load_trace(str(etl), mode="native")
    trace = get_trace(_trace_id(result))

    assert trace is not None
    assert trace.event_store is not None
    assert trace.event_store.scan("sampled_profile")["Stack"].iloc[0] == [HIGH_ADDRESS, 0x1234]
    assert "cpu_sampling" in trace.raw_csv
    assert "sampled_profile" not in trace.raw_csv


def test_streaming_cache_reload_opens_event_store_without_dumper_materialization(
    monkeypatch,
    tmp_path: Path,
):
    etl = _make_etl(tmp_path)
    export_dir = etl.parent / f".etw-export-{etl.stem}"
    export_dir.mkdir()

    metadata = pd.DataFrame({
        "NumberOfProcessors": [4],
        "StartTime": [10_000_000],
        "EndTime": [20_000_000],
        "DurationSeconds": [1.0],
        "PerfFreq": [1_000_000],
    })
    metadata.to_parquet(export_dir / "trace_metadata.parquet", index=False)

    writer = NativeEventStoreWriter(export_dir, run_id="run-stream", staging=False)
    writer.append("sampled_profile", _sample(1, 1_000))
    store = writer.commit()

    native_cache.write_manifest(
        export_dir,
        native_cache.CacheManifest.event_store_streaming(
            etl,
            [
                native_cache.CacheDataset(
                    name="trace_metadata",
                    kind="parquet",
                    path="trace_metadata.parquet",
                    row_count=len(metadata),
                    materialize_on_load=True,
                ),
                store.cache_dataset(),
            ],
        ),
    )

    cached = trace_mgmt._load_from_cache(export_dir, etl, mode="native")
    assert cached is not None
    assert "trace_metadata" in cached
    assert "sampled_profile" not in cached

    monkeypatch.setattr(native_config, "resolve_mode", lambda mode, etl_path=None: "native")
    monkeypatch.setattr(native_config, "_etl_size_mb", lambda etl_path: 0.1)
    monkeypatch.setattr(trace_mgmt, "find_xperf", lambda: None)
    monkeypatch.setattr(
        trace_mgmt,
        "_start_background_dumper",
        lambda trace: pytest.fail("streaming cache reload must not materialize events"),
    )

    result = trace_mgmt.load_trace(str(etl), mode="native")
    trace = get_trace(_trace_id(result))

    assert "Native event store" in result
    assert "aggregate tools may report limited data" in result
    assert trace is not None
    assert trace.event_store is not None
    assert trace.event_store.scan("sampled_profile")["Stack"].iloc[0] == [
        HIGH_ADDRESS,
        0x1234,
    ]
    assert "sampled_profile" not in trace.raw_csv
