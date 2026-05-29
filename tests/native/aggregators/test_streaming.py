from __future__ import annotations

import re
from pathlib import Path

import pandas as pd
import pytest

from etw_analyzer.native import cache as native_cache
from etw_analyzer.native.aggregators.dpcisr import aggregate_dpc_isr
from etw_analyzer.native.aggregators.profile_detail import aggregate_cpu_sampling
from etw_analyzer.native.aggregators.profile_util import aggregate_cpu_timeline
from etw_analyzer.native.aggregators.streaming import (
    _normalize_cpu_sampling_capacity,
    build_streaming_aggregates,
)
from etw_analyzer.native.event_store import EventStoreTimebase, NativeEventStoreWriter
from etw_analyzer.native.worker import NativeWorkerRequest, build_streaming_event_store_cache
import etw_analyzer.native as native
import etw_analyzer.native.config as native_config
import etw_analyzer.tools.trace_mgmt as trace_mgmt
from etw_analyzer.tools.cpu_sampling import get_cpu_samples
from etw_analyzer.tools.dpc_isr import get_dpc_summary
from etw_analyzer.tools.per_cpu import get_per_cpu_summary
from etw_analyzer.tools.system_info import get_process_info
from etw_analyzer.trace_state import TraceData, clear_traces, get_trace


HIGH_ADDRESS = 0x18001000


class _FakeSymbolizer:
    def bulk_resolve(self, addrs):
        return {
            int(addr): "mod.sys!HotRoutine+0x10"
            for addr in addrs
            if int(addr) in {HIGH_ADDRESS, HIGH_ADDRESS + 0x20}
        }


@pytest.fixture(autouse=True)
def _clean_registry():
    clear_traces()
    native_config.reset_auto_cache()
    yield
    clear_traces()
    native_config.reset_auto_cache()


def _trace_id(result: str) -> str:
    match = re.search(r"Trace ID:\*\* `([^`]+)`", result)
    assert match, result
    return match.group(1)


def _make_etl(tmp_path: Path) -> Path:
    etl = tmp_path / "sample.etl"
    etl.write_bytes(b"synthetic etl")
    return etl


def _populate_store(writer: NativeEventStoreWriter) -> None:
    writer.append(
        "process",
        {
            "EventSequence": 1,
            "TimeStampQpc": 1_000,
            "CPU": 0,
            "ProcessId": 1234,
            "ParentId": 4,
            "SessionId": 0,
            "ImageFileName": "server.exe",
            "CommandLine": "server.exe -listen",
            "Type": "DCStart",
        },
    )
    writer.append(
        "thread",
        {
            "EventSequence": 2,
            "TimeStampQpc": 1_000,
            "CPU": 0,
            "ProcessId": 1234,
            "ThreadId": 4242,
            "ThreadName": "worker",
            "Type": "DCStart",
        },
    )
    writer.append(
        "image",
        {
            "EventSequence": 3,
            "TimeStampQpc": 1_000,
            "CPU": 0,
            "ProcessId": 1234,
            "ImageBase": HIGH_ADDRESS & ~0xFFF,
            "ImageSize": 0x10_000,
            "FileName": r"C:\Windows\System32\drivers\mod.sys",
            "Type": "DCStart",
        },
    )
    for index, (qpc, cpu, weight) in enumerate(
        [(501_000, 0, 3), (1_501_000, 1, 2), (1_601_000, 1, 1)],
        start=4,
    ):
        writer.append(
            "sampled_profile",
            {
                "EventSequence": index,
                "TimeStampQpc": qpc,
                "CPU": cpu,
                "ProcessId": 0xFFFFFFFF,
                "ThreadId": 4242,
                "PayloadThreadId": 4242,
                "InstructionPointer": HIGH_ADDRESS,
                "Weight": 1,
                "ProfileWeight": weight,
                "Stack": [HIGH_ADDRESS, HIGH_ADDRESS + 0x20],
            },
        )
    writer.append(
        "dpc",
        {
            "EventSequence": 10,
            "TimeStampQpc": 1_200,
            "InitialTimeQpc": 1_100,
            "CPU": 1,
            "Routine": HIGH_ADDRESS,
            "Type": "DPC",
            "DurationQpc": 100,
            "DurationUs": 100.0,
            "Stack": [HIGH_ADDRESS],
        },
    )


def _make_store(export_dir: Path):
    writer = NativeEventStoreWriter(
        export_dir,
        run_id="streaming-test",
        timebase=EventStoreTimebase(qpc_origin=1_000, perf_freq=1_000_000),
        staging=False,
    )
    _populate_store(writer)
    return writer.commit()


def test_streaming_aggregates_match_dataframe_aggregators(tmp_path: Path):
    store = _make_store(tmp_path / ".etw-export-sample")
    trace = TraceData(
        trace_id="trace_stream",
        etl_path=tmp_path / "sample.etl",
        export_dir=tmp_path / ".etw-export-sample",
        mode="native",
        raw_csv={
            "trace_metadata": pd.DataFrame([{
                "NumberOfProcessors": 2,
                "DurationSeconds": 2.0,
                "PerfFreq": 1_000_000,
            }]),
        },
        duration_seconds=2.0,
        cpu_count=2,
        timestamp_frequency=1_000_000,
    )
    trace.symbolizer = _FakeSymbolizer()

    result = build_streaming_aggregates(trace, store, batch_size=2)

    samples = store.scan("sampled_profile")
    process = store.scan("process")
    thread = store.scan("thread")
    expected_trace = TraceData(
        trace_id="trace_expected",
        etl_path=trace.etl_path,
        export_dir=trace.export_dir,
        mode="native",
        raw_csv={
            "trace_metadata": trace.raw_csv["trace_metadata"],
            "Process/DCStart": process,
            "Thread/DCStart": thread,
        },
        dumper_df=samples,
        duration_seconds=2.0,
        cpu_count=2,
        timestamp_frequency=1_000_000,
    )
    expected_trace.symbolizer = _FakeSymbolizer()

    expected_cpu = aggregate_cpu_sampling(expected_trace)
    pd.testing.assert_frame_equal(
        result.dataframes["cpu_sampling"].reset_index(drop=True),
        expected_cpu.reset_index(drop=True),
        check_dtype=False,
    )

    expected_timeline = aggregate_cpu_timeline(expected_trace)
    pd.testing.assert_frame_equal(
        result.dataframes["cpu_timeline"].reset_index(drop=True),
        expected_timeline.reset_index(drop=True),
        check_dtype=False,
    )

    dpc = store.scan("dpc")
    dpc_expected = pd.DataFrame({
        "TimeStamp": dpc["TimeStamp"],
        "InitialTime": (
            (pd.to_numeric(dpc["InitialTimeQpc"]) - 1_000)
            * 1_000_000.0
            / 1_000_000
        ).round().astype("int64"),
        "Routine": dpc["Routine"],
        "CPU": dpc["CPU"],
    })
    expected_trace.raw_csv["_native_dpc_events"] = dpc_expected
    expected_dpc = aggregate_dpc_isr(expected_trace)
    pd.testing.assert_frame_equal(
        result.dataframes["dpc_isr"].reset_index(drop=True),
        expected_dpc.reset_index(drop=True),
        check_dtype=False,
    )

    assert "process_info" in result.texts
    assert "server.exe" in result.texts["process_info"]
    assert result.warnings == []


def test_streaming_idle_top_up_does_not_treat_real_idle_sample_as_synthetic(tmp_path: Path):
    trace = TraceData(
        trace_id="trace_idle",
        etl_path=tmp_path / "sample.etl",
        export_dir=tmp_path / ".etw-export-sample",
        mode="native",
        duration_seconds=1.0,
        cpu_count=1,
    )
    cpu_sampling = pd.DataFrame([{
        "Process Name": "Idle",
        "PID": 0,
        "Weight": 250_000,
        "% Weight": 100.0,
        "Module": "ntoskrnl.exe",
        "Function": "KiIdleLoop",
    }])
    cpu_sampling.attrs["profile_weight_time_scaled"] = True

    result = _normalize_cpu_sampling_capacity(cpu_sampling, None, trace)

    assert len(result) == 2
    assert int(result["Weight"].sum()) == 1_000_000
    synthetic = result[
        (result["Module"] == "<Heuristic Low Power State>")
        & (result["Function"] == "<C3>")
    ].iloc[0]
    assert synthetic["Process Name"] == "Idle"
    assert synthetic["Weight"] == 750_000


def test_streaming_sample_count_weights_do_not_synthesize_idle(tmp_path: Path):
    trace = TraceData(
        trace_id="trace_sample_count",
        etl_path=tmp_path / "sample.etl",
        export_dir=tmp_path / ".etw-export-sample",
        mode="native",
        duration_seconds=1.0,
        cpu_count=1,
    )
    cpu_sampling = pd.DataFrame([{
        "Process Name": "server.exe",
        "PID": 1234,
        "Weight": 1_000,
        "% Weight": 100.0,
        "Module": "mod.sys",
        "Function": "HotRoutine",
    }])
    cpu_sampling.attrs["profile_weight_time_scaled"] = False

    result = _normalize_cpu_sampling_capacity(cpu_sampling, None, trace)

    assert len(result) == 1
    assert "Idle" not in result["Process Name"].tolist()
    assert int(result["Weight"].sum()) == 1_000


def test_worker_streaming_finalization_writes_aggregate_outputs(
    monkeypatch,
    tmp_path: Path,
):
    etl = _make_etl(tmp_path)
    export_dir = tmp_path / ".etw-export-sample"

    def fake_extract_events_to_store(etl_path, export_dir, **kwargs):
        store = _make_store(Path(export_dir))
        stats_sink = kwargs.get("stats_sink")
        if stats_sink is not None:
            stats_sink.append(
                native.ExtractStats(
                    event_count=8,
                    elapsed_seconds=0.01,
                    bytes_processed=1234,
                    provider_counts={"provider": 8},
                    decoded_counts={"SampledProfile": 3, "PerfInfo/DPC": 1},
                    events_lost=0,
                    stacks_paired=0,
                    stacks_orphan=0,
                    logfile_metadata=[],
                )
            )
        return store

    monkeypatch.setattr(native, "extract_events_to_store", fake_extract_events_to_store)

    request = NativeWorkerRequest(
        etl_path=etl,
        export_dir=export_dir,
        staging_dir=export_dir,
        trace_id="trace_worker",
        mode="native",
        strategy=native_cache.STREAMING_EVENT_STORE_STRATEGY,
        schema_version=native_cache.SCHEMA_VERSION,
        symbol_path_env_key=None,
        requested_event_classes=[],
    )

    payload = build_streaming_event_store_cache(request)

    assert payload["ok"] is True
    for filename in (
        "trace_metadata.parquet",
        "cpu_sampling.parquet",
        "cpu_timeline.parquet",
        "dpc_isr.parquet",
        "dpc_isr_per_cpu.parquet",
        "process_info.txt",
        "sysconfig.txt",
        "tracestats.txt",
    ):
        assert (export_dir / filename).exists(), filename

    manifest = native_cache.read_manifest(export_dir)
    assert manifest is not None
    names = {dataset.name for dataset in manifest.datasets}
    assert {
        "native_event_store",
        "cpu_sampling",
        "cpu_timeline",
        "dpc_isr",
        "dpc_isr_per_cpu",
        "process_info",
        "sysconfig",
        "tracestats",
    }.issubset(names)


def test_streaming_cache_reload_and_tool_smoke(monkeypatch, tmp_path: Path):
    etl = _make_etl(tmp_path)
    export_dir = etl.parent / f".etw-export-{etl.stem}"
    store = _make_store(export_dir)
    trace = TraceData(
        trace_id="trace_cache",
        etl_path=etl,
        export_dir=export_dir,
        mode="native",
        raw_csv={
            "trace_metadata": pd.DataFrame([{
                "NumberOfProcessors": 2,
                "DurationSeconds": 2.0,
                "PerfFreq": 1_000_000,
            }]),
        },
        duration_seconds=2.0,
        cpu_count=2,
        timestamp_frequency=1_000_000,
        event_store=store,
    )
    trace.symbolizer = _FakeSymbolizer()
    aggregates = build_streaming_aggregates(trace, store, batch_size=2)

    datasets = []
    for name, df in {
        "trace_metadata": trace.raw_csv["trace_metadata"],
        **aggregates.dataframes,
    }.items():
        df.to_parquet(export_dir / f"{name}.parquet", index=False)
        datasets.append(native_cache.CacheDataset(
            name=name,
            kind="parquet",
            path=f"{name}.parquet",
            row_count=len(df),
            materialize_on_load=True,
        ))
    for name, text in aggregates.texts.items():
        filename = {
            "process_info": "process_info.txt",
            "sysconfig": "sysconfig.txt",
            "tracestats": "tracestats.txt",
        }[name]
        (export_dir / filename).write_text(text, encoding="utf-8")
        datasets.append(native_cache.CacheDataset(
            name=name,
            kind="text",
            path=filename,
            row_count=1,
            materialize_on_load=True,
        ))
    datasets.append(store.cache_dataset())
    native_cache.write_manifest(
        export_dir,
        native_cache.CacheManifest.event_store_streaming(etl, datasets),
    )

    cached = trace_mgmt._load_from_cache(export_dir, etl, mode="native")
    assert cached is not None
    assert "cpu_sampling" in cached
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
    loaded = get_trace(_trace_id(result))
    assert loaded is not None
    assert loaded.event_store is not None
    assert "cpu_sampling" in loaded.raw_csv

    assert "mod.sys" in get_cpu_samples(loaded.trace_id, group_by="module")
    assert "Per-CPU Summary" in get_per_cpu_summary(loaded.trace_id)
    assert "DPC/ISR Duration Summary" in get_dpc_summary(loaded.trace_id)
    assert "server.exe" in get_process_info(loaded.trace_id)
