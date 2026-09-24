from types import SimpleNamespace

import pandas as pd

from etw_analyzer.native.aggregators.streaming import _apply_store_metadata
from etw_analyzer.native.processor_count import select_processor_count
from etw_analyzer.tools.trace_mgmt import _populate_metadata
from etw_analyzer.trace_state import TraceData


def _trace(tmp_path, *, mode="dotnet") -> TraceData:
    etl = tmp_path / "processor-count.etl"
    etl.write_bytes(b"synthetic")
    return TraceData(
        trace_id="trace_processor_count",
        etl_path=etl,
        export_dir=tmp_path,
        mode=mode,
    )


def test_authoritative_header_wins_over_observed_lower_bound():
    assert select_processor_count(
        authoritative_counts=[80],
        fallback_counts=[60],
        observed_cpu_ids=[79],
    ) == 80


def test_observed_cpu_is_fallback_lower_bound():
    assert select_processor_count(
        authoritative_counts=[0, None, "bad"],
        fallback_counts=[60],
        observed_cpu_ids=[0, 79],
    ) == 80


def test_missing_processor_evidence_stays_unknown():
    assert select_processor_count(
        authoritative_counts=[0, -1, None],
        fallback_counts=[0, None],
        observed_cpu_ids=[],
    ) is None


def test_non_streaming_metadata_and_trace_are_reconciled(tmp_path):
    trace = _trace(tmp_path)
    trace.cpu_count = 60
    trace.raw_csv["trace_metadata"] = pd.DataFrame([{
        "NumberOfProcessors": 60,
    }])
    trace.raw_csv["EventTrace/Header"] = pd.DataFrame([{
        "NumberOfProcessors": 80,
    }])
    trace.raw_csv["SampledProfile"] = pd.DataFrame({
        "CPU": [0, 79],
    })

    _populate_metadata(trace)

    assert trace.cpu_count == 80
    assert int(trace.raw_csv["trace_metadata"].iloc[0]["NumberOfProcessors"]) == 80


def test_streaming_observed_cpu_repairs_inferred_metadata(tmp_path):
    trace = _trace(tmp_path, mode="native")
    trace.cpu_count = 60
    trace.raw_csv["trace_metadata"] = pd.DataFrame([{
        "NumberOfProcessors": 60,
        "DurationSeconds": 1.0,
    }])
    store = SimpleNamespace(
        timebase=SimpleNamespace(perf_freq=0),
        manifest=SimpleNamespace(datasets={}),
    )

    _apply_store_metadata(trace, store, observed_max_cpu=79)

    assert trace.cpu_count == 80
    assert int(trace.raw_csv["trace_metadata"].iloc[0]["NumberOfProcessors"]) == 80
