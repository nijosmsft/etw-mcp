from __future__ import annotations

from pathlib import Path

import pandas as pd

from etw_analyzer.native.consumer import TraceLogfileMetadata
from etw_analyzer.native.extract import ExtractStats
from etw_analyzer.tools.trace_mgmt import _populate_metadata
from etw_analyzer.trace_state import TraceData


def _trace(raw_csv: dict[str, pd.DataFrame]) -> TraceData:
    return TraceData(
        trace_id="trace_test",
        etl_path=Path(r"C:\traces\test.etl"),
        export_dir=Path(r"C:\traces\.etw-export-test"),
        mode="native",
        raw_csv=raw_csv,
    )


def _stats(metadata: TraceLogfileMetadata) -> ExtractStats:
    return ExtractStats(
        event_count=1,
        elapsed_seconds=0.1,
        bytes_processed=1,
        provider_counts={},
        decoded_counts={},
        events_lost=metadata.events_lost,
        stacks_paired=0,
        stacks_orphan=0,
        logfile_metadata=[metadata],
    )


def test_native_metadata_uses_logfile_header_not_observed_events():
    observed = pd.DataFrame({"CPU": [0, 5], "TimeStamp": [100, 200]})
    trace = _trace({"SampledProfile": observed})
    trace._native_extract_stats = _stats(
        TraceLogfileMetadata(
            number_of_processors=80,
            start_time_utc_100ns=1_000_000_000,
            end_time_utc_100ns=1_164_502_142,
            perf_freq=10_000_000,
            timer_resolution_100ns=156_250,
            cpu_speed_mhz=2295,
            events_lost=0,
            buffers_lost=0,
            buffers_written=1,
            pointer_size=8,
        )
    )

    _populate_metadata(trace)

    assert trace.cpu_count == 80
    assert trace.duration_seconds == 16.4502142
    assert trace.timestamp_frequency == 10_000_000.0
    assert "trace_metadata" in trace.raw_csv


def test_cached_native_metadata_is_authoritative():
    observed = pd.DataFrame({"CPU": [0, 5], "TimeStamp": [100, 200]})
    trace = _trace({
        "trace_metadata": pd.DataFrame({
            "NumberOfProcessors": [80],
            "DurationSeconds": [16.4502142],
            "PerfFreq": [10_000_000],
        }),
        "SampledProfile": observed,
    })

    _populate_metadata(trace)

    assert trace.cpu_count == 80
    assert trace.duration_seconds == 16.4502142
    assert trace.timestamp_frequency == 10_000_000.0


def test_native_without_header_does_not_infer_from_sparse_events():
    observed = pd.DataFrame({"CPU": [0, 5], "TimeStamp": [100, 200]})
    trace = _trace({"SampledProfile": observed})

    _populate_metadata(trace)

    assert trace.cpu_count is None
    assert trace.duration_seconds is None
