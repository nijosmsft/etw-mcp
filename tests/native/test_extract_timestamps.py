"""Tests for native extractor timestamp normalization."""

from __future__ import annotations

import pandas as pd

from etw_analyzer.native.consumer import TraceLogfileMetadata
from etw_analyzer.native.extract import _normalize_native_timestamps


def _metadata(perf_freq: int = 10_000_000) -> list[TraceLogfileMetadata]:
    return [
        TraceLogfileMetadata(
            number_of_processors=2,
            start_time_utc_100ns=10_000_000,
            end_time_utc_100ns=20_000_000,
            perf_freq=perf_freq,
            timer_resolution_100ns=156_250,
            cpu_speed_mhz=2500,
            events_lost=0,
            buffers_lost=0,
            buffers_written=1,
            pointer_size=8,
        )
    ]


def test_normalizes_qpc_timestamps_to_relative_microseconds():
    results = {
        "EventTrace/Header": pd.DataFrame([
            {"TimeStamp": 1_000_000, "EndTime": 999_999_999},
        ]),
        "SampledProfile": pd.DataFrame([
            {"TimeStamp": 1_005_000, "PID": 1234, "Weight": 1},
        ]),
        "PerfInfo/DPC": pd.DataFrame([
            {"TimeStamp": 1_005_500, "InitialTime": 1_004_000, "CPU": 0},
        ]),
        "StackWalk": pd.DataFrame([
            {"EventTimeStamp": 1_005_000, "StackTimeStamp": 1_005_010},
        ]),
    }

    _normalize_native_timestamps(results, _metadata())

    assert results["EventTrace/Header"].iloc[0]["TimeStamp"] == 0
    assert results["EventTrace/Header"].iloc[0]["EndTime"] == 999_999_999
    assert results["SampledProfile"].iloc[0]["TimeStamp"] == 500
    assert results["PerfInfo/DPC"].iloc[0]["TimeStamp"] == 550
    assert results["PerfInfo/DPC"].iloc[0]["InitialTime"] == 400
    assert results["StackWalk"].iloc[0]["EventTimeStamp"] == 500
    assert results["StackWalk"].iloc[0]["StackTimeStamp"] == 501


def test_normalization_uses_first_event_timestamp_when_header_missing():
    results = {
        "SampledProfile": pd.DataFrame([
            {"TimeStamp": 2_000_000, "PID": 1},
            {"TimeStamp": 2_010_000, "PID": 1},
        ]),
    }

    _normalize_native_timestamps(results, _metadata())

    assert results["SampledProfile"]["TimeStamp"].tolist() == [0, 1000]


def test_normalization_is_noop_without_perf_frequency():
    results = {
        "EventTrace/Header": pd.DataFrame([{"TimeStamp": 1_000_000}]),
        "SampledProfile": pd.DataFrame([{"TimeStamp": 1_005_000}]),
    }

    _normalize_native_timestamps(results, _metadata(perf_freq=0))

    assert results["SampledProfile"].iloc[0]["TimeStamp"] == 1_005_000
