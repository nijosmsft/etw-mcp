"""Tests for the cpu_timeline aggregator."""

from __future__ import annotations

import types

import pandas as pd

from etw_analyzer.native.aggregators.profile_util import aggregate_cpu_timeline


def _make_trace(
    dumper_df,
    duration_seconds=4.0,
    cpu_count=None,
    timestamp_frequency=1_000_000,
    raw_csv=None,
    mode="xperf",
):
    return types.SimpleNamespace(
        dumper_df=dumper_df,
        raw_csv=raw_csv or {},
        symbolizer=None,
        duration_seconds=duration_seconds,
        cpu_count=cpu_count,
        timestamp_frequency=timestamp_frequency,
        mode=mode,
    )


class TestAggregateCpuTimeline:
    def test_empty(self):
        assert aggregate_cpu_timeline(_make_trace(pd.DataFrame())) is None

    def test_none(self):
        assert aggregate_cpu_timeline(_make_trace(None)) is None

    def test_missing_columns(self):
        df = pd.DataFrame([{"foo": 1}])
        assert aggregate_cpu_timeline(_make_trace(df)) is None

    def test_basic_bucketing(self):
        # 4 samples evenly spread across 4 seconds. With 1s buckets we
        # should get 4 rows; each CPU should have one sample in its
        # bucket. Sample rate = 1000 Hz / 1s = 1000 max → 0.1%.
        rows = []
        for sec, cpu in [(0.5, 0), (1.5, 1), (2.5, 0), (3.5, 1)]:
            rows.append({
                "TimeStamp": int(sec * 1_000_000),  # microseconds
                "CPU": cpu,
                "Weight": 1,
            })
        df = pd.DataFrame(rows)
        trace = _make_trace(df, duration_seconds=4.0)
        result = aggregate_cpu_timeline(trace, bucket_seconds=1.0)
        assert result is not None
        # Columns: StartTime, EndTime, Cpu 0, Cpu 1
        assert "StartTime" in result.columns
        assert "EndTime" in result.columns
        assert "Cpu 0" in result.columns
        assert "Cpu 1" in result.columns
        # 4 buckets
        assert len(result) == 4
        # Each bucket should have exactly one sample in one CPU
        for _, row in result.iterrows():
            non_zero = sum(1 for c in ["Cpu 0", "Cpu 1"] if row[c] > 0)
            assert non_zero == 1

    def test_percentages_clipped_to_100(self):
        # 10_000 samples in a single 1-second bucket on CPU 0 should
        # cap at 100% even though raw / max = 10x.
        rows = [
            {"TimeStamp": int(0.5 * 1_000_000), "CPU": 0, "Weight": 1}
            for _ in range(10_000)
        ]
        df = pd.DataFrame(rows)
        trace = _make_trace(df, duration_seconds=1.0)
        result = aggregate_cpu_timeline(trace, bucket_seconds=1.0)
        assert result is not None
        assert result["Cpu 0"].max() <= 100.0

    def test_uses_full_trace_duration_and_inactive_cpus(self):
        rows = [
            {"TimeStamp": 1_100 + i, "CPU": 0, "Weight": 999_999}
            for i in range(5)
        ]
        df = pd.DataFrame(rows)
        header = pd.DataFrame({"TimeStamp": [1_000], "NumberOfProcessors": [4]})
        trace = _make_trace(
            df,
            duration_seconds=3.0,
            cpu_count=4,
            timestamp_frequency=1_000,
            raw_csv={"EventTrace/Header": header},
        )
        result = aggregate_cpu_timeline(
            trace,
            bucket_seconds=1.0,
            sample_rate_hz=10,
        )
        assert result is not None
        assert len(result) == 3
        assert list(result.columns) == [
            "StartTime", "EndTime", "Cpu 0", "Cpu 1", "Cpu 2", "Cpu 3",
        ]
        assert result.iloc[0]["Cpu 0"] == 50.0
        assert result.iloc[1]["Cpu 0"] == 0.0
        assert result.iloc[2]["Cpu 0"] == 0.0
        assert result[["Cpu 1", "Cpu 2", "Cpu 3"]].sum().sum() == 0.0

    def test_native_relative_microseconds_are_not_qpc_scaled_again(self):
        df = pd.DataFrame([
            {"TimeStamp": 500_000, "CPU": 0, "Weight": 1},
            {"TimeStamp": 1_500_000, "CPU": 1, "Weight": 1},
        ])
        trace = _make_trace(
            df,
            duration_seconds=2.0,
            cpu_count=2,
            timestamp_frequency=10_000_000,
            mode="native",
        )

        result = aggregate_cpu_timeline(
            trace,
            bucket_seconds=1.0,
            sample_rate_hz=10,
        )

        assert result is not None
        assert len(result) == 2
        assert result.iloc[0]["Cpu 0"] == 10.0
        assert result.iloc[0]["Cpu 1"] == 0.0
        assert result.iloc[1]["Cpu 0"] == 0.0
        assert result.iloc[1]["Cpu 1"] == 10.0
